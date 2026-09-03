// Package endpoint is the one place the sealed inference surfaces differ from
// each other.
//
// Chat and image generation diverge on several axes — which router service type
// ranks their providers, which wire profile fixes what must be sealed, which
// path this gateway serves, which path the sealed envelope is POSTed to on the
// router, and whether the surface streams at all. Each was re-derived
// independently: a switch in core mapped service type to profile, two more in
// route mapped it to the withheld field set and the upstream path, openaiproxy
// carried a hand-copied handler per surface, and proxycli and the gateway keyed
// off a bool and a nil check. Five spellings of one split, in four packages, and
// adding a surface meant finding all of them.
//
// This package carries the rows that core and openaiproxy read today. route's
// two switches and the hand-written enumerations in proxycli and the gateway are
// still outstanding — see All.
//
// The cost of that was not hypothetical. route.upstreamURL records one instance
// (every sealed image request POSTed to /v1/chat/completions, because the
// upstream path lived on the Router while the profile lived on the Client), and
// the stream_options graft fixed just before this package another (whether a
// surface streams was expressed as "the image handler happens to lack that
// branch").
//
// So: one row per surface, and every layer reads the row.
//
// It deliberately imports nothing but protocol/wire — no HTTP, no router, no
// client core — so every layer can depend on it without a cycle. Path is a
// plain string here for that reason.
package endpoint

import (
	"encoding/json"
	"fmt"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Endpoint is one sealed inference surface.
type Endpoint struct {
	// ServiceType is the ROUTER's vocabulary: the value sent to the route-preview
	// API, accepted by GET /v1/providers?service_type=, and warmed by the
	// background sweeper. It is not the model modality on /v1/models.
	ServiceType string
	// Profile is the PROTOCOL's vocabulary: wire's profile table fixes which
	// request field carries the payload, which the response must seal, and which
	// cleartext fields are pinned or required (SPEC §5.1).
	Profile wire.Profile
	// Path is where this gateway serves the surface. UpstreamPath is where the
	// sealed envelope is POSTed on the router.
	//
	// They agree for every surface today, and keeping them separate is the point:
	// nothing makes them agree, and assuming they did is what sent every sealed
	// image request to /v1/chat/completions, where the router handed it to the
	// chatbot handler and the pinned image provider was not in the pool. That bug
	// was possible because the upstream path was fixed on the Router at
	// construction while the profile was fixed on the Client — two halves of one
	// row, held by two objects.
	Path, UpstreamPath string
	// Streams is whether this surface has a streaming (SSE) shape at all. Image
	// generation returns one JSON object, so `"stream": true` on it is a caller
	// error rather than a mode to select.
	//
	// It is NOT the same question as "does this profile use stream_options".
	// stream_options is an OpenAI CHAT convention, so the chat profile wants it
	// and the Anthropic profile — which streams, and reports usage on its own
	// frames — does not. core.withStreamUsage therefore keys off the profile, not
	// off this field. Collapsing the two would put an undefined field into every
	// /v1/messages request the day that surface lands.
	Streams bool
	// PreSeal normalises the request body before it is sealed, for a rule that
	// belongs to this surface rather than to the protocol. nil means there is
	// nothing to do. It must not mutate the request it is given: the same body is
	// re-sealed to each fallback candidate.
	PreSeal func(wire.Request) (wire.Request, error)
}

// Chat is POST /v1/chat/completions: the OpenAI chat-completions surface.
var Chat = Endpoint{
	ServiceType:  "chatbot",
	Profile:      wire.ProfileChat,
	Path:         "/v1/chat/completions",
	UpstreamPath: "/v1/chat/completions",
	Streams:      true,
}

// Image is POST /v1/images/generations: the OpenAI image-generation surface.
var Image = Endpoint{
	ServiceType:  "text-to-image",
	Profile:      wire.ProfileImage,
	Path:         "/v1/images/generations",
	UpstreamPath: "/v1/images/generations",
	Streams:      false,
	PreSeal:      imagePreSeal,
}

// All is every surface this module knows how to seal.
//
// It is NOT yet the thing that mounts them. The gateway and proxycli still name
// Chat and Image one at a time, so adding a row here does not by itself serve a
// surface — replacing those hand-written enumerations is the last step. What a
// row DOES already decide is everything about how the surface behaves once
// mounted: its profile, its sealed set, its service type, its upstream path,
// whether it streams, and its pre-seal normalisation.
//
// The Anthropic profile is deliberately ABSENT even though protocol/wire carries
// a complete ProfileAnthropic. The router's route-preview API rejects that
// service type today, so a row here would mount a surface that resolves to
// nothing on every request. When preview accepts it this is one struct literal —
// its service type is "anthropic-chat" and its router path /v1/messages, which
// is NOT /v1/chat/completions: a separate router endpoint with its own handler
// and request shape. (route used to carry those two facts in switch cases that
// nothing could reach; they are recorded here instead, next to the row they
// belong to.)
//
// Its absence does NOT make it unknown to the seal path. What a surface must
// withhold when this table does not carry it is derived from wire.Profiles(),
// the PROTOCOL's list — see route.sensitiveFieldsForServiceType. Deriving that
// from All instead would drop ProfileAnthropic's top-level `system` and upload
// it in the clear.
var All = []Endpoint{Chat, Image}

// ByServiceType looks a surface up by the router's service-type string, for a
// layer that is handed one rather than an Endpoint: route, whose Resolve
// signature carries the service type across the core boundary.
//
// A miss returns the ZERO Endpoint and false. The zero value fails closed by
// construction — its Profile is the empty profile, which wire rejects on every
// seal and open — so a caller that ignores ok cannot silently get chat's rules
// applied to a surface nobody analysed. A caller that does honour ok must still
// decide what a miss means for it; route treats it as "withhold everything any
// profile could carry", which is the safe direction.
func ByServiceType(t string) (Endpoint, bool) {
	for _, ep := range All {
		if ep.ServiceType == t {
			return ep, true
		}
	}
	return Endpoint{}, false
}

// fieldResponseFormat is the image profile's pinned cleartext field (SPEC §7.1).
const fieldResponseFormat = "response_format"

// imagePreSeal fills in the image profile's pinned cleartext
// `response_format: "b64_json"` when the caller omitted it, and rejects an
// explicit conflicting value.
//
// The pin exists because url mode has the provider persist the images and serve
// them from a plain URL — outside the sealed channel, which is a worse leak than
// the prompt since it is the generated content itself (SPEC §7.1). The field is
// REQUIRED rather than defaulted at the protocol layer precisely because
// OpenAI's own default for the DALL·E family is `url`, so an omitted field is a
// request to publish in the clear, spelled as silence.
//
// Defaulting it HERE rather than in wire is the difference between a gateway
// being convenient and a protocol being safe: this gateway knows its callers
// reached a sealed endpoint on purpose, so filling the field in is honouring an
// intent they already expressed. The protocol layer knows nothing about the
// caller and must keep failing closed for every other client. An explicit `url`
// is refused rather than silently rewritten: the caller asked for a format this
// mode cannot honour and has to learn that, which is the same reasoning the
// broker applies to the same value.
//
// The request map is shallow-copied so the caller's body is never mutated.
func imagePreSeal(req wire.Request) (wire.Request, error) {
	const want = "b64_json"
	// A JSON `null` is the absence of a value, not a value — treat it as omitted
	// and fill it in, the same reading wire.IsE2EESealed gives `_e2ee: null`.
	// Spelled out because it is otherwise an accident: decoding `null` into a
	// string is a no-op that returns NO error, so it would fall through to the
	// value comparison and be rejected as `response_format=""`, which is a
	// confusing message for a field the caller never set.
	if raw, ok := req[fieldResponseFormat]; ok && string(raw) != "null" {
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			return nil, fmt.Errorf("%s must be the JSON string %q", fieldResponseFormat, want)
		}
		if got != want {
			return nil, fmt.Errorf(
				"%s=%q is not supported for a sealed image request (the images would be served outside the sealed channel); use %q",
				fieldResponseFormat, got, want)
		}
		return req, nil
	}
	out := make(wire.Request, len(req)+1)
	for k, v := range req {
		out[k] = v
	}
	out[fieldResponseFormat] = json.RawMessage(`"` + want + `"`)
	return out, nil
}
