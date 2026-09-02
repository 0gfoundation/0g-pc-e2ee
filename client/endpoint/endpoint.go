// Package endpoint is the one place the sealed inference surfaces differ from
// each other.
//
// Chat and image generation diverge on five axes — which router service type
// ranks their providers, which wire profile fixes what must be sealed, which
// path this gateway serves, which path the sealed envelope is POSTed to on the
// router, and whether the surface streams at all. Before this package each axis
// was re-derived independently: a switch in core mapped service type to profile,
// two more in route mapped it to the withheld field set and the upstream path,
// openaiproxy carried a hand-copied handler per surface, and proxycli and the
// gateway keyed off a bool and a nil check. Five spellings of one split, in four
// packages, and adding a sixth surface meant finding all of them.
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
	// sealed envelope is POSTed on the router. They agree for every surface today
	// — the point of keeping them separate is that nothing makes them agree, and
	// assuming they did is what sent sealed image requests to the chat handler.
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

// All is every surface this module knows how to seal. Adding a row here is what
// makes a surface exist: the gateway mounts what is in this list (and an
// explicit refusal for what a given build does not serve), proxycli builds a
// client per row and validates the operator's field flags against each row's
// profile, and the warmer enumerates each row's service type.
//
// The Anthropic profile is deliberately ABSENT even though protocol/wire
// carries a complete ProfileAnthropic and route already knows the
// "anthropic-chat" service type and its /v1/messages upstream path. The
// router's route-preview API rejects that service type today, so a row here
// would mount a surface that resolves to nothing on every request. Its wire
// spec keeps until preview accepts it, at which point this is one struct
// literal.
var All = []Endpoint{Chat, Image}

// ByServiceType looks a surface up by the router's service-type string, for a
// layer that is handed one rather than an Endpoint (route, whose Resolve
// signature carries the service type across the core boundary).
//
// A miss returns the ZERO Endpoint and false. The zero value fails closed by
// construction: its Profile is the empty profile, which wire rejects on every
// seal and open, so a caller that ignores ok cannot silently get chat's rules
// applied to a surface nobody analysed.
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
