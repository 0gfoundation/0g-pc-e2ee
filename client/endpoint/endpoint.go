// Package endpoint is the one place the sealed inference surfaces differ from
// each other.
//
// The surfaces diverge on several axes — which router service type ranks their
// providers, which API surface within that service type, which wire profile
// fixes what must be sealed, which path this gateway serves, which path the
// sealed envelope is POSTed to on the router, and whether the surface streams at
// all. Each was re-derived independently: a switch in core mapped service type to
// profile, two more in route mapped it to the withheld field set and the upstream
// path, openaiproxy carried a hand-copied handler per surface, and proxycli and
// the gateway keyed off a bool and a nil check. Five spellings of one split, in
// four packages, and adding a surface meant finding all of them.
//
// Every layer reads the rows: core seals under a row's profile, openaiproxy
// serves a row, route resolves a row's upstream and withheld set, proxycli builds
// a client per served row, the gateway mounts every row, and metrics labels by
// row.
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
	//
	// It does NOT identify a row. Two surfaces share "chatbot" — the OpenAI
	// chat-completions one and the Anthropic messages one — because they are one
	// pool of providers answering two request shapes. Path is the unique key.
	ServiceType string
	// APIFormat is the API SURFACE within a service type, for the one service type
	// that has more than one: `chatbot` answers both /v1/chat/completions
	// (`openai`) and /v1/messages (`anthropic`). Sent as the preview request's
	// `api_format` when non-empty; empty means "this service type has one surface,
	// do not narrow".
	//
	// It is a separate field rather than a fancier ServiceType because the router
	// draws the line in exactly the same place: its previewServiceType REFUSES
	// "anthropic-chat" as a service_type ("it is a (service type, surface) PAIR
	// wearing one string, and the surface is a separate axis with its own field"),
	// and previewAPIFormat is where /v1/messages is asked for. A row spelling the
	// pair as one string would 400 on every request.
	//
	// Empty and "openai" are the same request to the router — it applies no format
	// filter for either, because OpenAI is the default surface every chat provider
	// answers and many do not enumerate it in `api_formats` at all. So the chat row
	// leaves this empty rather than saying "openai": the two are equivalent
	// upstream, and empty is the honest spelling of "not an axis I am selecting on".
	APIFormat string
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
	// off this field. Both of those rows have Streams true, so collapsing the two
	// would put an undefined field into every streaming /v1/messages request.
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

// Anthropic is POST /v1/messages: the Anthropic Messages surface.
//
// Its ServiceType is "chatbot", the same pool as Chat, with the surface carried
// on APIFormat — see that field for why the pair is not one string. Its own path
// is /v1/messages on both sides: a separate router endpoint with its own handler
// and request shape, NOT /v1/chat/completions.
//
// The profile is what earns the row. ProfileAnthropic seals a top-level `system`
// that the chat profile has no opinion about, so serving this surface under
// ProfileChat would leave the system prompt in the clear — through the router,
// and then refused by the broker, which validates the sealed set against the
// surface it was reached on.
var Anthropic = Endpoint{
	ServiceType:  "chatbot",
	APIFormat:    "anthropic",
	Profile:      wire.ProfileAnthropic,
	Path:         "/v1/messages",
	UpstreamPath: "/v1/messages",
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

// All is every surface this module knows how to seal, and adding a row here is
// what makes a surface exist. The gateway mounts every row — as the sealed
// handler when its build serves it, as an explicit refusal when not, never left
// to the cleartext catch-all — proxycli builds a client and validates the
// operator's field flags per served row, the warmer enumerates each row's fleet,
// and metrics gives each row its own label. Nothing else enumerates them.
//
// The rows are keyed by Path, which is the only field unique to each. Chat and
// Anthropic deliberately SHARE ServiceType "chatbot": one provider pool, two
// request shapes, told apart by APIFormat. A lookup by service type therefore
// cannot name a surface, which is why this package no longer offers one — the
// row travels with the request instead (core.WithEndpoint holds it, and
// core.Resolver.Resolve carries it across the boundary to route).
//
// That is the same fix, one level up, as the two this package's header records:
// a surface identified by a lossy projection of itself is a surface that can be
// silently confused with another. A ByServiceType("chatbot") would have returned
// whichever chat row came first in this slice and shadowed the other with no
// error anywhere.
var All = []Endpoint{Chat, Anthropic, Image}

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
