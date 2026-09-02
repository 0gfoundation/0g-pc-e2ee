// Package wire implements the v1 envelopes (SPEC §5–§7): field-level sealing of
// OpenAI-shaped requests and responses. The sensitive fields are removed from
// the JSON and sealed into an `_e2ee` object; every other top-level field stays
// cleartext (so the router can route/bill on it) but is bound as AEAD
// associated data, so an intermediary can read but not tamper.
//
//   - Request (§5–§6): client seals the payload fields to the provider enc key —
//     messages/tools for chat, prompt for image, messages/system for Anthropic
//     (see Profile).
//   - Response (§7): the enclave seals the generated content to the client's
//     ephemeral key — choices for chat, data for image, a field per event shape
//     for Anthropic (§7.2) — one frame for non-streaming or a sequence of frames
//     for streaming.
//
// Contract: broker <-> client (byte-for-byte, per SPEC.md). All AAD is taken
// over JCS (RFC 8785) canonical JSON so Go/TS/Rust agree byte-for-byte.
package wire

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/gowebpki/jcs"
)

const (
	// Version is the `_e2ee` envelope version (SPEC §5).
	Version = 1
	// KEMID identifies the HPKE KEM on the wire (SPEC §3).
	KEMID = "0x0020"
	// SealInfo is the HPKE info string for request sealing (SPEC §5.2/§6).
	SealInfo = "0g-pc/v1/seal"
	// e2eeKey is the reserved top-level key that holds the sealing metadata.
	e2eeKey = "_e2ee"
	// fieldMessages is the sensitive field a chat request MUST always seal.
	fieldMessages = "messages"
	// fieldPrompt is the sensitive field an image request MUST always seal.
	fieldPrompt = "prompt"
	// fieldSystem is Anthropic's TOP-LEVEL system prompt (/v1/messages), as
	// opposed to OpenAI's system message inside "messages". Being its own
	// top-level field is why it needs naming at all: it is payload the chat
	// profile's rules do not reach. Conditionally required — see
	// profileSpec.requiredIfPresent.
	fieldSystem = "system"
	// fieldResponseFormat is the cleartext image field pinned to "b64_json"
	// (SPEC §7.1) — see profileSpec.pinnedCleartext.
	fieldResponseFormat = "response_format"
	// fieldChoices / fieldData are the generated content a sealed RESPONSE frame
	// MUST cover, per profile (SPEC §7).
	fieldChoices = "choices"
	fieldData    = "data"
	// The Anthropic response carries its generated content in a different field
	// per event shape (SPEC §7.2) — see anthropicFrames.
	fieldContent      = "content"       // the whole content array (non-streaming, and message.content)
	fieldContentBlock = "content_block" // a block's opening value
	fieldDelta        = "delta"         // an incremental block/message update
	fieldErr          = "error"         // an upstream error object, which may quote the input
	// fieldType is the cleartext field an Anthropic frame names its own shape in,
	// and fieldMessage the envelope message_start wraps the message skeleton in.
	fieldType    = "type"
	fieldMessage = "message"
	// fieldStopSequence is the custom stop string the CLIENT supplied in the
	// request's `stop_sequences`, echoed back when it is what ended the turn. It
	// is client input, not model output, so it is sealed wherever it appears — see
	// frameShape.sealIfPresent.
	fieldStopSequence = "stop_sequence"
	// fieldUsage / fieldOutputImages locate the billable image count a sealed
	// image response MUST carry in cleartext (SPEC §7.1) — see
	// profileSpec.requiredResponseCleartext.
	fieldUsage        = "usage"
	fieldOutputImages = "output_images"
	// clientEphPubLen is the byte length of an X25519 public key — the client's
	// response ephemeral key (SPEC §3 suite).
	clientEphPubLen = 32
)

// b64 is base64url without padding — the wire encoding for binary fields (§3).
var b64 = base64.RawURLEncoding

// Profile names a request family (SPEC §5.1). The envelope format, crypto suite
// and AAD rule are identical across profiles — a profile only fixes WHERE the
// sensitive payload lives, so the "you cannot accidentally ship the payload in
// cleartext" check knows what to require. For most profiles that is one request
// field and one response field; for a frame-typed one it is a field per response
// event shape (§7.2).
//
// It is deliberately NOT carried on the wire: `sealed_fields` is already
// self-describing, and the enclave's Open check (decrypted keys == declared
// sealed_fields) is profile-independent. The profile is the client-side half of
// the guard — the only half that can stop a leak before it is sent. An enclave
// serving a known endpoint enforces the same requirement independently, since a
// third-party client is under no obligation to use this package.
type Profile string

const (
	// ProfileChat is /v1/chat/completions and friends: the payload is "messages".
	ProfileChat Profile = "chat"
	// ProfileImage is /v1/images/generations: the payload is "prompt".
	ProfileImage Profile = "image"
	// ProfileAnthropic is /v1/messages: the payload is "messages" plus the
	// top-level "system" prompt whenever the request carries one, and the response
	// is a sequence of DIFFERENTLY SHAPED frames rather than one shape repeated
	// (SPEC §7.2).
	ProfileAnthropic Profile = "anthropic"
)

// profileSpec fixes, per profile, the field that MUST be sealed, any CLEARTEXT
// field pinned to a specific value, and the v1 default sealed sets for a request
// and for the response it produces.
type profileSpec struct {
	// required / responseRequired are the fields that MUST be sealed; request /
	// response are the v1 DEFAULTS, which may be supersets. Keeping the two
	// distinct on both sides matters: the request side has always had it right
	// ("tools" is a default but not mandatory), and reusing one field for both on
	// the response side would silently mean "every default is mandatory" — fine
	// while each response default has exactly one member, wrong the moment a
	// profile defaults to sealing two fields of which only one is the content.
	required         string   // the request field a sealed envelope MUST cover (§5.1)
	request          []string // v1 default request sealed set (§5.1)
	responseRequired string   // the response field a sealed frame MUST cover (§7)
	response         []string // v1 default response sealed set (§7)
	// requiredIfPresent are request fields that need not EXIST, but MUST be
	// sealed whenever the request carries one. `required` cannot express that: it
	// is checked from (profile, field names) alone, so a field that is only
	// sometimes there would either reject every request that omits it or, listed
	// as a mere default, be silently droppable.
	//
	// Anthropic's `system` is the case the distinction exists for. It is prompt
	// content — the same class as `messages` — but it is optional, and it sits at
	// the TOP LEVEL rather than inside `messages`, so nothing about sealing
	// `messages` covers it. Left out, a request seals the conversation and hands
	// the system prompt to the router in the clear, passing every other check.
	requiredIfPresent []string
	// responseFrames is set for a profile whose response frames do not all have
	// the same shape, so "the field a frame must seal" is a property of the FRAME
	// rather than of the profile. nil means single-shape (chat, image), where
	// responseRequired/response answer for every frame.
	responseFrames *responseFrameRule
	// pinnedCleartext maps a cleartext field to the ONLY value a sealed request
	// of this profile may carry. The field must be present — an absent one is
	// rejected, never defaulted — because a server-side default is exactly what
	// this guards against (§7.1). Empty for profiles with no such constraint.
	pinnedCleartext map[string]string
	// requiredResponseCleartext are numeric values a sealed FINAL response frame
	// of this profile MUST carry in cleartext, because the router bills on them
	// and cannot recover them from the sealed content (§7.1). Empty for profiles
	// with no such requirement.
	requiredResponseCleartext []cleartextNumber
	// mustStayBoundResponse are cleartext response fields this profile may never
	// declare unbound, ON TOP of the profile-independent floor
	// (mustStayBoundInResponse).
	//
	// It exists because that floor is name-based on TOP-LEVEL fields, and a
	// profile can carry a value that must be authenticated one level down.
	// Anthropic's billable INPUT token count is at `message.usage.input_tokens`,
	// whose top-level name is `message` — so "usage must stay bound" does not
	// reach it, and an enclave could declare `message` unbound, put the count
	// outside the AAD, and let a router restate it with the client's Open AND the
	// §8 verification both still passing. That is the §7.1/§12 attack the `usage`
	// rule exists to stop, on the input side.
	//
	// Unbinding `message` would also void the §7.2 `message.content` emptiness
	// check, since that check reads a field an intermediary could then rewrite.
	mustStayBoundResponse []string
}

// cleartextNumber locates a required cleartext number one level inside a
// top-level response field — `usage.output_images`, and so far only that. A
// two-level struct rather than general dotted-path resolution because the one
// requirement that exists is two levels deep, and a path parser would be more
// machinery than the rule it enforces.
type cleartextNumber struct {
	field string // top-level cleartext response field, e.g. "usage"
	key   string // key within that object, e.g. "output_images"
}

func (c cleartextNumber) String() string { return c.field + "." + c.key }

// responseFrameRule describes a profile whose response is a sequence of
// differently shaped frames (SPEC §7.2). Each frame names its own shape in a
// cleartext field, and the shape fixes what that frame must seal.
//
// The single-shape rule cannot be stretched to cover this. Requiring one field
// on every frame rejects the shapes that legitimately have no sensitive payload
// (Anthropic's message_start / content_block_stop / message_stop / ping), and
// relaxing it to "seal whatever you like" is the leak the requirement exists to
// stop. Only the frame itself says which of the two a given frame is.
type responseFrameRule struct {
	// discriminator is the cleartext frame field naming the shape. It MUST stay
	// cleartext and bound: every check below keys off it, so a sealed or unbound
	// discriminator is a check the sender can decline (SPEC §12).
	discriminator string
	// shapes maps a discriminator value to its shape. A value that is not here is
	// REJECTED rather than waved through: an unrecognized frame may carry content,
	// and nothing about it says it does not.
	shapes map[string]frameShape
}

// frameShape is what one frame shape must seal, and what it must not carry.
type frameShape struct {
	// content is the field this shape MUST seal, or "" for a shape with no
	// sensitive payload at all — for which the sealed set must be EXACTLY empty.
	// Not "anything goes": an empty seal still binds the frame's cleartext in the
	// AAD and still carries `_e2ee`, so the stream stays uniform and signed, while
	// permitting a superset would let a sealer swallow a field the router reads
	// (Anthropic's input token count rides inside message_start's `message`).
	content string
	// sealIfPresent are fields this shape must seal WHENEVER THE FRAME CARRIES
	// them — the response-side twin of the request's requiredIfPresent, and for
	// the same reason: a field that is sensitive but optional cannot be expressed
	// by `content` (required-always would reject every frame that omits it).
	//
	// `stop_sequence` on the non-streaming shape is the case. It is the custom
	// stop string the CLIENT supplied, echoed back — client input, not model
	// output. The streaming path already seals it (it lives inside
	// `message_delta`'s `delta`), so leaving it cleartext here would send the SAME
	// value one way in one mode and the other way in the other. That matters
	// exactly when a client seals `stop_sequences` in its request, which
	// DefaultSealedFieldsFor invites: the response would then hand back in the
	// clear a value the client deliberately sealed on the way in.
	//
	// `stop_reason` is deliberately NOT here: it is a model-produced enum
	// ("end_turn", "max_tokens", …) with no client input in it. Streaming seals it
	// only because it shares the `delta` object with `stop_sequence`.
	sealIfPresent []string
	// nestedMustBeEmpty are arrays one level inside a cleartext field that this
	// shape MUST NOT carry content in.
	//
	// It exists for message_start, whose `message` must stay cleartext (the
	// router's input token count is inside it) while `message.content` is, per
	// Anthropic's own spec, always []. Nothing else would notice if it were not:
	// an enclave that put the whole answer there would ship it in the clear, the
	// client would open the frame happily, and an SDK reading message_start's
	// message skeleton would even render it. So the emptiness Anthropic promises
	// is checked rather than assumed — on both sides, since the side that can
	// only detect it is the client (SPEC §12).
	nestedMustBeEmpty []nestedArray
}

// nestedArray locates an array one level inside a top-level frame field —
// `message.content`, and so far only that. Deliberately the same two-level
// literal as cleartextNumber rather than general path resolution, for the same
// reason: a path parser would be more machinery than the rule it enforces.
type nestedArray struct {
	field string // top-level cleartext frame field, e.g. "message"
	key   string // key within that object, e.g. "content"
}

func (n nestedArray) String() string { return n.field + "." + n.key }

// anthropicFrames is the /v1/messages event taxonomy (SPEC §7.2). The shapes
// with content are the ones that carry generated text, a tool call, or an
// upstream error message; the rest are sequencing metadata, and `usage` /
// `message` stay cleartext on them so the router can bill without a key.
//
// `type` is the discriminator because Anthropic already puts it in every event's
// payload, so nothing new goes on the wire. Note that the SSE `event:` LINE is
// not usable for this: it sits outside the JSON and therefore outside the AAD,
// so an intermediary can rewrite it undetected. A receiver MUST key off this
// bound field and rebuild the `event:` line from it.
var anthropicFrames = responseFrameRule{
	discriminator: fieldType,
	shapes: map[string]frameShape{
		// Non-streaming: one frame holding the whole content array, plus the
		// client's own stop string when that is what ended the turn.
		"message": {content: fieldContent, sealIfPresent: []string{fieldStopSequence}},
		// Streaming. message_start's `message` holds the input token counts the
		// router bills on, so it stays cleartext — with its content array checked
		// empty, since that is the one part of it that could carry the answer.
		"message_start":       {nestedMustBeEmpty: []nestedArray{{field: fieldMessage, key: fieldContent}}},
		"content_block_start": {content: fieldContentBlock},
		"content_block_delta": {content: fieldDelta},
		"content_block_stop":  {},
		// message_delta carries the output token count in a TOP-LEVEL `usage`
		// (cleartext, and bound), and stop_reason/stop_sequence in `delta`. Sealing
		// `delta` is what covers `stop_sequence` — the client's own stop string
		// echoed back — on this path; the non-streaming shape has to name it
		// explicitly because there it is a top-level field of its own.
		"message_delta": {content: fieldDelta},
		"message_stop":  {},
		"ping":          {},
		// An upstream error message can quote the request that produced it. The
		// router still sees `type: "error"`, which is all it needs to classify the
		// failure.
		"error": {content: fieldErr},
	},
}

// contentFields is every field ANY shape of this rule is required to seal —
// `content` values and `sealIfPresent` values alike — deduplicated. It is what
// makes a MISLABELED frame detectable: a frame that claims a metadata shape and
// carries `delta` in its cleartext half would otherwise satisfy "the sealed set
// is empty, as this shape requires" and leak the delta to every intermediary.
// Checking the union means a frame may carry one of these fields only if it
// seals it, whatever the frame calls itself.
func (r responseFrameRule) contentFields() []string {
	out := make([]string, 0, len(r.shapes))
	add := func(f string) {
		if f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	for _, s := range r.shapes {
		add(s.content)
		for _, f := range s.sealIfPresent {
			add(f)
		}
	}
	slices.Sort(out) // stable error messages
	return out
}

// sealedFieldsFor is what a frame of this shape MUST seal: the shape's content
// field, plus each sealIfPresent field the frame actually carries. Empty for a
// sequencing shape, whose sealed set must then be exactly empty.
//
// One function serves both ends, like the request side's conditional payload
// check. At seal time the frame still holds what it is about to seal, so a
// present `stop_sequence` is required; at open time a sealed one is already gone
// from the cleartext, so it is not required — but one that is STILL there was
// never sealed, and is required, which is exactly the rejection the receiver
// half owes (SPEC §12).
func (s frameShape) sealedFieldsFor(frame Response) []string {
	out := make([]string, 0, 1+len(s.sealIfPresent))
	if s.content != "" {
		out = append(out, s.content)
	}
	for _, f := range s.sealIfPresent {
		if _, present := frame[f]; present {
			out = append(out, f)
		}
	}
	return out
}

var profiles = map[Profile]profileSpec{
	ProfileChat: {
		required:         fieldMessages,
		request:          []string{"messages", "tools"},
		responseRequired: fieldChoices,
		response:         []string{"choices"},
	},
	ProfileImage: {
		// "prompt" is the whole sensitive payload of an image request; "data" —
		// the generated images — is the whole sensitive payload of the response.
		// The image COUNT stays cleartext as `usage.output_images` so the router
		// can bill without decrypting (§7.1), the same trade-off chat makes for
		// `usage`.
		required:         fieldPrompt,
		request:          []string{"prompt"},
		responseRequired: fieldData,
		response:         []string{"data"},
		// response_format must be an EXPLICIT "b64_json" (§7.1). "url" has the
		// enclave persist the images and serve them from a plain URL, outside
		// the sealed channel — a worse leak than the prompt, since it is the
		// generated content itself. Requiring the field rather than merely
		// banning "url" is the point: OpenAI's own default for the DALL·E
		// family IS "url", so an omitted field is a request to leak, spelled
		// as silence.
		pinnedCleartext: map[string]string{fieldResponseFormat: "b64_json"},
		// The billable count. Sealing `data` makes the images uncountable from
		// outside, so §7.1 requires the enclave to restate how many it produced
		// in cleartext; without this the router's own parse of a sealed frame
		// yields zero images and bills nothing, silently, forever.
		requiredResponseCleartext: []cleartextNumber{{field: fieldUsage, key: fieldOutputImages}},
	},
	ProfileAnthropic: {
		// "messages" is the conversation and is always there; "system" is the
		// top-level system prompt, the same class of payload but optional — hence
		// requiredIfPresent rather than a second `required`. "tools" follows chat:
		// a default, not mandatory.
		required:          fieldMessages,
		requiredIfPresent: []string{fieldSystem},
		request:           []string{"messages", "system", "tools"},
		// The response is frame-typed, so there is no single field a frame must
		// seal and no meaningful profile-wide default set: both are properties of
		// the frame (see anthropicFrames). responseRequired/response stay zero so
		// the single-shape helpers refuse this profile outright rather than
		// resolving to something plausible and wrong.
		responseFrames: &anthropicFrames,
		// No pinned cleartext field: /v1/messages has no equivalent of the image
		// profile's response_format — nothing in it directs the server to publish
		// the result outside the sealed channel.
		//
		// `message` may never be declared unbound: message_start's
		// `message.usage.input_tokens` is the billable input count, and the
		// profile-independent "usage must stay bound" floor is name-based on
		// top-level fields, so it does not reach one nested a level down.
		mustStayBoundResponse: []string{fieldMessage},
		// No requiredResponseCleartext either, for chat's reason plus one of its
		// own: the billable counts are tokens, and they arrive in TWO places
		// (message_start's message.usage.input_tokens, message_delta's
		// usage.output_tokens) on non-final frames. cleartextNumber addresses two
		// levels and this check runs on the final frame only, so neither fits.
		// TODO(anthropic-usage): an omitted count is under-billing, not a leak
		// (the router reads zero and cannot tell that from a genuine zero — the
		// §7.1 failure mode), so it wants the same treatment once the locator
		// handles three levels and per-shape required cleartext.
	},
}

// Deliberately not set for ProfileChat: chat's billable quantities are the token
// counts, and a streaming chat response omits `usage` on every frame unless the
// caller asked for it (stream_options.include_usage). Requiring it here would
// reject conforming chat streams to enforce a rule §7 does not state.

// validatePinnedCleartextFor enforces a profile's pinned cleartext constraints
// (§5.1 / §7.1) on a RECEIVED envelope. It is the enclave-side counterpart of
// the checks SealRequestFor runs before sealing, and the SPEC requires it: the
// client-side half stops the reference library from BUILDING a violating
// request, but a third-party client is under no obligation to use it.
//
// Unexported because OpenRequestFor is the enclave's entry point and calls this
// itself. An enclave should not be able to open an envelope without the check
// having run, which a second, exported way in would allow.
//
// It checks all three ways the pin can be defeated:
//
//   - the value is wrong, absent, or not a string;
//   - the field was SEALED, so it is gone from the cleartext the server reads
//     and the server falls back to its own default (which for the image profile
//     is `url` — the leak);
//   - the field was declared UNBOUND, so an intermediary could have rewritten it
//     in transit and Open would still succeed.
//
// A profile with no pinned fields (chat) always passes.
func validatePinnedCleartextFor(p Profile, env Request) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	if len(spec.pinnedCleartext) == 0 {
		return nil
	}
	e2ee, err := env.E2EE()
	if err != nil {
		return err
	}
	if err := validatePinnedNotSealed(spec, e2ee.SealedFields); err != nil {
		return err
	}
	if err := validatePinnedNotUnbound(spec, e2ee.UnboundFields); err != nil {
		return err
	}
	return validatePinnedCleartext(spec, env)
}

// validatePinnedNotSealed rejects a sealed set that swallows a pinned cleartext
// field. Sealing it removes it from the cleartext envelope entirely, so the
// server reads nothing where the pin should be and falls back to its own default
// — for the image profile, `url`. That makes this the one way to satisfy the
// VALUE check and still leak: the value is verified against the pre-seal
// request, and the field is then encrypted away.
func validatePinnedNotSealed(spec profileSpec, sealed []string) error {
	for _, f := range sealed {
		if want, pinned := spec.pinnedCleartext[f]; pinned {
			return fmt.Errorf("%q is pinned to %q and must stay CLEARTEXT: sealing it removes it from the envelope the server reads, which then falls back to its own default", f, want)
		}
	}
	return nil
}

// validatePinnedNotUnbound rejects an unbound set that frees a pinned cleartext
// field. An unbound field is excluded from the AAD, so an intermediary can
// rewrite it and Open still succeeds — which would let a router flip a pinned
// `response_format: "b64_json"` to `"url"` in transit and hand the enclave a
// request that publishes the images in the clear. A pin on an unbound field is
// a pin in name only: it constrains the value at seal time and nothing after.
func validatePinnedNotUnbound(spec profileSpec, unbound []string) error {
	for _, f := range unbound {
		if want, pinned := spec.pinnedCleartext[f]; pinned {
			return fmt.Errorf("%q is pinned to %q and cannot be unbound: an unbound field is outside the AAD, so an intermediary could rewrite it in transit and the enclave would accept the result", f, want)
		}
	}
	return nil
}

// validatePinnedCleartext enforces spec.pinnedCleartext against the request's
// cleartext fields (§5.1 profiles). It runs at seal time, before any ciphertext
// exists, so a request that would have leaked is never built — the same reason
// the sealed-set check lives here rather than only in the enclave.
func validatePinnedCleartext(spec profileSpec, req Request) error {
	for field, want := range spec.pinnedCleartext {
		raw, ok := req[field]
		if !ok {
			return fmt.Errorf("sealed request must set %q to %q explicitly (an absent value takes the server's default, which may not be %q)", field, want, want)
		}
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			return fmt.Errorf("sealed request field %q must be the JSON string %q: %w", field, want, err)
		}
		if got != want {
			return fmt.Errorf("sealed request field %q must be %q, got %q", field, want, got)
		}
	}
	return nil
}

// validatePayloadIfPresentFor enforces a profile's CONDITIONAL payload fields
// (§5.1): a field that need not exist, but MUST be sealed whenever the message
// carries it. Anthropic's `system` is the case — see profileSpec.requiredIfPresent.
//
// It cannot live in ValidateSealedFieldsFor, which answers "is this set of field
// names valid for this profile?" from (profile, fields) alone. That is what lets
// an operator validate `-seal-fields` at startup, before any request exists, and
// this rule needs the request. So it is called from both ends instead:
//
//   - SealRequestFor, on the pre-seal request, where the field is present
//     whether or not it is about to be sealed: "you have a system prompt and are
//     not sealing it";
//   - OpenRequestFor, on the received envelope, where a sealed field is already
//     gone: "a system prompt arrived in the clear".
//
// One predicate serves both — present as a top-level field AND absent from the
// sealed set — because the sealer removes what it seals. The receiving half is
// the load-bearing one (SPEC §12): a third-party client runs no seal-time check.
//
// Presence is literal, so an explicit `"system": null` counts as present and
// must be sealed like any other value. That errs toward sealing, which is the
// safe direction, and keeps the rule "if the field is in the object, it is
// payload" rather than a JSON-value special case a sender could aim at.
func validatePayloadIfPresentFor(p Profile, fields []string, msg Request) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	if len(spec.requiredIfPresent) == 0 {
		return nil
	}
	sealed := toSet(fields)
	for _, f := range spec.requiredIfPresent {
		if _, present := msg[f]; !present {
			continue
		}
		if _, isSealed := sealed[f]; isSealed {
			continue
		}
		return fmt.Errorf("%s-profile request carries %q in cleartext: it is payload and MUST be sealed whenever present", p, f)
	}
	return nil
}

func (p Profile) spec() (profileSpec, error) {
	s, ok := profiles[p]
	if !ok {
		return profileSpec{}, fmt.Errorf("unknown profile %q", p)
	}
	return s, nil
}

// DefaultSealedFields is the v1 default set of chat request fields to seal (SPEC
// §5.1) — shorthand for DefaultSealedFieldsFor(ProfileChat), kept because chat
// is by far the common case.
func DefaultSealedFields() []string {
	return DefaultSealedFieldsFor(ProfileChat)
}

// DefaultSealedFieldsFor is the v1 default set of request fields to seal for a
// profile (SPEC §5.1). It returns a fresh slice, so a caller may filter it to
// the fields actually present or append additional sensitive ones (e.g.
// "metadata", "user") without mutating the shared default. The defaults live
// here in exactly one place; clients reference them rather than re-listing the
// names.
//
// An unknown profile yields an EMPTY BUT NON-NIL slice, so a caller that passes
// the result straight into SealRequest/SealRequestFor fails closed with "no
// sealed fields". Returning nil would instead mean "use the default set" at
// those call sites and silently seal the chat fields for a profile that does not
// exist. (Same reasoning as the client core's own presence filter.)
func DefaultSealedFieldsFor(p Profile) []string {
	s, err := p.spec()
	if err != nil {
		return []string{}
	}
	return slices.Clone(s.request)
}

// DefaultUnboundFields is the v1 default set of cleartext request fields excluded
// from the AAD (SPEC §5.2) — the "unbound" denylist a client applies when the
// caller does not override it. Like DefaultSealedFields it returns a fresh slice,
// so a caller may append to it (e.g. "x_0g_trace", "route_options") without
// mutating the shared default. The default lives here in exactly one place;
// clients reference it rather than re-listing the names.
//
// "model" is unbound so an intermediary (router/broker) may rewrite it in transit
// — e.g. resolving an alias or picking a fallback candidate — without breaking
// Open. An unbound value is NOT authenticated by the transport crypto: trust in
// the model actually served comes from the TEE response signature (D4), never
// from the AAD. The unbound_fields list itself stays bound (it lives in _e2ee),
// so an intermediary cannot enlarge it to free other fields.
//
// TODO(model-binding): including "model" here is a TEMPORARY measure. The 0G
// router still rewrites "model" in transit, so binding it would fail Open. Once
// the router stops modifying "model", REVERT this to an empty set (bind
// everything) so "model" is tamper-evident on the wire again — restoring the
// original D2 decision (see docs/design/request-envelope-and-integrity.md).
func DefaultUnboundFields() []string {
	return []string{"model"}
}

// ValidateSealedFields enforces the chat-profile invariants on a sealed-field
// set — shorthand for ValidateSealedFieldsFor(ProfileChat, fields).
func ValidateSealedFields(fields []string) error {
	return ValidateSealedFieldsFor(ProfileChat, fields)
}

// ValidateSealedFieldsFor enforces the invariants on a sealed-field set for a
// profile: non-empty, no duplicates, the profile's payload field present
// ("messages" for chat, "prompt" for image), and no pinned cleartext field
// swallowed by the set. Leaving the payload cleartext defeats the purpose, so
// any sealed envelope MUST cover it.
//
// SealRequestFor calls this fail-closed per request, so a client cannot build an
// envelope that silently leaves the payload exposed — the only place a leak can
// actually be *prevented*. It is also exported so a caller can validate an
// operator-supplied sealed set up front (e.g. the sidecar's -seal-fields flag)
// and fail fast instead of erroring on every request.
//
// That second use is why the pinned check belongs here and not only in
// SealRequestFor. The two rules answer the same question — "is this set of field
// names valid for this profile?" — and depend on nothing but (profile, fields),
// so an operator validating `-seal-fields` up front must see both verdicts. With
// the pinned half elsewhere, `prompt,response_format` passed startup validation
// clean and then failed 100% of requests: the exact failure mode the fail-fast
// call exists to prevent.
//
// By the same rule, what it does NOT check is a profile's CONDITIONAL payload
// fields (requiredIfPresent, e.g. Anthropic's `system`): whether those are
// required depends on the request, not on the field names, so they cannot be
// answered here. SealRequestFor and OpenRequestFor run that half — see
// validatePayloadIfPresentFor.
func ValidateSealedFieldsFor(p Profile, fields []string) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return fmt.Errorf("no sealed fields")
	}
	if err := validatePinnedNotSealed(spec, fields); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(fields))
	hasRequired := false
	for _, f := range fields {
		if f == "" {
			return fmt.Errorf("empty sealed field name")
		}
		if f == e2eeKey {
			return fmt.Errorf("%q is reserved and cannot be a sealed field", e2eeKey)
		}
		if _, dup := seen[f]; dup {
			return fmt.Errorf("duplicate sealed field %q", f)
		}
		seen[f] = struct{}{}
		if f == spec.required {
			hasRequired = true
		}
	}
	if !hasRequired {
		return fmt.Errorf("%s-profile sealed fields must include %q", p, spec.required)
	}
	return nil
}

// ValidateUnboundFields enforces the invariants on the unbound (AAD-excluded)
// set (SPEC §5.2): no empty names, no duplicates, the reserved `_e2ee` key is
// disallowed, and no overlap with the sealed set — a field cannot be both
// encrypted and intermediary-mutable.
//
// Unlike sealed fields, an unbound field need NOT be present in the message: it
// may name a slot an intermediary will only fill in later (e.g. a router-injected
// trace object). An empty set is valid and means "bind everything".
func ValidateUnboundFields(unbound, sealed []string) error {
	if len(unbound) == 0 {
		return nil
	}
	sealedSet := toSet(sealed)
	seen := make(map[string]struct{}, len(unbound))
	for _, f := range unbound {
		if f == "" {
			return fmt.Errorf("empty unbound field name")
		}
		if f == e2eeKey {
			return fmt.Errorf("%q is reserved and cannot be an unbound field", e2eeKey)
		}
		if _, dup := seen[f]; dup {
			return fmt.Errorf("duplicate unbound field %q", f)
		}
		seen[f] = struct{}{}
		if _, both := sealedSet[f]; both {
			return fmt.Errorf("field %q cannot be both sealed and unbound", f)
		}
	}
	return nil
}

// E2EE is the sealing-metadata object added to the request under `_e2ee` (§5).
type E2EE struct {
	V            int      `json:"v"`
	KEMID        string   `json:"kem_id"`
	KeyID        string   `json:"key_id"`         // base64url(SHA-256(enc_pub)[0:8])
	SignerAddr   string   `json:"signer_addr"`    // provider TEE signer address (teeSignerAddress, 0x…); the enclave verifies it and signs responses with it
	ClientEphPub string   `json:"client_eph_pub"` // base64url X25519, for response sealing
	Enc          string   `json:"enc"`            // base64url HPKE encapsulated key
	SealedFields []string `json:"sealed_fields"`
	// UnboundFields lists cleartext fields excluded from the AAD (SPEC §5.2):
	// intermediaries may add/modify/remove them. The list itself is bound (it
	// lives here in `_e2ee`), so it cannot be enlarged in transit. Omitted when
	// empty, which means "bind everything" (the safe default).
	UnboundFields []string `json:"unbound_fields,omitempty"`
	Ciphertext    string   `json:"ciphertext"` // base64url; excluded from the AAD
}

// Request is a decoded OpenAI-shaped request as an ordered-agnostic field map.
// Values are kept as raw JSON so unknown fields pass through untouched.
type Request map[string]json.RawMessage

// SealRequest builds the §5 request envelope for the chat profile — shorthand
// for SealRequestFor(ProfileChat, …).
func SealRequest(encPub crypto.PublicKey, req Request, sealedFields []string, signerAddr string, clientEphPub []byte, unboundFields ...string) (Request, error) {
	return SealRequestFor(ProfileChat, encPub, req, sealedFields, signerAddr, clientEphPub, unboundFields...)
}

// SealRequestFor builds the §5 request envelope. It removes sealedFields from
// req, seals their values to encPub, and returns a new Request carrying the
// cleartext fields plus the `_e2ee` object.
//
//   - profile:      the request family (ProfileChat, ProfileImage); it fixes only
//     which field MUST be sealed — the wire format is identical, and the profile
//     is not carried on the wire (`sealed_fields` is self-describing).
//   - encPub:       the provider enc key (verified out of a quote by the caller)
//   - sealedFields: fields to seal; nil uses the profile's v1 default. The
//     profile's payload field is required and each field MUST be present in req.
//   - signerAddr:   the provider's on-chain TEE signer address ("0x…"), the pin
//   - clientEphPub: the client's response ephemeral X25519 public key (raw bytes)
//   - unboundFields: optional cleartext fields excluded from the AAD (§5.2), i.e.
//     ones an intermediary may add/modify. Empty (the default) binds everything.
func SealRequestFor(profile Profile, encPub crypto.PublicKey, req Request, sealedFields []string, signerAddr string, clientEphPub []byte, unboundFields ...string) (Request, error) {
	spec, err := profile.spec()
	if err != nil {
		return nil, err
	}
	if sealedFields == nil {
		sealedFields = DefaultSealedFieldsFor(profile)
	}
	if err := ValidateSealedFieldsFor(profile, sealedFields); err != nil {
		return nil, err
	}
	// The conditional half of the payload requirement, which needs the request:
	// a field the profile only demands when it is there (Anthropic's `system`).
	if err := validatePayloadIfPresentFor(profile, sealedFields, req); err != nil {
		return nil, err
	}
	// Sealing the payload is not enough on its own: a cleartext field can direct
	// the server to publish the RESULT outside the sealed channel (§7.1). Check
	// the value AND that it will still be readable and authenticated when it gets
	// there — a pin that is sealed away, or that an intermediary can rewrite, is
	// not a pin. ValidateSealedFieldsFor above already rejected a set that seals
	// the pin away; validatePinnedCleartextFor runs all three checks together on
	// the receiving side.
	if err := validatePinnedNotUnbound(spec, unboundFields); err != nil {
		return nil, err
	}
	if err := validatePinnedCleartext(spec, req); err != nil {
		return nil, err
	}
	if err := ValidateUnboundFields(unboundFields, sealedFields); err != nil {
		return nil, err
	}
	if !isSignerAddr(signerAddr) {
		return nil, fmt.Errorf("invalid signer_addr %q (want 0x followed by 40 hex)", signerAddr)
	}
	// clientEphPub is stored, not used, at seal time — the enclave seals the
	// response to it (§7). Reject a malformed key here rather than emit an
	// envelope whose response can never be opened.
	if len(clientEphPub) != clientEphPubLen {
		return nil, fmt.Errorf("client_eph_pub must be %d bytes (X25519), got %d", clientEphPubLen, len(clientEphPub))
	}

	// 1. sealed_obj = { field: original value } for each sealed field.
	sealedObj := make(map[string]json.RawMessage, len(sealedFields))
	for _, f := range sealedFields {
		v, ok := req[f]
		if !ok {
			return nil, fmt.Errorf("sealed field %q not present in request", f)
		}
		sealedObj[f] = v
	}
	// The sealed body needs no canonical form: the AEAD protects its exact
	// bytes, and the response signature binds the ciphertext, not a re-derived
	// canonical plaintext (D1 / SPEC §8). Plain Marshal avoids the JCS pass that
	// profiling showed dominates SealRequest at large payloads.
	pt, err := json.Marshal(sealedObj)
	if err != nil {
		return nil, fmt.Errorf("marshal sealed object: %w", err)
	}

	// 2. HPKE setup — enc is needed before the AAD (it lives inside `_e2ee`).
	enc, sealer, err := crypto.SetupSender(encPub, []byte(SealInfo))
	if err != nil {
		return nil, err
	}

	// 3. Build the envelope: cleartext fields (req minus sealed) + `_e2ee`.
	env := make(Request, len(req)+1)
	sealedSet := toSet(sealedFields)
	for k, v := range req {
		if k == e2eeKey {
			return nil, fmt.Errorf("request already contains %q", e2eeKey)
		}
		if _, sealed := sealedSet[k]; sealed {
			continue
		}
		env[k] = v
	}
	e2ee := E2EE{
		V:             Version,
		KEMID:         KEMID,
		KeyID:         b64.EncodeToString(keyID(encPub)),
		SignerAddr:    signerAddr,
		ClientEphPub:  b64.EncodeToString(clientEphPub),
		Enc:           b64.EncodeToString(enc),
		SealedFields:  sealedFields,
		UnboundFields: unboundFields, // nil/empty → omitted (bind everything)
		// Ciphertext filled in after sealing; it is excluded from the AAD.
	}
	if err := env.setE2EE(e2ee); err != nil {
		return nil, err
	}

	// 4. aad = JCS(envelope without _e2ee.ciphertext and the unbound fields).
	aad, err := aadFromEnvelope(env)
	if err != nil {
		return nil, err
	}

	// 5. Seal and record the ciphertext.
	ct, err := sealer.Seal(pt, aad)
	if err != nil {
		return nil, err
	}
	e2ee.Ciphertext = b64.EncodeToString(ct)
	if err := env.setE2EE(e2ee); err != nil {
		return nil, err
	}
	return env, nil
}

// OpenRequestFor is the enclave's entry point: it runs every profile check the
// receiver is responsible for, then opens the envelope. It is the request-side
// counterpart of OpenResponseFor, and exists for the same reason — a check the
// caller has to remember to make separately is a check that eventually is not
// made.
//
// SPEC §12 puts a bolded "receiver must refuse" against both of these, on the
// reasoning that a third-party CLIENT is not obliged to run the sender-side
// half. The same reasoning applies to a third-party ENCLAVE, and to an enclave
// living in another repository: neither should have to know that two separate
// validators exist and must be called in the right order before OpenRequest.
// Prefer this over calling OpenRequest directly.
//
// The checks, in order, all before any decryption:
//
//   - ValidateSealedFieldsFor — the sealed set covers this profile's payload
//     field, so the request did not arrive with its prompt in the clear;
//   - validatePayloadIfPresentFor — no conditional payload field (Anthropic's
//     top-level `system`) arrived in the cleartext half;
//   - validatePinnedCleartextFor — the pinned cleartext field is present, has
//     the required value, and was neither sealed away nor declared unbound.
//
// Then OpenRequest's own fail-closed checks (version, suite, AEAD, decrypted
// keys == declared sealed_fields, no collision with cleartext).
func OpenRequestFor(profile Profile, priv crypto.PrivateKey, env Request) (Request, error) {
	if _, err := profile.spec(); err != nil {
		return nil, err
	}
	e2ee, err := env.E2EE()
	if err != nil {
		return nil, err
	}
	if err := ValidateSealedFieldsFor(profile, e2ee.SealedFields); err != nil {
		return nil, err
	}
	// Read on the ENVELOPE, where a sealed field is already gone: a conditional
	// payload field still present here arrived in the clear.
	if err := validatePayloadIfPresentFor(profile, e2ee.SealedFields, env); err != nil {
		return nil, err
	}
	if err := validatePinnedCleartextFor(profile, env); err != nil {
		return nil, err
	}
	return OpenRequest(priv, env)
}

// OpenRequest reverses SealRequest with the recipient private key (SPEC §6): it
// recomputes the AAD, opens the sealed object, checks the decrypted keys equal
// sealed_fields and do not collide with cleartext fields, and returns the
// reconstructed original request (cleartext ∪ decrypted). It does NOT enforce
// signer_addr == the enclave's own signer address; that policy check belongs to
// the caller (the broker), which knows its own identity — read it via E2EE().
//
// It also does NOT apply the profile checks: it cannot, since it is not told
// which profile the request belongs to. An enclave that knows the endpoint it
// serves should call OpenRequestFor instead, which runs them and then delegates
// here.
func OpenRequest(priv crypto.PrivateKey, env Request) (Request, error) {
	e2ee, err := env.E2EE()
	if err != nil {
		return nil, err
	}
	if e2ee.V != Version {
		return nil, fmt.Errorf("unsupported envelope version %d", e2ee.V)
	}
	if e2ee.KEMID != KEMID {
		return nil, fmt.Errorf("unsupported kem_id %q", e2ee.KEMID)
	}
	enc, err := b64.DecodeString(e2ee.Enc)
	if err != nil {
		return nil, fmt.Errorf("bad enc: %w", err)
	}
	ct, err := b64.DecodeString(e2ee.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bad ciphertext: %w", err)
	}

	aad, err := aadFromEnvelope(env)
	if err != nil {
		return nil, err
	}
	opener, err := crypto.SetupReceiver(priv, enc, []byte(SealInfo))
	if err != nil {
		return nil, err
	}
	pt, err := opener.Open(ct, aad) // fail-closed on tamper / wrong key
	if err != nil {
		return nil, err
	}

	var sealedObj map[string]json.RawMessage
	if err := json.Unmarshal(pt, &sealedObj); err != nil {
		return nil, fmt.Errorf("decrypted object is not a JSON object: %w", err)
	}
	// Decrypted keys MUST equal the declared sealed_fields exactly (§5.1).
	if !sameKeys(sealedObj, e2ee.SealedFields) {
		return nil, fmt.Errorf("decrypted fields do not match sealed_fields")
	}

	// Reconstruct: cleartext fields (minus _e2ee) merged with decrypted fields,
	// rejecting any collision (§5.1).
	out := make(Request, len(env)+len(sealedObj))
	for k, v := range env {
		if k == e2eeKey {
			continue
		}
		out[k] = v
	}
	for k, v := range sealedObj {
		// Defense in depth (H2): a decrypted `_e2ee` would otherwise slip the
		// collision check below, since `out` is built with `_e2ee` excluded.
		// sameKeys + ValidateSealedFields already forbid it, but a
		// non-conformant sealer must never be able to inject the metadata key.
		if k == e2eeKey {
			return nil, fmt.Errorf("decrypted object must not contain %q", e2eeKey)
		}
		if _, clash := out[k]; clash {
			return nil, fmt.Errorf("sealed field %q collides with a cleartext field", k)
		}
		out[k] = v
	}
	return out, nil
}

// E2EE decodes the `_e2ee` metadata object. Intermediaries (the router) use this
// to read routing/pin fields without decrypting anything.
func (r Request) E2EE() (E2EE, error) {
	raw, ok := r[e2eeKey]
	if !ok {
		return E2EE{}, fmt.Errorf("envelope missing %q", e2eeKey)
	}
	var e E2EE
	if err := json.Unmarshal(raw, &e); err != nil {
		return E2EE{}, fmt.Errorf("decode %q: %w", e2eeKey, err)
	}
	return e, nil
}

func (r Request) setE2EE(e E2EE) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode %q: %w", e2eeKey, err)
	}
	r[e2eeKey] = raw
	return nil
}

// aadFromEnvelope computes the AAD: JCS of the whole envelope with the
// `_e2ee.ciphertext` value and any fields named in `_e2ee.unbound_fields`
// removed (§5.2). Sender and receiver call this with the same logical envelope,
// so — JCS being canonical — they derive identical bytes without depending on
// field order or whitespace.
func aadFromEnvelope(env map[string]json.RawMessage) ([]byte, error) {
	out := make(map[string]json.RawMessage, len(env))
	for k, v := range env {
		out[k] = v
	}
	rawE2EE, ok := out[e2eeKey]
	if !ok {
		return nil, fmt.Errorf("envelope missing %q", e2eeKey)
	}
	var e2ee map[string]json.RawMessage
	if err := json.Unmarshal(rawE2EE, &e2ee); err != nil {
		return nil, fmt.Errorf("decode %q for aad: %w", e2eeKey, err)
	}
	// Exclude the intermediary-mutable fields from the AAD (SPEC §5.2). The
	// `unbound_fields` list itself stays inside `_e2ee` (restored below), so it
	// remains bound — an attacker cannot enlarge the set without changing the
	// AAD. Strict (H1): it MUST be a JSON array of strings; anything else (a
	// string, number, object) fails closed here, before Open. Absent/`null` →
	// exclude nothing. `_e2ee` itself is never excludable (re-added below).
	if rawUnbound, ok := e2ee["unbound_fields"]; ok {
		var unbound []string
		if err := json.Unmarshal(rawUnbound, &unbound); err != nil {
			return nil, fmt.Errorf("unbound_fields must be an array of strings: %w", err)
		}
		for _, f := range unbound {
			delete(out, f)
		}
	}
	delete(e2ee, "ciphertext")
	cleaned, err := json.Marshal(e2ee)
	if err != nil {
		return nil, err
	}
	out[e2eeKey] = cleaned
	return canonicalJSON(out)
}

// canonicalJSON marshals v and returns its JCS (RFC 8785) canonical form.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// keyID = SHA-256(enc_pub)[0:8] (§4.3).
func keyID(encPub crypto.PublicKey) []byte {
	h := sha256.Sum256(encPub)
	return h[:8]
}

// isSignerAddr reports whether s is a 0x-prefixed 20-byte hex address — the
// on-chain signer address format (§4.2). Case-insensitive on the hex body; the
// checksum (EIP-55) is not verified here.
func isSignerAddr(s string) bool {
	if len(s) != 42 || s[0] != '0' || s[1] != 'x' {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func toSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

// sameKeys reports whether the keys of obj are exactly the set fields (no more,
// no fewer, no duplicates in fields).
func sameKeys(obj map[string]json.RawMessage, fields []string) bool {
	if len(obj) != len(fields) {
		return false
	}
	for _, f := range fields {
		if _, ok := obj[f]; !ok {
			return false
		}
	}
	return true
}
