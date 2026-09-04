package wire

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// RespInfo is the HPKE info string for response sealing (SPEC §7). It differs
// from the request's SealInfo, so a request context cannot open a response.
const RespInfo = "0g-pc/v1/resp"

// Response is one response frame: cleartext fields (usage, model, id, created,
// system_fingerprint) plus an `_e2ee` object holding the sealed choices. A
// non-streaming response is a single frame; a streaming (SSE) response is a
// sequence of frames sharing one HPKE context.
type Response map[string]json.RawMessage

// ResponseE2EE is the `_e2ee` object on a response frame (§7). v and enc appear
// on the first frame only; the rest of a streaming response reuses that context.
type ResponseE2EE struct {
	V            int      `json:"v,omitempty"`
	Enc          string   `json:"enc,omitempty"` // base64url; first frame only
	SealedFields []string `json:"sealed_fields"`
	// UnboundFields: cleartext frame fields excluded from the AAD (§5.2 / D5),
	// e.g. a router-injected `x_0g_trace`. Bound as a list, omitted when empty.
	UnboundFields []string `json:"unbound_fields,omitempty"`
	Final         bool     `json:"final"`
	Ciphertext    string   `json:"ciphertext"` // base64url; excluded from the AAD
}

// DefaultResponseSealedFieldsFor is the v1 default set of response fields to
// seal for a profile (SPEC §7): the generated content — "choices" for chat,
// "data" (the images) for image. Everything else in the frame stays cleartext so
// the router can bill on it without decrypting.
//
// An unknown profile yields an EMPTY BUT NON-NIL slice, so a caller that passes
// the result straight into SealFrame fails closed with "no sealed fields".
// Returning nil would instead be read by SealFrame as "use the default", sending
// it back here for a profile that does not exist.
//
// The enclave passes this explicitly per service type; it is exported so the
// broker names the field in one place rather than re-listing it.
//
// A FRAME-TYPED profile (Anthropic, §7.2) has no profile-wide answer — what a
// frame must seal depends on the frame — and yields the same empty non-nil
// slice as an unknown profile. Callers serving such a profile MUST use
// ResponseSealedFieldsForFrame, or pass nil to SealFrame and let it resolve per
// frame; an empty set held for a whole stream would seal nothing on every
// content frame. SealFrame refuses that (the frame's shape requires its content
// field), so the mistake fails loudly rather than shipping cleartext.
//
// A profile with CONDITIONALLY sealed response fields (speech, §7.3) has no
// profile-wide answer either, and yields the same empty set — for a reason worth
// spelling out, because here the tempting answer is not merely incomplete but
// LATENT. Returning `["text"]` would be valid for every `json` transcription and
// invalid for every `verbose_json` one, so a broker holding it would pass all its
// own testing and then fail 100% of verbose responses in production, the first
// time a client asked for timestamps — after the upstream call, which is already
// billed. An empty set fails on the very first request instead. Use
// ResponseSealedFieldsForFrame, or pass nil to SealFrame.
func DefaultResponseSealedFieldsFor(p Profile) []string {
	s, err := p.spec()
	if err != nil || s.responseFrames != nil || s.hasOptionalResponsePayload() {
		return []string{}
	}
	return s.alwaysSealedResponseFields()
}

// alwaysSealedResponseFields are the response payload fields every frame of this
// profile must seal — the mandatory ones. The optional ones are deliberately not
// here: they are added per frame by responseFieldsFor, because a set naming
// `segments` would be refused by SealFrame on every plain `json` transcription
// (see profileSpec.responsePayload for why this differs from the request side).
func (s profileSpec) alwaysSealedResponseFields() []string {
	out := make([]string, 0, len(s.responsePayload))
	for _, f := range s.responsePayload {
		if !f.optional {
			out = append(out, f.name)
		}
	}
	return out
}

// hasOptionalResponsePayload reports whether this profile's response sealed set
// varies with the frame, which is what makes a profile-wide default unanswerable.
func (s profileSpec) hasOptionalResponsePayload() bool {
	for _, f := range s.responsePayload {
		if f.optional {
			return true
		}
	}
	return false
}

// ResponseSealedFieldsForFrame resolves what THIS frame must seal under a
// profile: the profile default for a single-shape profile (chat, image),
// whatever the frame; the shape's own content field for a frame-typed one
// (§7.2), which may legitimately be nothing at all for a sequencing frame.
//
// Exported so an enclave streaming a frame-typed profile can name the set it is
// about to seal — for a signature, a log, or its own guard — rather than
// duplicating the taxonomy. SealFrame calls it for a nil sealedFields.
func ResponseSealedFieldsForFrame(p Profile, frame Response) ([]string, error) {
	spec, err := p.spec()
	if err != nil {
		return nil, err
	}
	if spec.responseFrames == nil {
		return spec.responseFieldsFor(frame), nil
	}
	_, shape, err := spec.responseFrames.shapeOf(frame)
	if err != nil {
		return nil, fmt.Errorf("%s-profile: %w", p, err)
	}
	return shape.sealedFieldsFor(frame), nil
}

// responseFieldsFor is what a frame of a SINGLE-SHAPE profile must seal: every
// mandatory response payload field, plus each optional one this frame actually
// carries.
//
// For chat and image no field is optional and this is exactly the always-sealed
// set — the conditional half is inert for them by construction, not by a flag.
//
// It mirrors frameShape.sealedFieldsFor, and for the same reason: one function
// serves both ends. At seal time the frame still holds what it is about to seal,
// so a present `segments` is required; at open time a sealed one is already gone
// from the cleartext, so it is not required — but one that is STILL there was
// never sealed, and that is exactly the rejection the receiver owes (SPEC §12).
//
// One list per profile is also what makes a duplicate unrepresentable. While the
// mandatory and optional fields were two lists, a name in both produced a
// doubled entry here that validateResponseSealedFieldNames would reject with a
// confusing message about the CALLER's set.
func (s profileSpec) responseFieldsFor(frame Response) []string {
	out := make([]string, 0, len(s.responsePayload))
	for _, f := range s.responsePayload {
		if f.optional {
			if _, present := frame[f.name]; !present {
				continue
			}
		}
		out = append(out, f.name)
	}
	return out
}

// IsTerminalResponseFrame reports whether this frame is one that ENDS a stream
// of this profile, and so is the frame `final` belongs on (§7).
//
// A frame-typed profile can have more than one: Anthropic ends a completed turn
// with `message_stop` and a failed one with `error`, and a stream that ends with
// `error` sends no `message_stop` at all. An enclave that recognized only the
// former would emit a stream with no final frame — which §7 requires the client
// to reject as a truncation — so this is exported rather than left for each
// enclave to hardcode, which is the drift the taxonomy exists to prevent.
//
// A single-shape profile (chat, image) has no terminal EVENT: its final frame is
// whichever one the sealer marks, and for a stream that is a synthesized
// placeholder. Those profiles therefore answer false for every frame, with no
// error — "no terminal shape" is an answer, not a failure.
//
// This answers "which STREAM frame ends the stream", not "is this frame final",
// and the two differ on one shape: a NON-STREAMING frame (Anthropic's `message`)
// answers false, because it does not end a stream — it is the whole response,
// `final` by definition, and `SealResponseFor` marks it directly. So do not wire
// a sealer's `final` argument to this function unconditionally: on the
// non-streaming path that would emit `final: false`, which §7 requires the
// client to reject as a truncation. Use it only where a stream is being sealed
// frame by frame.
func IsTerminalResponseFrame(p Profile, frame Response) (bool, error) {
	spec, err := p.spec()
	if err != nil {
		return false, err
	}
	if spec.responseFrames == nil {
		return false, nil
	}
	_, shape, err := spec.responseFrames.shapeOf(frame)
	if err != nil {
		return false, fmt.Errorf("%s-profile: %w", p, err)
	}
	return shape.terminal, nil
}

// ResponseFramesAreTyped reports whether this profile's responses are frame-typed
// — an event taxonomy where each frame declares its own shape (SPEC §7.2) — as
// opposed to a single response shape.
//
// It is the question a stream's FRAMING depends on, which is why it is answered
// here rather than by each receiver testing for a profile by name. Two things
// differ, and neither is derivable from a frame:
//
//   - a frame-typed stream announces every event by name, so a receiver must
//     emit an `event:` line (see ResponseEventName);
//   - it ends with a TERMINAL FRAME of its own (Anthropic's `message_stop`, or
//     `error` on a turn that failed partway), so OpenAI's `data: [DONE]`
//     sentinel must NOT be appended. `[DONE]` is a chat convention; sending it
//     on a frame-typed stream is a protocol violation, and an SDK reading that
//     stream has no rule that would let it ignore the extra event.
//
// Both are the same class of fact as stream_options being a chat-only field, and
// they are all read off the profile for the same reason: a surface that streams
// is not thereby an OpenAI stream.
func ResponseFramesAreTyped(p Profile) bool {
	spec, err := p.spec()
	if err != nil {
		return false
	}
	return spec.responseFrames != nil
}

// ResponseEventName is the SSE `event:` name a receiver MUST announce a frame
// under, or "" for a profile whose responses are not frame-typed.
//
// It exists because §7.2 puts a requirement on the RECEIVER that nothing else
// could satisfy: the `event:` line sits outside the JSON and therefore outside
// the AAD, so an intermediary can rewrite it undetected. A sender must drop the
// upstream's line and a receiver must not trust one — both rebuild it from the
// frame's own bound discriminator, which the seal covers. Handing a client an
// Anthropic stream with no `event:` lines is not a lesser version of the
// protocol either: an Anthropic SDK dispatches on the event name, so the frames
// arrive unusable.
//
// The frame must be the OPENED (plaintext) one, since that is what the receiver
// announces. The discriminator itself is cleartext on the wire, so either would
// read the same value — but opening is what proves the frame was sealed as its
// shape requires, and a name derived before that check would announce a shape
// nothing had validated.
//
// A single-shape profile (chat, image) answers "" with no error: those streams
// have no event taxonomy, and their frames carry no name to announce. An unknown
// or malformed discriminator IS an error, via shapeOf — the same refusal the
// seal and open paths give, for the same reason.
//
// A name containing a line break is refused rather than emitted. It is
// unreachable through the taxonomy (shapeOf accepts only a fixed set of
// identifiers), and that is exactly why it is checked here: a name written into
// an SSE line would end that line and start a fresh one, so a value that ever
// escaped the taxonomy would let an intermediary inject an unsealed `data:`
// frame ahead of the real one — the channel dropping the upstream's own
// `event:` line exists to close.
func ResponseEventName(p Profile, frame Response) (string, error) {
	spec, err := p.spec()
	if err != nil {
		return "", err
	}
	if spec.responseFrames == nil {
		return "", nil
	}
	kind, _, err := spec.responseFrames.shapeOf(frame)
	if err != nil {
		return "", fmt.Errorf("%s-profile: %w", p, err)
	}
	if strings.ContainsAny(kind, "\r\n") {
		return "", fmt.Errorf("%s-profile: frame %s %q contains a line break",
			p, spec.responseFrames.discriminator, kind)
	}
	return kind, nil
}

// shapeOf reads a frame's cleartext discriminator and returns its shape. An
// absent, non-string or unrecognized value is an error: a frame whose shape is
// unknown may carry content, and nothing about it says it does not, so it is
// refused rather than sealed (or opened) under a guess.
func (r responseFrameRule) shapeOf(frame Response) (string, frameShape, error) {
	raw, ok := frame[r.discriminator]
	if !ok {
		return "", frameShape{}, fmt.Errorf("frame has no cleartext %q, so its shape — and what it must seal — cannot be determined", r.discriminator)
	}
	var kind string
	if err := json.Unmarshal(raw, &kind); err != nil {
		return "", frameShape{}, fmt.Errorf("frame %q must be a JSON string: %w", r.discriminator, err)
	}
	shape, known := r.shapes[kind]
	if !known {
		return kind, frameShape{}, fmt.Errorf("unknown frame %s %q: an unrecognized shape may carry content, so it is refused rather than passed through", r.discriminator, kind)
	}
	return kind, shape, nil
}

// mustStayCleartextInResponse are response fields a sealed frame MUST NOT seal,
// whatever the profile: the router reads them WITHOUT a key to bill and to
// attribute the response, so sealing one does not merely inconvenience it — it
// makes the response unbillable (SPEC §7).
//
// This is a floor for every profile rather than a per-profile list because the
// reason is the same everywhere: the router's inputs. `usage` covers both the
// chat token counts and the image `usage.output_images` (§7.1).
var mustStayCleartextInResponse = []string{"usage", "model"}

// mustStayBoundInResponse are cleartext response fields that may never be listed
// in `unbound_fields`. Cleartext is not the whole requirement: an unbound field
// is excluded from the seal AAD, so an intermediary can rewrite it, the client's
// Open still succeeds, AND the §8 binding — which hashes that same AAD — comes
// out byte-identical. A router could therefore restate `usage.output_images`
// from 2 to 99 with nothing anywhere detecting it. "The router bills on it
// without decrypting, and a lying count is caught at verify" (§7.1) is only true
// while `usage` is bound.
//
// Deliberately NOT the same list as mustStayCleartextInResponse: `model` is on
// that one but not this one. The broker declares `model` unbound on purpose, so
// the router can substitute the served model back to the alias the client asked
// for, and the resulting un-authenticated `model` is a known, documented
// trade-off (see DefaultUnboundFields' TODO(model-binding)). `usage` has no such
// justification — nothing downstream needs to rewrite it.
var mustStayBoundInResponse = []string{"usage"}

// validateResponseUnboundFields rejects an unbound set that would strip the
// authentication from a field the §8 signature must cover.
//
// It is enforced on BOTH sides, and the receiving side is the one that matters.
// Checking only at seal time protects a conforming enclave from misconfiguring
// itself; it does nothing about the actual threat, which is an enclave that
// declares `usage` unbound on purpose so a router can restate the billable count
// with Open and the §8 verification both still passing. Only the client can
// refuse that, so OpenFrame calls this on every frame — per frame, not once,
// because a sealer that varies the set could otherwise declare it late in a
// stream.
//
// Not profile-parameterized, unlike validateResponseSealedFieldsFor: WHAT a
// profile seals differs, but which fields must stay authenticated does not, and
// a per-profile signature would imply a latitude no profile actually has.
func validateResponseUnboundFields(unbound []string) error {
	for _, f := range unbound {
		if slices.Contains(mustStayBoundInResponse, f) {
			return fmt.Errorf("%q must stay bound: an unbound field is outside the seal AAD and the §8 binding, so an intermediary could rewrite it undetected", f)
		}
	}
	return nil
}

// validateResponseUnboundFieldsFor is the floor above plus the one field a
// profile adds to it: a frame-typed profile's discriminator (§7.2).
//
// It has to stay bound for the reason §12 states as its own row — a
// receive-side check must not be gated on a sender-controlled value. Every
// frame-shape rule keys off the discriminator, so freeing it would let an
// intermediary relabel a content frame as a sequencing one after the fact, and
// the client's checks would then apply the wrong shape's rules and pass.
//
// This is the ONE profile-specific narrowing of an otherwise profile-independent
// list, and it narrows rather than widens: no profile gets latitude here, one
// just has an extra field whose value must be trusted.
func validateResponseUnboundFieldsFor(p Profile, unbound []string) error {
	if err := validateResponseUnboundFields(unbound); err != nil {
		return err
	}
	spec, err := p.spec()
	if err != nil {
		return err
	}
	if spec.responseFrames != nil && slices.Contains(unbound, spec.responseFrames.discriminator) {
		return fmt.Errorf("%q must stay bound for the %s profile: it names the frame's shape, so an unbound one lets an intermediary relabel a content frame as a sequencing frame and every shape check then passes", spec.responseFrames.discriminator, p)
	}
	// The profile's protected fields. The floor above is name-based on TOP-LEVEL
	// fields, so it cannot reach a value that must be authenticated one level down
	// — Anthropic's billable input count at `message.usage.input_tokens` is the
	// case, and unbinding `message` would let a router restate it with the
	// client's Open and the §8 verification both still passing.
	for _, pc := range spec.protected {
		if slices.Contains(unbound, pc.field) {
			return fmt.Errorf("%q must stay bound for the %s profile: it carries %s, one level down where the profile-independent rule cannot see it, so an unbound one could be rewritten in transit and still verify", pc.field, p, pc.reads)
		}
	}
	// And the fields a required quantity is LOCATED in, which is the same trap
	// once more and in the direction the floor list cannot follow. That list is
	// `usage` by name, so it protects `usage.output_images` and `usage.seconds`
	// and nothing else: a profile whose quantity lives at a top-level `duration`
	// satisfies every rule above while leaving the number an intermediary may
	// rewrite — outside the AAD, so Open succeeds AND the §8 binding, which
	// hashes that same AAD, comes out byte-identical.
	//
	// Derived from the locators rather than added to the floor by name, so the
	// next profile that bills on a differently-named field is covered without
	// anyone remembering to extend a list. This is the mechanised form of the
	// SPEC §5.1 warning that its own table is written in field NAMES.
	for _, q := range spec.requiredResponseCleartext {
		for _, loc := range q.locators {
			if slices.Contains(unbound, loc.field) {
				return fmt.Errorf("%q must stay bound for the %s profile: it locates %s, and an unbound field is outside the AAD, so a router could restate the billed quantity with the client's Open and the §8 verification both still passing", loc.field, p, q.what)
			}
		}
	}
	return nil
}

// validateProtectedCleartextFor enforces a profile's protected fields (see
// protectedCleartext) on ONE frame: not sealed away, and carrying no content in
// the nested arrays that must stay empty.
//
// Per profile and per FRAME, deliberately — not per shape. Both bugs this
// replaced were scope mismatches: the emptiness rule was declared on
// message_start, so any other shape could carry a cleartext
// `message: {"content": [...]}` and smuggle the answer past a check that only
// looked at one shape; and the "seal nothing extra" rule only fired on shapes
// with no content of their own, so a content frame could seal `message` away and
// leave the router billing zero input tokens. Anchoring both to the field rather
// than to a shape is what makes them hold everywhere.
//
// The unbound half of the same declaration lives in
// validateResponseUnboundFieldsFor, which already runs per profile.
func validateProtectedCleartextFor(p Profile, spec profileSpec, frame Response, fields []string) error {
	for _, pc := range spec.protected {
		if slices.Contains(fields, pc.field) {
			return fmt.Errorf("%q must stay CLEARTEXT for the %s profile: it carries %s, so sealing it — even as an extra alongside a legitimate sealed field — leaves the router nothing to bill on", pc.field, p, pc.reads)
		}
		raw, ok := frame[pc.field]
		if !ok {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return fmt.Errorf("%s-profile frame field %q must be a JSON object: %w", p, pc.field, err)
		}
		for _, key := range pc.emptyArrays {
			v, present := obj[key]
			if !present {
				continue
			}
			var arr []json.RawMessage
			if err := json.Unmarshal(v, &arr); err != nil {
				return fmt.Errorf("%s-profile frame %s.%s must be a JSON array: %w", p, pc.field, key, err)
			}
			if len(arr) > 0 {
				return fmt.Errorf("%s-profile frame carries %d element(s) in cleartext %s.%s: that field stays cleartext so the router can read %s, which is exactly why content may not ride inside it — an enclave with content to send MUST use a shape that seals it", p, len(arr), pc.field, key, pc.reads)
			}
		}
	}
	return nil
}

// validateResponseSealedFields requires a non-empty set with no duplicates, and
// no field the router must be able to read. Unlike the request there is no
// single mandatory field pinned in v1 — profiles differ in WHAT they seal, but
// agree on what they may not.
func validateResponseSealedFields(fields []string) error {
	if len(fields) == 0 {
		return fmt.Errorf("no sealed fields")
	}
	return validateResponseSealedFieldNames(fields)
}

// validateResponseSealedFieldNames is validateResponseSealedFields minus the
// non-empty requirement — every rule that is about the NAMES in the set rather
// than about there being any.
//
// The split exists for the one case where an empty set is correct: a frame-typed
// profile's sequencing frames (Anthropic's message_stop and friends) carry no
// sensitive payload, and their sealed set must be exactly empty. Everywhere else
// an empty set means the content is riding in the clear, so the wrapper above
// keeps rejecting it.
func validateResponseSealedFieldNames(fields []string) error {
	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		if f == "" {
			return fmt.Errorf("empty sealed field name")
		}
		if f == e2eeKey {
			return fmt.Errorf("%q is reserved and cannot be a sealed field", e2eeKey)
		}
		if slices.Contains(mustStayCleartextInResponse, f) {
			return fmt.Errorf("%q must stay cleartext so the router can bill and attribute without decrypting", f)
		}
		if _, dup := seen[f]; dup {
			return fmt.Errorf("duplicate sealed field %q", f)
		}
		seen[f] = struct{}{}
	}
	return nil
}

// validateResponseSealedFieldsFor checks a response sealed set against a
// profile: the shared invariants above, plus that it actually covers the
// profile's generated content ("choices" for chat, "data" for image) rather than
// sealing something incidental and shipping the content in the clear.
//
// It is the response-side counterpart of ValidateSealedFieldsFor, and BOTH sides
// call it: SealFrame so a conforming enclave cannot emit such a frame, OpenFrame
// on every frame so a client can refuse one that was emitted anyway.
//
// Sealing a superset is still fine — only the MANDATORY response payload fields
// have to be there, so any superset satisfies them. That distinction is why the
// check can run at seal time at all.
func validateResponseSealedFieldsFor(p Profile, fields []string) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	if spec.responseFrames != nil {
		// A frame-typed profile has no profile-wide answer, and guessing one here
		// would be the wrong kind of wrong: spec.responsePayload is empty for such
		// a profile, so the loop below would demand nothing at all and wave through
		// a frame that seals nothing. Refuse the entry point instead — the
		// frame-aware one is the only correct caller.
		return fmt.Errorf("%s-profile response frames are typed: validate against the frame, not the profile alone", p)
	}
	if err := validateResponseSealedFields(fields); err != nil {
		return err
	}
	// Only the MANDATORY fields — not every member of the default set. A caller
	// may legitimately seal a superset, and an optional field's absence must not
	// be a hard failure here: whether it is required depends on the frame, which
	// this name-only check does not have (see validateResponseSealedIfPresent).
	for _, f := range spec.responsePayload {
		if f.optional {
			continue
		}
		if !slices.Contains(fields, f.name) {
			return fmt.Errorf("%s-profile response sealed fields must include %q", p, f.name)
		}
	}
	return nil
}

// validateResponseSealedFieldsForFrame is the frame-typed counterpart of
// validateResponseSealedFieldsFor (§7.2): it checks a sealed set against the
// shape the FRAME declares, and delegates to the profile-wide rule for a
// single-shape profile.
//
// Both ends call it, for the reason the profile-wide one does: SealFrame so a
// conforming enclave cannot emit a frame that leaks, OpenFrame on every frame so
// a client can refuse one that was emitted anyway. The three rules are
//
//   - the discriminator is neither sealed nor (checked in
//     validateResponseUnboundFieldsFor) unbound, so the shape is knowable and
//     not sender-rewritable;
//   - the shape's content field is sealed if it has one, and the set is EXACTLY
//     empty if it does not;
//   - no content field of ANY shape rides in the frame's cleartext half, which
//     is what makes a mislabeled frame detectable — see contentFields.
func validateResponseSealedFieldsForFrame(p Profile, frame Response, fields []string) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	// The profile's protected fields, first and for every profile: they are a
	// property of the field, not of the shape or of whether the profile is
	// frame-typed at all.
	if err := validateProtectedCleartextFor(p, spec, frame, fields); err != nil {
		return err
	}
	// The fields a required quantity is LOCATED in, likewise for every profile
	// and every frame. `usage` is already covered by the profile-independent
	// floor, so only the names that floor cannot reach are checked here — a
	// top-level `duration` being the case.
	//
	// This is not belt-and-braces over the §7.3 presence check, and the reason is
	// alternation. With one locator, sealing it IS fail-closed: it disappears
	// from the cleartext and the presence check refuses the frame. With two, a
	// frame can seal `duration` and satisfy the requirement through a cleartext
	// `usage.seconds` — so the presence check passes and the sealed locator is
	// simply invisible. What that costs is the AGREEMENT rule: at seal time both
	// values are in hand and a disagreement is caught, but at open time the
	// sealed one is gone from the cleartext, so a client cannot compare them.
	// Refusing the seal is what keeps both locators visible to the receiver, and
	// therefore what makes the client's half of the agreement rule exist at all.
	if err := validateQuantityLocatorsNotSealed(p, spec, fields); err != nil {
		return err
	}
	rule := spec.responseFrames
	if rule == nil {
		if err := validateResponseSealedFieldsFor(p, fields); err != nil {
			return err
		}
		// The conditional half, which needs the FRAME and so cannot live in the
		// name-only validator above.
		return validateResponseSealedIfPresent(p, spec, frame, fields)
	}
	if slices.Contains(fields, rule.discriminator) {
		return fmt.Errorf("%s-profile frames must keep %q cleartext: it names the frame's shape, and every check on the frame keys off it", p, rule.discriminator)
	}
	if err := validateResponseSealedFieldNames(fields); err != nil {
		return err
	}
	kind, shape, err := rule.shapeOf(frame)
	if err != nil {
		return fmt.Errorf("%s-profile: %w", p, err)
	}
	// What this frame must seal: the shape's content field, plus any
	// conditionally-sealed field the frame actually carries (see
	// frameShape.sealedFieldsFor for why one function serves both ends).
	required := shape.sealedFieldsFor(frame)
	if len(required) == 0 && len(fields) != 0 {
		// A shape with nothing sensitive of its own must seal nothing at all. Note
		// this is NOT what keeps a protected field out of the sealed set — that
		// rule fires for every shape, above, because a CONTENT frame may otherwise
		// seal a legal superset and swallow it.
		return fmt.Errorf("%s-profile %q frame carries no sensitive payload and must seal nothing, got %v", p, kind, fields)
	}
	for _, f := range required {
		if !slices.Contains(fields, f) {
			return fmt.Errorf("%s-profile %q frame must seal %q", p, kind, f)
		}
	}
	return validateNoCleartextContent(p, kind, *rule, frame, fields)
}

// validateQuantityLocatorsNotSealed rejects a sealed set that swallows a field
// one of the profile's required quantities is located in.
//
// Names already on mustStayCleartextInResponse are skipped: `usage` is refused
// by that floor with a message about the router's inputs, which is the right
// message for it, and duplicating the rejection here would only change which
// error a caller sees. What this adds is the names the floor cannot reach,
// because the floor is a list of names and a locator can be any field the
// profile declares.
func validateQuantityLocatorsNotSealed(p Profile, spec profileSpec, fields []string) error {
	for _, q := range spec.requiredResponseCleartext {
		for _, loc := range q.locators {
			if slices.Contains(mustStayCleartextInResponse, loc.field) {
				continue
			}
			if slices.Contains(fields, loc.field) {
				return fmt.Errorf("%q must stay CLEARTEXT for the %s profile: it locates %s, and sealing it hides the value from the router that bills on it — and, where a quantity has alternative locators, from the client that would otherwise check the two against each other", loc.field, p, q.what)
			}
		}
	}
	return nil
}

// validateResponseSealedIfPresent enforces a single-shape profile's
// conditionally-sealed response fields (SPEC §7.3): a field that need not
// exist, but MUST be sealed whenever the frame carries it.
//
// It is the response-side twin of validatePayloadSealedFor, with the
// receiving end swapped — the client is the half that holds here, where the
// enclave is on the request side. The predicate is the same in both: a field
// still present in the received cleartext was never sealed, because a sealer
// removes what it seals.
//
// The speech profile is the case (`segments`, `words`, the response's inferred
// `language`). A frame-typed profile expresses the same rule per shape through
// frameShape.sealIfPresent and does not come here.
//
// This is what makes conditional sealing enforceable rather than advisory: on
// the seal side it stops a conforming enclave from shipping a transcript in the
// clear, and on the open side it is the client's ONLY evidence that a
// non-conforming one did — a router forwards such a frame unremarkably, and
// nothing else in the chain has a reason to look.
func validateResponseSealedIfPresent(p Profile, spec profileSpec, frame Response, fields []string) error {
	sealed := toSet(fields)
	for _, f := range spec.responsePayload {
		if !f.optional {
			continue
		}
		if _, present := frame[f.name]; !present {
			continue
		}
		if _, isSealed := sealed[f.name]; isSealed {
			continue
		}
		return fmt.Errorf("%s-profile frame carries %q in cleartext: it is generated content and MUST be sealed whenever present", p, f.name)
	}
	return nil
}

// validateNoCleartextContent rejects a frame that carries any shape's content
// field in its cleartext half without sealing it.
//
// This is what closes mislabeling. Every other check trusts the frame's own
// `type`: a frame that claims `message_stop` and puts the answer in a cleartext
// `delta` satisfies "seal nothing, as this shape requires" exactly, opens
// cleanly, and reads to an SDK as a stray field on a stop event — while every
// intermediary has the delta. Keying the rule off the field NAMES rather than
// off the declared shape is the point: it holds whatever the frame calls itself.
//
// One predicate serves both ends, as on the request side: the sealer has not yet
// removed what it is about to seal, so the "unless it is sealed" clause is what
// makes the seal-time reading ("you are shipping content you did not seal") and
// the open-time one ("content arrived in the clear") the same code.
//
// That clause is not a way through, either. A hostile frame that declares `delta`
// sealed AND carries a cleartext `delta` is skipped here, but OpenFrame's
// collision check refuses it after decrypting ("sealed field %q collides with a
// cleartext field") — profile-independently, and for every field, not just these.
// So the two checks compose: this one catches content in a frame that does not
// claim to seal it, that one catches content in a frame that does.
func validateNoCleartextContent(p Profile, kind string, rule responseFrameRule, frame Response, fields []string) error {
	sealed := toSet(fields)
	for _, f := range rule.contentFields() {
		if _, present := frame[f]; !present {
			continue
		}
		if _, isSealed := sealed[f]; isSealed {
			continue
		}
		return fmt.Errorf("%s-profile %q frame carries %q in cleartext: it is generated content under some frame shape, so a frame may carry it only by sealing it", p, kind, f)
	}
	return nil
}

// validateResponseCleartextFor enforces a profile's required cleartext response
// values (§7.1) on a FINAL frame: for the image profile, that it restates the
// billable count as a non-negative `usage.output_images`.
//
// Sealing `data` makes the images uncountable from outside the enclave, so this
// number is the only thing the router has to bill on. Its absence is not a loud
// failure downstream — the router parses the sealed frame perfectly well and
// arrives at zero images — so nothing anywhere reports it, and every sealed
// image request is served free. That is why the requirement is checked here
// rather than left to the biller: a missing count and a genuine zero are
// indistinguishable once the frame has left.
//
// Enforced on BOTH sides. At seal time so a conforming enclave cannot ship a
// frame it will not be paid for, and at open time so a client can tell that its
// counterparty stated a count at all — the receiver half being the one that
// holds when the enclave is not conforming.
//
// FINAL frames only: `usage` is a property of the whole response, and a
// streaming profile legitimately omits it until the last frame. A profile with
// no such requirement (chat) always passes.
func validateResponseCleartextFor(p Profile, frame Response) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	for _, q := range spec.requiredResponseCleartext {
		if err := validateCleartextQuantity(p, q, frame); err != nil {
			return err
		}
	}
	return nil
}

// validateCleartextQuantity enforces ONE required cleartext quantity: at least
// one of its locators carries a value in the quantity's numeric domain, and any
// others that are also present agree with it.
//
// "At least one" rather than "all": the locators are alternatives, because one
// quantity has more than one place upstreams report it (§7.3 — `usage.seconds`
// on a `json` transcription, a top-level `duration` on a `verbose_json` one that
// carries no `usage` at all). "Any others agree" is the rule alternation brings
// with it: a client opens one locator and a router bills another, so a frame
// stating two different numbers is one response transacted at two prices.
func validateCleartextQuantity(p Profile, q cleartextQuantity, frame Response) error {
	// found records the value read from each locator that was present, so the
	// agreement check below has something to compare and the error can name which
	// locators disagreed.
	//
	// float64 for both numeric kinds, which is exact for every value either
	// quantity can hold (a whole number up to 2^53, a duration in seconds). A
	// future WHOLE quantity with alternative locators and values past 2^53 would
	// need a kind-aware comparison; there is none today, and one alternative-free
	// quantity (the image count) never reaches the comparison at all.
	type reading struct {
		locator cleartextNumber
		value   float64
	}
	var found []reading

	for _, loc := range q.locators {
		raw, ok := frame[loc.field]
		if !ok {
			continue
		}
		// A top-level locator (empty key) IS the number; otherwise it is one level
		// inside an object. A non-object where an object is expected is an error
		// rather than a skip: the field is there and malformed, which is a
		// different thing from the alternative not being used, and skipping it
		// would let a frame satisfy the requirement through the OTHER locator while
		// shipping garbage in this one for the router to read.
		v := raw
		if loc.key != "" {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				return fmt.Errorf("sealed %s response field %q must be a JSON object carrying %s: %w", p, loc.field, loc, err)
			}
			// A JSON `null` decodes into a map WITHOUT error, yielding a nil map — so
			// it would have slipped past the line above and then read as "the key is
			// not there", i.e. as this alternative simply being unused. That is the
			// same `null`-reads-as-absence trap the numeric parse below documents,
			// one level up, and it is worse here because `null` is the likeliest junk
			// value an upstream emits for a block it did not populate: `"usage": 7`
			// was correctly refused while `"usage": null` sealed cleanly. The field
			// is PRESENT and is not an object, which is the error this branch exists
			// to report.
			if obj == nil {
				return fmt.Errorf("sealed %s response field %q must be a JSON object carrying %s, got null: a null block is not the absence of the block, and %s cannot be read from it", p, loc.field, loc, loc)
			}
			inner, present := obj[loc.key]
			if !present {
				continue
			}
			v = inner
		}
		n, err := parseCleartextNumber(p, q, loc, v)
		if err != nil {
			return err
		}
		found = append(found, reading{locator: loc, value: n})
	}

	if len(found) == 0 {
		return fmt.Errorf("sealed %s response must carry cleartext %s (%s): the sealed content cannot be billed on, and an absent value is indistinguishable from a genuine zero", p, q, q.what)
	}
	// Exact comparison, on purpose. Two JSON spellings of one number (12.5 and
	// 12.50) decode to the same float64, so this only fires on values that really
	// differ — and any real difference matters, since the two readers each believe
	// their own locator.
	for _, r := range found[1:] {
		if r.value != found[0].value {
			return fmt.Errorf("sealed %s response states %s twice and disagrees: %s = %v but %s = %v. One reader bills the first and another opens the second, so they must be the same number", p, q.what, found[0].locator, found[0].value, r.locator, r.value)
		}
	}
	return nil
}

// parseCleartextNumber decodes one located value in a quantity's numeric domain.
//
// The pointer is load-bearing in both domains: decoding JSON `null` into a bare
// numeric leaves the variable untouched and returns NO error, so `null` reads as
// a perfectly good 0 — the one value §7.1 spells out as legitimate, which is why
// it once slipped past a check whose whole job is telling a real value from the
// absence of one. A pointer is nil for `null` and only for `null`.
func parseCleartextNumber(p Profile, q cleartextQuantity, loc cleartextNumber, raw json.RawMessage) (float64, error) {
	switch q.kind {
	case numberWhole:
		var n *int64
		if err := json.Unmarshal(raw, &n); err != nil {
			return 0, fmt.Errorf("sealed %s response %s must be a whole number: %w", p, loc, err)
		}
		if n == nil {
			return 0, fmt.Errorf("sealed %s response %s is null: %s must be a whole number, and null is the absence of one, not a zero", p, loc, q.what)
		}
		if *n < 0 {
			return 0, fmt.Errorf("sealed %s response %s must not be negative, got %d", p, loc, *n)
		}
		return float64(*n), nil
	case numberFractional:
		// A JSON STRING is rejected here, and that is a decision rather than a
		// consequence of the decoder: consumers of this endpoint do tolerate
		// `"12.5"` defensively against non-conforming providers, but a value that
		// is sometimes a string is a value every implementation must write two
		// parsers for, so the protocol does not bless the form. Unmarshal into
		// *float64 refuses it, which is the behaviour we want and the reason there
		// is no string fallback below.
		var n *float64
		if err := json.Unmarshal(raw, &n); err != nil {
			return 0, fmt.Errorf("sealed %s response %s must be a JSON number (a quoted string is not accepted): %w", p, loc, err)
		}
		if n == nil {
			return 0, fmt.Errorf("sealed %s response %s is null: %s must be a number, and null is the absence of one, not a zero", p, loc, q.what)
		}
		// No finiteness check, and that is checked rather than assumed: JSON has no
		// Inf or NaN literal, and Go's decoder REFUSES a finite literal that
		// overflows float64 ("cannot unmarshal number 1e400") rather than yielding
		// +Inf. So a non-finite value cannot reach here through this decode, and a
		// guard for it would be unreachable code claiming to defend something.
		// Stated because "must be finite" is what §7.3 says, and the reason it
		// needs no code is not self-evident.
		if *n < 0 {
			return 0, fmt.Errorf("sealed %s response %s must not be negative, got %v", p, loc, *n)
		}
		return *n, nil
	default:
		return 0, fmt.Errorf("sealed %s response %s: unknown numeric kind %d (a profile declared a quantity this package cannot check)", p, loc, q.kind)
	}
}

// ResponseSealer seals a sequence of response frames under one HPKE context (the
// enclave is the sender, the client's ephemeral key the recipient). Frames MUST
// be sealed in order; the receiver opens them in the same order.
type ResponseSealer struct {
	sealer  *crypto.Sealer
	enc     string // base64url; emitted on the first frame only
	first   bool
	unbound []string // AAD-excluded fields, applied to every frame
	profile Profile
	// nonConforming drops the profile-level seal-time checks so a TEST can build
	// the frame a hostile or third-party enclave would emit — the very frames the
	// receiver-side checks exist to refuse, and which a conforming sealer can no
	// longer produce. Never set outside tests: the only way to set it is
	// newNonConformingResponseSealer, which lives in export_test.go and so is not
	// compiled into the package.
	nonConforming bool
}

// validateSealedFields applies the profile's response sealed-set rule for this
// frame, or only the profile-independent floor for a deliberately non-conforming
// test sealer.
func (rs *ResponseSealer) validateSealedFields(frame Response, sealedFields []string) error {
	if rs.nonConforming {
		return validateResponseSealedFields(sealedFields)
	}
	return validateResponseSealedFieldsForFrame(rs.profile, frame, sealedFields)
}

// NewResponseSealer sets up chat-profile response sealing — shorthand for
// NewResponseSealerFor(ProfileChat, …).
func NewResponseSealer(clientEphPub crypto.PublicKey, unboundFields ...string) (*ResponseSealer, error) {
	return NewResponseSealerFor(ProfileChat, clientEphPub, unboundFields...)
}

// NewResponseSealerFor sets up response sealing to the client's ephemeral public
// key (carried in the request's _e2ee.client_eph_pub), for the profile the
// request used. unboundFields are the cleartext frame fields to exclude from the
// AAD (§5.2 / D5) — the same set is applied to every frame; empty binds
// everything. They are validated against each frame's sealed set in SealFrame.
//
// The profile is what lets SealFrame check the final frame against §7.1's
// required cleartext (see validateResponseCleartextFor); it is the send-side
// mirror of NewResponseOpenerFor and, like it, is not carried on the wire.
func NewResponseSealerFor(profile Profile, clientEphPub crypto.PublicKey, unboundFields ...string) (*ResponseSealer, error) {
	if _, err := profile.spec(); err != nil {
		return nil, err
	}
	// Before any key material: an unbound set that frees a field the signature
	// must cover would produce frames that verify no matter what an intermediary
	// does to them.
	if err := validateResponseUnboundFieldsFor(profile, unboundFields); err != nil {
		return nil, err
	}
	enc, s, err := crypto.SetupSender(clientEphPub, []byte(RespInfo))
	if err != nil {
		return nil, err
	}
	return &ResponseSealer{sealer: s, enc: b64.EncodeToString(enc), first: true, unbound: unboundFields, profile: profile}, nil
}

// SealFrame seals one frame: it removes sealedFields (nil → this sealer's
// profile's v1 default) from frame, seals their values, and returns the frame
// carrying `_e2ee`. final marks the last frame.
func (rs *ResponseSealer) SealFrame(frame Response, sealedFields []string, final bool) (Response, error) {
	if sealedFields == nil {
		// THIS sealer's profile, not chat's, and resolved against THIS frame.
		// Reading the default from a fixed profile is what
		// DefaultResponseSealedFieldsFor's own comment warns about, and it does not
		// take an unknown profile to go wrong: it made nil mean "seal choices" for
		// every profile, so the documented "nil → the profile's default" held only
		// for chat. Resolving per frame is then what a frame-typed profile needs —
		// its answer is a property of the frame, not of the profile (§7.2).
		fields, err := ResponseSealedFieldsForFrame(rs.profile, frame)
		if err != nil {
			return nil, err
		}
		sealedFields = fields
	}
	// The profile's own requirement, not just the profile-independent floor: a
	// set that seals something incidental instead of the generated content puts
	// that content in the frame's CLEARTEXT half. The client refuses such a frame,
	// but by then it has been on the wire and every intermediary has read it —
	// refusing to build it is the only place the leak is prevented rather than
	// detected (SPEC §12).
	if err := rs.validateSealedFields(frame, sealedFields); err != nil {
		return nil, err
	}
	if err := ValidateUnboundFields(rs.unbound, sealedFields); err != nil {
		return nil, err
	}
	// The last frame is where the response's billable totals are due (§7.1).
	// Checked against `frame` before anything is removed from it, so a profile
	// that ever seals part of `usage` would be caught by the sealed-set rules
	// rather than reading as "absent" here.
	if final && !rs.nonConforming {
		if err := validateResponseCleartextFor(rs.profile, frame); err != nil {
			return nil, err
		}
	}

	sealedObj := make(map[string]json.RawMessage, len(sealedFields))
	for _, f := range sealedFields {
		v, ok := frame[f]
		if !ok {
			return nil, fmt.Errorf("sealed field %q not present in frame", f)
		}
		sealedObj[f] = v
	}
	// Sealed body needs no canonical form (D1 / SPEC §8): AEAD protects its
	// exact bytes and the signature binds the ciphertext, not the plaintext.
	pt, err := json.Marshal(sealedObj)
	if err != nil {
		return nil, fmt.Errorf("marshal sealed object: %w", err)
	}

	out := make(Response, len(frame)+1)
	sealedSet := toSet(sealedFields)
	for k, v := range frame {
		if k == e2eeKey {
			return nil, fmt.Errorf("frame already contains %q", e2eeKey)
		}
		if _, sealed := sealedSet[k]; sealed {
			continue
		}
		out[k] = v
	}

	e2ee := ResponseE2EE{SealedFields: sealedFields, UnboundFields: rs.unbound, Final: final}
	if rs.first {
		e2ee.V = Version
		e2ee.Enc = rs.enc
	}
	if err := setResponseE2EE(out, e2ee); err != nil {
		return nil, err
	}

	aad, err := aadFromEnvelope(out)
	if err != nil {
		return nil, err
	}
	ct, err := rs.sealer.Seal(pt, aad)
	if err != nil {
		return nil, err
	}
	e2ee.Ciphertext = b64.EncodeToString(ct)
	if err := setResponseE2EE(out, e2ee); err != nil {
		return nil, err
	}
	rs.first = false
	return out, nil
}

// ResponseOpener opens a sequence of response frames in seal order.
type ResponseOpener struct {
	opener  *crypto.Opener
	profile Profile
}

// NewResponseOpener builds the receive context from the first frame (which
// carries enc) and the client's ephemeral private key.
func NewResponseOpener(clientEphPriv crypto.PrivateKey, firstFrame Response) (*ResponseOpener, error) {
	return NewResponseOpenerFor(ProfileChat, clientEphPriv, firstFrame)
}

// NewResponseOpenerFor builds the receive context and binds it to the profile
// the client's REQUEST used, so every frame can be checked against what that
// profile requires the response to seal.
//
// That check is the reason this variant exists. Without it a client cannot tell
// a protected response from an unprotected one: an enclave may declare
// `sealed_fields: ["created"]`, seal the timestamp, and ship `choices` in the
// CLEAR. Open succeeds (the decrypted keys do match the declared set), the
// content merges back exactly as the caller expects, and the §8 signature
// verifies too — the cleartext content is inside the AAD the binding hashes. The
// caller gets its answer, correct and complete, having no way to learn that
// every intermediary read it. It is the response-side twin of a request whose
// sealed set omits the prompt, and it is silent in the same way.
func NewResponseOpenerFor(profile Profile, clientEphPriv crypto.PrivateKey, firstFrame Response) (*ResponseOpener, error) {
	if _, err := profile.spec(); err != nil {
		return nil, err
	}
	e2ee, err := firstFrame.E2EE()
	if err != nil {
		return nil, err
	}
	if e2ee.V != Version {
		return nil, fmt.Errorf("unsupported response envelope version %d", e2ee.V)
	}
	if e2ee.Enc == "" {
		return nil, fmt.Errorf("first response frame missing enc")
	}
	enc, err := b64.DecodeString(e2ee.Enc)
	if err != nil {
		return nil, fmt.Errorf("bad enc: %w", err)
	}
	o, err := crypto.SetupReceiver(clientEphPriv, enc, []byte(RespInfo))
	if err != nil {
		return nil, err
	}
	return &ResponseOpener{opener: o, profile: profile}, nil
}

// OpenFrame opens one frame and returns it reconstructed (cleartext ∪
// decrypted). Frames MUST be opened in seal order — the underlying AEAD sequence
// increments per frame, so an out-of-order or missing frame fails.
func (ro *ResponseOpener) OpenFrame(frame Response) (Response, error) {
	e2ee, err := frame.E2EE()
	if err != nil {
		return nil, err
	}
	// Refuse a frame that frees a field whose value must be authenticated, BEFORE
	// opening it. This is the half of the check that defends the client: a
	// non-conforming enclave can declare `usage` unbound on purpose, and every
	// other verification the client runs — Open, and the §8 binding, which hashes
	// the same AAD — would still pass over a router-rewritten count.
	if err := validateResponseUnboundFieldsFor(ro.profile, e2ee.UnboundFields); err != nil {
		return nil, err
	}
	// And refuse a frame whose sealed set does not actually cover this profile's
	// generated content — otherwise the content rides in the cleartext half and
	// opening succeeds anyway. Per frame, not once on the first: sealed_fields is
	// carried on every frame, so a stream could seal the content for a while and
	// then stop.
	if err := validateResponseSealedFieldsForFrame(ro.profile, frame, e2ee.SealedFields); err != nil {
		return nil, err
	}
	// And, on the frame that closes the response, refuse one that omits the
	// billable count §7.1 requires in cleartext. The client is the party with an
	// interest here: an enclave that drops `usage.output_images` is served for
	// free by a router that cannot tell the omission from a zero, so no
	// downstream component ever raises it.
	if e2ee.Final {
		if err := validateResponseCleartextFor(ro.profile, frame); err != nil {
			return nil, err
		}
	}
	ct, err := b64.DecodeString(e2ee.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bad ciphertext: %w", err)
	}
	aad, err := aadFromEnvelope(frame)
	if err != nil {
		return nil, err
	}
	pt, err := ro.opener.Open(ct, aad) // fail-closed on tamper / wrong order / wrong key
	if err != nil {
		return nil, err
	}

	var sealedObj map[string]json.RawMessage
	if err := json.Unmarshal(pt, &sealedObj); err != nil {
		return nil, fmt.Errorf("decrypted object is not a JSON object: %w", err)
	}
	if !sameKeys(sealedObj, e2ee.SealedFields) {
		return nil, fmt.Errorf("decrypted fields do not match sealed_fields")
	}

	out := make(Response, len(frame)+len(sealedObj))
	for k, v := range frame {
		if k == e2eeKey {
			continue
		}
		out[k] = v
	}
	for k, v := range sealedObj {
		// Defense in depth (H2): `out` is built with `_e2ee` excluded, so a
		// decrypted `_e2ee` would slip the collision check; forbid it outright.
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

// SealResponse seals a complete non-streaming chat response as a single final
// frame — shorthand for SealResponseFor(ProfileChat, …).
func SealResponse(clientEphPub crypto.PublicKey, resp Response, sealedFields []string, unboundFields ...string) (Response, error) {
	return SealResponseFor(ProfileChat, clientEphPub, resp, sealedFields, unboundFields...)
}

// SealResponseFor seals a complete non-streaming response as a single final
// frame, for the profile the request used. unboundFields are the cleartext
// fields excluded from the AAD (§5.2 / D5).
//
// Because the one frame is also the final frame, this is where the image
// profile's `usage.output_images` requirement (§7.1) bites: a non-streaming
// image response that omits the count is refused here rather than shipped.
func SealResponseFor(profile Profile, clientEphPub crypto.PublicKey, resp Response, sealedFields []string, unboundFields ...string) (Response, error) {
	rs, err := NewResponseSealerFor(profile, clientEphPub, unboundFields...)
	if err != nil {
		return nil, err
	}
	return rs.SealFrame(resp, sealedFields, true)
}

// OpenResponse opens a complete non-streaming (single-frame) chat response —
// shorthand for OpenResponseFor(ProfileChat, …).
func OpenResponse(clientEphPriv crypto.PrivateKey, resp Response) (Response, error) {
	return OpenResponseFor(ProfileChat, clientEphPriv, resp)
}

// OpenResponseFor opens a complete non-streaming (single-frame) response and
// checks it against the profile the request used (see NewResponseOpenerFor).
//
// The one frame of a non-streaming response IS the final frame by definition, so
// this requires `final` before opening anything. Without that the receive-side
// §7.1 check is defeated by the sender setting one bit: those obligations fall
// due on the final frame, and `final` is a value the sealer chooses. An enclave
// could ship `data` sealed with no `usage` and `final: false`, and a client
// calling this — the only shape §7.1 actually describes — would hand back a
// complete, correct response having verified none of it. A non-final frame here
// is not a lesser response; it is a stream fragment presented as a whole
// response, which is a truncation whether or not it was meant as one.
func OpenResponseFor(profile Profile, clientEphPriv crypto.PrivateKey, resp Response) (Response, error) {
	e2ee, err := resp.E2EE()
	if err != nil {
		return nil, err
	}
	if !e2ee.Final {
		return nil, fmt.Errorf("non-streaming response frame is not marked final: a single-frame response must be the final frame, and the checks that fall due on it would otherwise be skipped")
	}
	ro, err := NewResponseOpenerFor(profile, clientEphPriv, resp)
	if err != nil {
		return nil, err
	}
	return ro.OpenFrame(resp)
}

// E2EE decodes the `_e2ee` metadata on a response frame.
func (r Response) E2EE() (ResponseE2EE, error) {
	raw, ok := r[e2eeKey]
	if !ok {
		return ResponseE2EE{}, fmt.Errorf("frame missing %q", e2eeKey)
	}
	var e ResponseE2EE
	if err := json.Unmarshal(raw, &e); err != nil {
		return ResponseE2EE{}, fmt.Errorf("decode %q: %w", e2eeKey, err)
	}
	return e, nil
}

// FrameDebug is a redaction-safe structural summary of a response frame, for
// diagnosing an open (AEAD) failure. It carries field NAMES and byte lengths
// only — never plaintext, ciphertext bytes, or key material — so it is safe to
// write to an operator log even on the multi-tenant gateway.
//
// It exists because every distinct cause of a frame open failure surfaces as
// the same opaque "chacha20poly1305: message authentication failed": a
// first-frame key/enc/AAD mismatch, a dropped or reordered later frame, or an
// intermediary that mutated a cleartext field not listed in unbound_fields
// (so it stays bound in the AAD). The structure here tells them apart — chiefly
// whether the failure is on the first frame vs a later one, and which cleartext
// fields the frame actually carried (revealing a router-injected bound field).
type FrameDebug struct {
	Version       int      // _e2ee.v (first frame only; 0 elsewhere or if unreadable)
	HasEnc        bool     // _e2ee.enc present (a well-formed first frame carries it)
	Final         bool     // _e2ee.final
	SealedFields  []string // _e2ee.sealed_fields
	UnboundFields []string // _e2ee.unbound_fields (AAD-excluded, intermediary-mutable)
	CleartextKeys []string // top-level frame keys except _e2ee, sorted; a key here that the sealer did not emit points at an intermediary-injected bound field
	CiphertextLen int      // decoded ciphertext length in bytes; -1 if absent/undecodable
	E2EEErr       string   // why _e2ee could not be read, if it could not
}

// Debug returns a redaction-safe structural summary of the frame (see
// FrameDebug). It never returns an error: a frame whose _e2ee is missing or
// malformed still yields its cleartext key set, with E2EEErr explaining the gap.
func (r Response) Debug() FrameDebug {
	d := FrameDebug{CiphertextLen: -1}
	for k := range r {
		if k == e2eeKey {
			continue
		}
		d.CleartextKeys = append(d.CleartextKeys, k)
	}
	sort.Strings(d.CleartextKeys) // stable order so log lines are comparable
	e2ee, err := r.E2EE()
	if err != nil {
		d.E2EEErr = err.Error()
		return d
	}
	d.Version = e2ee.V
	d.HasEnc = e2ee.Enc != ""
	d.Final = e2ee.Final
	d.SealedFields = e2ee.SealedFields
	d.UnboundFields = e2ee.UnboundFields
	if ct, err := b64.DecodeString(e2ee.Ciphertext); err == nil {
		d.CiphertextLen = len(ct)
	}
	return d
}

func setResponseE2EE(r Response, e ResponseE2EE) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode %q: %w", e2eeKey, err)
	}
	r[e2eeKey] = raw
	return nil
}
