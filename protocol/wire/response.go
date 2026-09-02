package wire

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"

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
func DefaultResponseSealedFieldsFor(p Profile) []string {
	s, err := p.spec()
	if err != nil || s.responseFrames != nil {
		return []string{}
	}
	return slices.Clone(s.response)
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
		return slices.Clone(spec.response), nil
	}
	_, shape, err := spec.responseFrames.shapeOf(frame)
	if err != nil {
		return nil, fmt.Errorf("%s-profile: %w", p, err)
	}
	return shape.sealedFieldsFor(frame), nil
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
	// The profile's own must-stay-bound fields. The floor above is name-based on
	// TOP-LEVEL fields, so it cannot reach a value that must be authenticated one
	// level down — Anthropic's billable input count at `message.usage.input_tokens`
	// is the case, and unbinding `message` would let a router restate it with the
	// client's Open and the §8 verification both still passing.
	for _, f := range spec.mustStayBoundResponse {
		if slices.Contains(unbound, f) {
			return fmt.Errorf("%q must stay bound for the %s profile: it carries a value the router bills on (or a value another check reads), one level down where the profile-independent rule cannot see it, so an unbound one could be rewritten in transit and still verify", f, p)
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
// Sealing a superset is still fine — only spec.responseRequired is mandatory, so
// any superset satisfies it. That distinction is why the check can run at seal
// time at all.
func validateResponseSealedFieldsFor(p Profile, fields []string) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	if spec.responseFrames != nil {
		// A frame-typed profile has no profile-wide answer, and guessing one here
		// would be the wrong kind of wrong: spec.responseRequired is "" for such a
		// profile, so the check below would demand that every frame seal a field
		// named "" and reject the entire stream with a nonsense message. Refuse the
		// entry point instead — the frame-aware one is the only correct caller.
		return fmt.Errorf("%s-profile response frames are typed: validate against the frame, not the profile alone", p)
	}
	if err := validateResponseSealedFields(fields); err != nil {
		return err
	}
	// Only the profile's CONTENT field is mandatory — not every member of its
	// default set. A caller may legitimately seal a superset, and a future
	// profile whose default covers something besides the content must not make
	// that extra field's absence a hard failure.
	if !slices.Contains(fields, spec.responseRequired) {
		return fmt.Errorf("%s-profile response sealed fields must include %q", p, spec.responseRequired)
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
	rule := spec.responseFrames
	if rule == nil {
		return validateResponseSealedFieldsFor(p, fields)
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
	if len(required) == 0 {
		// Not merely unnecessary: `message` on a message_start holds the input
		// token count the router bills on, so a sealer permitted to seal "extra"
		// on a sequencing frame could make the response unbillable.
		if len(fields) != 0 {
			return fmt.Errorf("%s-profile %q frame carries no sensitive payload and must seal nothing, got %v", p, kind, fields)
		}
	}
	for _, f := range required {
		if !slices.Contains(fields, f) {
			return fmt.Errorf("%s-profile %q frame must seal %q", p, kind, f)
		}
	}
	if err := validateNoCleartextContent(p, kind, *rule, frame, fields); err != nil {
		return err
	}
	return validateNestedEmpty(p, kind, shape, frame)
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

// validateNestedEmpty enforces a shape's nestedMustBeEmpty arrays — today only
// message_start's `message.content`, which Anthropic's own spec fixes to [].
// See frameShape.nestedMustBeEmpty for why a promise from the schema is checked
// rather than assumed.
//
// An absent field or absent key passes: this says "not content here", not "this
// must exist". A present non-array is rejected, because a non-array where the
// schema says array is not something to reason about further.
func validateNestedEmpty(p Profile, kind string, shape frameShape, frame Response) error {
	for _, n := range shape.nestedMustBeEmpty {
		raw, ok := frame[n.field]
		if !ok {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return fmt.Errorf("%s-profile %q frame field %q must be a JSON object: %w", p, kind, n.field, err)
		}
		v, ok := obj[n.key]
		if !ok {
			continue
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(v, &arr); err != nil {
			return fmt.Errorf("%s-profile %q frame %s must be a JSON array: %w", p, kind, n, err)
		}
		if len(arr) > 0 {
			return fmt.Errorf("%s-profile %q frame carries %d element(s) in cleartext %s: this shape does not seal it, so content there would be in the clear — an enclave with content to send MUST use a shape that seals it", p, kind, len(arr), n)
		}
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
	for _, req := range spec.requiredResponseCleartext {
		raw, ok := frame[req.field]
		if !ok {
			return fmt.Errorf("sealed %s response must carry cleartext %s: the sealed content cannot be billed on, and an absent count is indistinguishable from zero", p, req)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return fmt.Errorf("sealed %s response field %q must be a JSON object carrying %s: %w", p, req.field, req, err)
		}
		v, ok := obj[req.key]
		if !ok {
			return fmt.Errorf("sealed %s response must carry cleartext %s: the sealed content cannot be billed on, and an absent count is indistinguishable from zero", p, req)
		}
		// A POINTER, and an integer one. Decoding JSON `null` into a bare numeric
		// leaves the variable untouched and returns no error, so `null` read as a
		// perfectly good 0 — the one value §7.1 spells out as legitimate, which is
		// why it slipped past a check whose whole job is telling a real count from
		// the absence of one. A pointer is nil for `null` and only for `null`.
		//
		// int64 rather than float64 so this is exactly as strict as the router's
		// own `*int` parse. The protocol package must not accept a count its
		// consumer will reject: that would let a conforming enclave seal a response
		// (2.5 images, 1e3) the router then refuses to bill, turning a spec
		// question into a 502 nobody can act on.
		var n *int64
		if err := json.Unmarshal(v, &n); err != nil {
			return fmt.Errorf("sealed %s response %s must be a whole number: %w", p, req, err)
		}
		if n == nil {
			return fmt.Errorf("sealed %s response %s is null: a count must be a whole number, and null is the absence of one, not a zero", p, req)
		}
		if *n < 0 {
			return fmt.Errorf("sealed %s response %s must not be negative, got %d", p, req, *n)
		}
	}
	return nil
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
