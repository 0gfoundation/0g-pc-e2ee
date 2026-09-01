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
// Returning nil would instead select the nil default below and silently seal
// "choices" for a profile that does not exist.
//
// The enclave passes this explicitly per service type; it is exported so the
// broker names the field in one place rather than re-listing it.
func DefaultResponseSealedFieldsFor(p Profile) []string {
	s, err := p.spec()
	if err != nil {
		return []string{}
	}
	return slices.Clone(s.response)
}

// defaultResponseSealedFields is the v1 default set of response fields to seal
// (SPEC §7) when a caller passes nil: the chat profile's generated content.
func defaultResponseSealedFields() []string { return DefaultResponseSealedFieldsFor(ProfileChat) }

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

// ValidateResponseUnboundFields rejects an unbound set that would strip the
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
// Not profile-parameterized, unlike ValidateResponseSealedFieldsFor: WHAT a
// profile seals differs, but which fields must stay authenticated does not, and
// a per-profile signature would imply a latitude no profile actually has.
func ValidateResponseUnboundFields(unbound []string) error {
	for _, f := range unbound {
		if slices.Contains(mustStayBoundInResponse, f) {
			return fmt.Errorf("%q must stay bound: an unbound field is outside the seal AAD and the §8 binding, so an intermediary could rewrite it undetected", f)
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

// ValidateResponseSealedFieldsFor checks a response sealed set against a
// profile: the shared invariants above, plus that it actually covers the
// profile's generated content ("choices" for chat, "data" for image) rather than
// sealing something incidental and shipping the content in the clear.
//
// It is the response-side counterpart of ValidateSealedFieldsFor. SealFrame
// applies only the profile-independent invariants, since a caller may legitimately
// seal a superset; an enclave that knows which endpoint it serves SHOULD call
// this to check its own configuration fail-closed.
func ValidateResponseSealedFieldsFor(p Profile, fields []string) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	if err := validateResponseSealedFields(fields); err != nil {
		return err
	}
	for _, required := range spec.response {
		if !slices.Contains(fields, required) {
			return fmt.Errorf("%s-profile response sealed fields must include %q", p, required)
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
}

// NewResponseSealer sets up response sealing to the client's ephemeral public
// key (carried in the request's _e2ee.client_eph_pub). unboundFields are the
// cleartext frame fields to exclude from the AAD (§5.2 / D5) — the same set is
// applied to every frame; empty binds everything. They are validated against
// each frame's sealed set in SealFrame.
func NewResponseSealer(clientEphPub crypto.PublicKey, unboundFields ...string) (*ResponseSealer, error) {
	// Before any key material: an unbound set that frees a field the signature
	// must cover would produce frames that verify no matter what an intermediary
	// does to them.
	if err := ValidateResponseUnboundFields(unboundFields); err != nil {
		return nil, err
	}
	enc, s, err := crypto.SetupSender(clientEphPub, []byte(RespInfo))
	if err != nil {
		return nil, err
	}
	return &ResponseSealer{sealer: s, enc: b64.EncodeToString(enc), first: true, unbound: unboundFields}, nil
}

// SealFrame seals one frame: it removes sealedFields (nil → the v1 default,
// "choices") from frame, seals their values, and returns the frame carrying
// `_e2ee`. final marks the last frame.
func (rs *ResponseSealer) SealFrame(frame Response, sealedFields []string, final bool) (Response, error) {
	if sealedFields == nil {
		sealedFields = defaultResponseSealedFields()
	}
	if err := validateResponseSealedFields(sealedFields); err != nil {
		return nil, err
	}
	if err := ValidateUnboundFields(rs.unbound, sealedFields); err != nil {
		return nil, err
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
	opener *crypto.Opener
}

// NewResponseOpener builds the receive context from the first frame (which
// carries enc) and the client's ephemeral private key.
func NewResponseOpener(clientEphPriv crypto.PrivateKey, firstFrame Response) (*ResponseOpener, error) {
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
	return &ResponseOpener{opener: o}, nil
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
	if err := ValidateResponseUnboundFields(e2ee.UnboundFields); err != nil {
		return nil, err
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

// SealResponse seals a complete non-streaming response as a single final frame.
// unboundFields are the cleartext fields excluded from the AAD (§5.2 / D5).
func SealResponse(clientEphPub crypto.PublicKey, resp Response, sealedFields []string, unboundFields ...string) (Response, error) {
	rs, err := NewResponseSealer(clientEphPub, unboundFields...)
	if err != nil {
		return nil, err
	}
	return rs.SealFrame(resp, sealedFields, true)
}

// OpenResponse opens a complete non-streaming (single-frame) response.
func OpenResponse(clientEphPriv crypto.PrivateKey, resp Response) (Response, error) {
	ro, err := NewResponseOpener(clientEphPriv, resp)
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
