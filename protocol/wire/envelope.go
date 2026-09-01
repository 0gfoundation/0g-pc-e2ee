// Package wire implements the v1 envelopes (SPEC §5–§7): field-level sealing of
// OpenAI-shaped requests and responses. The sensitive fields are removed from
// the JSON and sealed into an `_e2ee` object; every other top-level field stays
// cleartext (so the router can route/bill on it) but is bound as AEAD
// associated data, so an intermediary can read but not tamper.
//
//   - Request (§5–§6): client seals the payload fields to the provider enc key —
//     messages/tools for chat, prompt for image (see Profile).
//   - Response (§7): the enclave seals the generated content to the client's
//     ephemeral key — choices for chat, data for image — one frame for
//     non-streaming or a sequence of frames for streaming.
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
	// fieldResponseFormat is the cleartext image field pinned to "b64_json"
	// (SPEC §7.1) — see profileSpec.pinnedCleartext.
	fieldResponseFormat = "response_format"
	// clientEphPubLen is the byte length of an X25519 public key — the client's
	// response ephemeral key (SPEC §3 suite).
	clientEphPubLen = 32
)

// b64 is base64url without padding — the wire encoding for binary fields (§3).
var b64 = base64.RawURLEncoding

// Profile names a request family (SPEC §5.1). The envelope format, crypto suite
// and AAD rule are identical across profiles — a profile only fixes WHICH field
// carries the sensitive payload, so the "you cannot accidentally ship the
// payload in cleartext" check knows what to require.
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
)

// profileSpec fixes, per profile, the field that MUST be sealed, any CLEARTEXT
// field pinned to a specific value, and the v1 default sealed sets for a request
// and for the response it produces.
type profileSpec struct {
	required string   // the field a sealed envelope of this profile MUST cover
	request  []string // v1 default request sealed set (§5.1)
	response []string // v1 default response sealed set (§7)
	// pinnedCleartext maps a cleartext field to the ONLY value a sealed request
	// of this profile may carry. The field must be present — an absent one is
	// rejected, never defaulted — because a server-side default is exactly what
	// this guards against (§7.1). Empty for profiles with no such constraint.
	pinnedCleartext map[string]string
}

var profiles = map[Profile]profileSpec{
	ProfileChat: {
		required: fieldMessages,
		request:  []string{"messages", "tools"},
		response: []string{"choices"},
	},
	ProfileImage: {
		// "prompt" is the whole sensitive payload of an image request; "data" —
		// the generated images — is the whole sensitive payload of the response.
		// The image COUNT stays cleartext as `usage.output_images` so the router
		// can bill without decrypting (§7.1), the same trade-off chat makes for
		// `usage`.
		required: fieldPrompt,
		request:  []string{"prompt"},
		response: []string{"data"},
		// response_format must be an EXPLICIT "b64_json" (§7.1). "url" has the
		// enclave persist the images and serve them from a plain URL, outside
		// the sealed channel — a worse leak than the prompt, since it is the
		// generated content itself. Requiring the field rather than merely
		// banning "url" is the point: OpenAI's own default for the DALL·E
		// family IS "url", so an omitted field is a request to leak, spelled
		// as silence.
		pinnedCleartext: map[string]string{fieldResponseFormat: "b64_json"},
	},
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
// profile: non-empty, no duplicates, and the profile's payload field present
// ("messages" for chat, "prompt" for image). Leaving the payload cleartext
// defeats the purpose, so any sealed envelope MUST cover it.
//
// SealRequestFor calls this fail-closed per request, so a client cannot build an
// envelope that silently leaves the payload exposed — the only place a leak can
// actually be *prevented*. It is also exported so a caller can validate an
// operator-supplied sealed set up front (e.g. the sidecar's -seal-fields flag)
// and fail fast instead of erroring on every request.
func ValidateSealedFieldsFor(p Profile, fields []string) error {
	spec, err := p.spec()
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return fmt.Errorf("no sealed fields")
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
	// Sealing the payload is not enough on its own: a cleartext field can direct
	// the server to publish the RESULT outside the sealed channel (§7.1). Check
	// those before building anything.
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

// OpenRequest reverses SealRequest with the recipient private key (SPEC §6): it
// recomputes the AAD, opens the sealed object, checks the decrypted keys equal
// sealed_fields and do not collide with cleartext fields, and returns the
// reconstructed original request (cleartext ∪ decrypted). It does NOT enforce
// signer_addr == the enclave's own signer address; that policy check belongs to
// the caller (the broker), which knows its own identity — read it via E2EE().
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
