// Package wire implements the v1 envelopes (SPEC §5–§7): field-level sealing of
// OpenAI-shaped requests and responses. The sensitive fields are removed from
// the JSON and sealed into an `_e2ee` object; every other top-level field stays
// cleartext (so the router can route/bill on it) but is bound as AEAD
// associated data, so an intermediary can read but not tamper.
//
//   - Request (§5–§6): client seals messages/tools to the provider enc key.
//   - Response (§7): the enclave seals choices to the client's ephemeral key,
//     one frame for non-streaming or a sequence of frames for streaming.
//
// Contract: broker <-> client (byte-for-byte, per SPEC.md). All AAD is taken
// over JCS (RFC 8785) canonical JSON so Go/TS/Rust agree byte-for-byte.
package wire

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

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
	// fieldMessages is the sensitive field that MUST always be sealed.
	fieldMessages = "messages"
	// clientEphPubLen is the byte length of an X25519 public key — the client's
	// response ephemeral key (SPEC §3 suite).
	clientEphPubLen = 32
)

// b64 is base64url without padding — the wire encoding for binary fields (§3).
var b64 = base64.RawURLEncoding

// DefaultSealedFields is the v1 default set of request fields to seal (SPEC
// §5.1). It returns a fresh slice, so a caller may filter it to the fields
// actually present or append additional sensitive ones (e.g. "metadata",
// "user") without mutating the shared default. The default lives here in
// exactly one place; clients reference it rather than re-listing the names.
func DefaultSealedFields() []string {
	return []string{"messages", "tools"}
}

// ValidateSealedFields enforces the invariants on a sealed-field set: non-empty,
// no duplicates, and "messages" present. Leaving the prompt cleartext defeats
// the purpose, so any sealed envelope MUST cover "messages".
//
// SealRequest calls this fail-closed per request, so a client cannot build an
// envelope that silently leaves the prompt exposed — the only place a leak can
// actually be *prevented*. It is also exported so a caller can validate an
// operator-supplied sealed set up front (e.g. the sidecar's -seal-fields flag)
// and fail fast instead of erroring on every request.
func ValidateSealedFields(fields []string) error {
	if len(fields) == 0 {
		return fmt.Errorf("no sealed fields")
	}
	seen := make(map[string]struct{}, len(fields))
	hasMessages := false
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
		if f == fieldMessages {
			hasMessages = true
		}
	}
	if !hasMessages {
		return fmt.Errorf("sealed fields must include %q", fieldMessages)
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
	ProviderID   string   `json:"provider_id"`    // pinned provider (signer address, 0x…)
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

// SealRequest builds the §5 request envelope. It removes sealedFields from req,
// JCS-seals their values to encPub, and returns a new Request carrying the
// cleartext fields plus the `_e2ee` object.
//
//   - encPub:       the provider enc key (verified out of a quote by the caller)
//   - sealedFields: fields to seal; nil uses the v1 default (messages, tools).
//     "messages" is required and each field MUST be present in req.
//   - providerID:   the pinned provider's on-chain signer address ("0x…")
//   - clientEphPub: the client's response ephemeral X25519 public key (raw bytes)
//   - unboundFields: optional cleartext fields excluded from the AAD (§5.2), i.e.
//     ones an intermediary may add/modify. Empty (the default) binds everything.
func SealRequest(encPub crypto.PublicKey, req Request, sealedFields []string, providerID string, clientEphPub []byte, unboundFields ...string) (Request, error) {
	if sealedFields == nil {
		sealedFields = DefaultSealedFields()
	}
	if err := ValidateSealedFields(sealedFields); err != nil {
		return nil, err
	}
	if err := ValidateUnboundFields(unboundFields, sealedFields); err != nil {
		return nil, err
	}
	if !isProviderID(providerID) {
		return nil, fmt.Errorf("invalid provider_id %q (want 0x followed by 40 hex)", providerID)
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
		ProviderID:    providerID,
		ClientEphPub:  b64.EncodeToString(clientEphPub),
		Enc:           b64.EncodeToString(enc),
		SealedFields:  sealedFields,
		UnboundFields: unboundFields, // nil/empty → omitted (bind everything)
		// Ciphertext filled in after sealing; it is excluded from the AAD.
	}
	if err := env.setE2EE(e2ee); err != nil {
		return nil, err
	}

	// 4. aad = JCS(envelope without _e2ee.ciphertext).
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
// provider_id == the enclave's own signer address; that policy check belongs to
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
// `_e2ee.ciphertext` value removed (§5.2). Sender and receiver call this with
// the same logical envelope, so — JCS being canonical — they derive identical
// bytes without depending on field order or whitespace.
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

// isProviderID reports whether s is a 0x-prefixed 20-byte hex address — the
// on-chain signer address format (§4.2). Case-insensitive on the hex body; the
// checksum (EIP-55) is not verified here.
func isProviderID(s string) bool {
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
