package wire

import (
	"encoding/json"
	"fmt"
)

// FrameBinding returns the two on-wire byte artifacts the §8 ciphertext binding
// hashes for one envelope — a sealed request or a single response frame: the AAD
// (JCS of the envelope minus `_e2ee.ciphertext` minus `unbound_fields`, per
// §5.2) and the raw ciphertext bytes.
//
// Both the enclave (when it signs) and the client (when it verifies) derive
// these from the same envelope, so hashing them needs no plaintext and no
// further canonicalization of the sealed content (SPEC §8). This is the seam the
// response-signature verifier hashes; it deliberately does NOT decrypt.
//
// The parameter is the generic envelope type shared by Request and Response
// (both are `map[string]json.RawMessage`), so one helper covers both halves of
// the binding. It fails closed on a malformed or ciphertext-less envelope.
func FrameBinding(env map[string]json.RawMessage) (aad, ct []byte, err error) {
	aad, err = aadFromEnvelope(env)
	if err != nil {
		return nil, nil, err
	}
	rawE2EE, ok := env[e2eeKey]
	if !ok {
		return nil, nil, fmt.Errorf("envelope missing %q", e2eeKey)
	}
	var meta struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(rawE2EE, &meta); err != nil {
		return nil, nil, fmt.Errorf("decode %q for binding: %w", e2eeKey, err)
	}
	if meta.Ciphertext == "" {
		return nil, nil, fmt.Errorf("envelope %q carries no ciphertext to bind", e2eeKey)
	}
	ct, err = b64.DecodeString(meta.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ciphertext for binding: %w", err)
	}
	return aad, ct, nil
}
