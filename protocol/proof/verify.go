package proof

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// RecoverFunc recovers the 0x-prefixed Ethereum address that produced an EIP-191
// (personal_sign) signature over text. secp256k1/keccak are heavyweight and
// platform-specific, so the concrete implementation is injected by the client —
// protocol stays dependency-light and portable (mirrors attest's WithQuoteParser
// seam). sig is the raw 65-byte r‖s‖v signature.
type RecoverFunc func(text string, sig []byte) (addr string, err error)

// VerifyE2EE verifies a non-stream E2EE response signature end to end, fail-closed:
//  1. the signed text uses the non-stream E2EE scheme (unknown/other → reject),
//  2. its content-binding halves equal the reqH/respH recomputed over the on-wire
//     aad‖ciphertext of the envelopes the caller received (no decryption),
//  3. the recovered signer equals expectedSigner — the on-chain acknowledged
//     teeSignerAddress — and NEVER sig.SigningAddress.
//
// reqEnv is the sealed request envelope the client sent; respEnv is the sealed
// response frame it received.
func (sig ChatSignature) VerifyE2EE(reqEnv, respEnv map[string]json.RawMessage, expectedSigner string, recover RecoverFunc) error {
	want, err := SignedTextE2EE(reqEnv, respEnv)
	if err != nil {
		return err
	}
	return sig.verify(want, SchemeE2EECiphertext, expectedSigner, recover)
}

// VerifyE2EEStream verifies a streamed E2EE response signature. respFrames are
// the sealed frames the client received, in delivery order (final frame last).
func (sig ChatSignature) VerifyE2EEStream(reqEnv map[string]json.RawMessage, respFrames []map[string]json.RawMessage, expectedSigner string, recover RecoverFunc) error {
	want, err := SignedTextE2EEStream(reqEnv, respFrames)
	if err != nil {
		return err
	}
	return sig.verify(want, SchemeE2EECiphertextStream, expectedSigner, recover)
}

// verify compares the signature's text against the locally recomputed want,
// checks the scheme, then recovers and anchors the signer on expectedSigner. It
// takes want (already assembled by the caller) so the content-binding is
// recomputed exactly once, by the shared builders.
func (sig ChatSignature) verify(want, wantScheme, expectedSigner string, recover RecoverFunc) error {
	if recover == nil {
		return fmt.Errorf("proof: no recover function supplied")
	}
	if strings.TrimSpace(expectedSigner) == "" {
		return fmt.Errorf("proof: no expected on-chain signer (refusing to trust self-reported address)")
	}

	// Reject an unknown/mismatched scheme before anything else (SPEC §9).
	got, err := parseText(sig.Text)
	if err != nil {
		return err
	}
	if got.scheme != wantScheme {
		return fmt.Errorf("proof: unexpected scheme %q (want %q)", got.scheme, wantScheme)
	}

	// Content binding: the recomputed text (scheme + both hashes) must match the
	// signed text byte-for-byte. Comparing the assembled strings covers the scheme
	// and both hash halves in one shot; the parse above only sharpens the error.
	if sig.Text != want {
		return fmt.Errorf("proof: content-binding mismatch (signed text does not match received request/response)")
	}

	// Recover over the EXACT signed bytes and anchor on the on-chain identity.
	raw, err := decodeSignature(sig.Signature)
	if err != nil {
		return err
	}
	addr, err := recover(sig.Text, raw)
	if err != nil {
		return fmt.Errorf("proof: recover signer: %w", err)
	}
	if !addrEqual(addr, expectedSigner) {
		return fmt.Errorf("proof: recovered signer %s != on-chain acknowledged signer %s", addr, expectedSigner)
	}
	return nil
}

// decodeSignature parses a 0x-prefixed 65-byte (r‖s‖v) hex signature.
func decodeSignature(s string) ([]byte, error) {
	h := strings.TrimPrefix(strings.TrimSpace(s), "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("proof: signature not hex: %w", err)
	}
	if len(b) != 65 {
		return nil, fmt.Errorf("proof: signature want 65 bytes, got %d", len(b))
	}
	return b, nil
}

// addrEqual compares two 0x-hex Ethereum addresses case-insensitively.
func addrEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
