package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Scheme tags prefix the signed text so a verifier selects exactly one binding
// rule and rejects anything else fail-closed (SPEC §8/§9). The tag is INSIDE the
// signed text — never a sibling JSON field — so an untrusted hop cannot relabel
// it. A breaking change to the algo/hash/canonicalization/binding bumps the
// version; adding a cleartext/unbound field does not (SPEC §9).
const (
	// SchemeE2EECiphertext binds a non-stream E2EE exchange to the on-wire
	// aad‖ciphertext of the sealed request and the single sealed response frame.
	SchemeE2EECiphertext = "zg-sig-v1/e2ee-ct"
	// SchemeE2EECiphertextStream binds a streamed E2EE exchange: the request as
	// above, the response as an ordered aggregate over its sealed frames.
	SchemeE2EECiphertextStream = "zg-sig-v1/e2ee-ct-stream"
	// SchemePlaintext binds a plaintext (non-E2EE) exchange over JCS(req)/JCS(resp).
	// Defined here for the contract's completeness; it is NOT verified in this
	// module (the plaintext-direct flow never traverses the E2EE client — see
	// 0g-pc-e2ee#48). Its verifier lives with the out-of-band auditor.
	SchemePlaintext = "zg-sig-v1/plain"
)

// ChatSignature is the TEE-signed proof the broker caches under a chatKey and
// serves at GET /v1/proxy/signature/{chatKey}. Field names match the broker JSON
// byte-for-byte (the broker↔client contract).
type ChatSignature struct {
	Text string `json:"text"` // "<scheme>:<reqHhex>:<respHhex>"; the exact bytes signed
	// Signature is the 0x-prefixed 65-byte ECDSA-secp256k1 signature over
	// EIP-191(personal_sign) of Text.
	Signature string `json:"signature"`
	// SigningAddress is the enclave's self-reported address. It is a HINT for
	// logging only — verification MUST anchor on the on-chain acknowledged
	// teeSignerAddress, never on this field (SPEC §8 step 4).
	SigningAddress string `json:"signing_address"`
	SigningAlgo    string `json:"signing_algo"`
}

// BindingHash is the per-artifact §8 binding: sha256( sha256(aad) ‖ sha256(ct) ).
// Both halves are fixed 32-byte digests, so the concatenation has unambiguous
// boundaries and needs no separator or length prefix (it is injective). This is
// the single definition of the convention; the broker and the client MUST both
// route through it (directly or via the text builders below) so the bytes cannot
// drift. Locked by KAT.
func BindingHash(aad, ct []byte) [32]byte {
	ha := sha256.Sum256(aad)
	hc := sha256.Sum256(ct)
	var buf [64]byte
	copy(buf[:32], ha[:])
	copy(buf[32:], hc[:])
	return sha256.Sum256(buf[:])
}

// frameBindingHash applies BindingHash to a sealed envelope's on-wire artifacts,
// reusing wire.FrameBinding so the AAD/JCS computation is shared code, not a
// reimplementation.
func frameBindingHash(env map[string]json.RawMessage) ([32]byte, error) {
	aad, ct, err := wire.FrameBinding(env)
	if err != nil {
		return [32]byte{}, err
	}
	return BindingHash(aad, ct), nil
}

// SignedTextE2EE returns the exact text signed (and verified) for a non-stream
// E2EE exchange: "<scheme>:<reqH>:<respH>". reqEnv is the sealed request
// envelope; respEnv is the single sealed response frame. This is the one place
// the non-stream binding is assembled — the broker imports it to SIGN, the
// client calls it to recompute, so the signed bytes cannot diverge.
func SignedTextE2EE(reqEnv, respEnv map[string]json.RawMessage) (string, error) {
	reqH, err := frameBindingHash(reqEnv)
	if err != nil {
		return "", fmt.Errorf("proof: request binding: %w", err)
	}
	respH, err := frameBindingHash(respEnv)
	if err != nil {
		return "", fmt.Errorf("proof: response binding: %w", err)
	}
	return formatText(SchemeE2EECiphertext, reqH, respH), nil
}

// SignedTextE2EEStream is the streaming variant. respFrames are the sealed
// response frames in send order (the final frame last); respH aggregates them as
// sha256( H(f_0) ‖ … ‖ H(f_{n-1}) ), which is order-, count- and
// truncation-sensitive.
func SignedTextE2EEStream(reqEnv map[string]json.RawMessage, respFrames []map[string]json.RawMessage) (string, error) {
	b, err := NewStreamBinder(reqEnv)
	if err != nil {
		return "", err
	}
	for i, f := range respFrames {
		if err := b.AddFrame(f); err != nil {
			return "", fmt.Errorf("proof: response frame %d: %w", i, err)
		}
	}
	return b.Text()
}

// StreamBinder accumulates the streaming response binding one frame at a time, so
// a caller (client receive loop or broker seal loop) can feed frames as they are
// produced rather than buffering the whole response. Not safe for concurrent use.
type StreamBinder struct {
	reqH [32]byte
	agg  []byte // concatenation of each frame's 32-byte BindingHash, in order
	n    int
}

// NewStreamBinder starts a streaming binder over the sealed request envelope.
func NewStreamBinder(reqEnv map[string]json.RawMessage) (*StreamBinder, error) {
	reqH, err := frameBindingHash(reqEnv)
	if err != nil {
		return nil, fmt.Errorf("proof: request binding: %w", err)
	}
	return &StreamBinder{reqH: reqH}, nil
}

// AddFrame folds one sealed response frame into the aggregate, in delivery order.
func (s *StreamBinder) AddFrame(frameEnv map[string]json.RawMessage) error {
	h, err := frameBindingHash(frameEnv)
	if err != nil {
		return err
	}
	s.agg = append(s.agg, h[:]...)
	s.n++
	return nil
}

// Text finalizes the aggregate and returns the signed text. Calling it with no
// frames added yields respH = sha256("") — a valid but empty binding; callers
// that require the §7 final frame enforce that separately.
func (s *StreamBinder) Text() (string, error) {
	respH := sha256.Sum256(s.agg)
	return formatText(SchemeE2EECiphertextStream, s.reqH, respH), nil
}

// formatText assembles "<scheme>:<reqHhex>:<respHhex>".
func formatText(scheme string, reqH, respH [32]byte) string {
	return scheme + ":" + hex.EncodeToString(reqH[:]) + ":" + hex.EncodeToString(respH[:])
}

// parsedText is a signed text split into its scheme and two 32-byte hashes.
type parsedText struct {
	scheme      string
	reqH, respH [32]byte
}

// parseText splits "<scheme>:<reqHhex>:<respHhex>" and validates both hex halves
// are 32 bytes. The scheme itself contains no ':' (only '/'), so a 3-way split is
// unambiguous. Unknown scheme is NOT judged here — the caller checks it against
// the scheme it expects.
func parseText(text string) (parsedText, error) {
	parts := strings.SplitN(text, ":", 3)
	if len(parts) != 3 {
		return parsedText{}, fmt.Errorf("proof: malformed signed text %q", text)
	}
	reqH, err := decodeHash(parts[1])
	if err != nil {
		return parsedText{}, fmt.Errorf("proof: request hash: %w", err)
	}
	respH, err := decodeHash(parts[2])
	if err != nil {
		return parsedText{}, fmt.Errorf("proof: response hash: %w", err)
	}
	return parsedText{scheme: parts[0], reqH: reqH, respH: respH}, nil
}

func decodeHash(h string) ([32]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return [32]byte{}, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}
