package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

const testSigner = "0x9f3ad2c4B5e6789012345678901234567890abCD"

// stubRecover returns a fixed address regardless of input — enough to exercise
// the scheme/binding/signer-anchor logic without a real secp256k1 recover
// (that arrives in Phase 2).
func stubRecover(addr string) RecoverFunc {
	return func(_ string, _ []byte) (string, error) { return addr, nil }
}

func fakeSig(text string) ChatSignature {
	return ChatSignature{
		Text:           text,
		Signature:      "0x" + strings.Repeat("11", 65),
		SigningAddress: "0xdead000000000000000000000000000000000000",
		SigningAlgo:    "ecdsa",
	}
}

// --- fixtures --------------------------------------------------------------

func sealReq(t *testing.T, ephPub crypto.PublicKey) map[string]json.RawMessage {
	t.Helper()
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("gen enc key: %v", err)
	}
	req := wire.Request{"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`)}
	sealed, err := wire.SealRequest(encPub, req, []string{"messages"},
		"0x1111111111111111111111111111111111111111", ephPub)
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	return sealed
}

func sealFrames(t *testing.T, ephPub crypto.PublicKey, n int) []map[string]json.RawMessage {
	t.Helper()
	rs, err := wire.NewResponseSealer(ephPub)
	if err != nil {
		t.Fatalf("NewResponseSealer: %v", err)
	}
	out := make([]map[string]json.RawMessage, n)
	for i := 0; i < n; i++ {
		frame := wire.Response{
			"model":   json.RawMessage(`"gpt-4o"`),
			"choices": json.RawMessage(`[{"index":0,"delta":{"content":"x"}}]`),
		}
		sealed, err := rs.SealFrame(frame, nil, i == n-1)
		if err != nil {
			t.Fatalf("SealFrame %d: %v", i, err)
		}
		out[i] = sealed
	}
	return out
}

// --- binding / format ------------------------------------------------------

func TestBindingHash_ConcatOrder(t *testing.T) {
	aad, ct := []byte("the-aad"), []byte("the-ct")
	ha := sha256.Sum256(aad)
	hc := sha256.Sum256(ct)
	want := sha256.Sum256(append(append([]byte{}, ha[:]...), hc[:]...))
	if got := BindingHash(aad, ct); got != want {
		t.Fatalf("BindingHash = %x, want %x", got, want)
	}
	// Order matters: swapping halves must change the result.
	if BindingHash(aad, ct) == BindingHash(ct, aad) {
		t.Fatal("BindingHash(aad,ct) == BindingHash(ct,aad); concat not order-sensitive")
	}
}

func TestSignedTextE2EE_Format(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	resp := sealFrames(t, ephPub, 1)[0]

	text, err := SignedTextE2EE(req, resp)
	if err != nil {
		t.Fatalf("SignedTextE2EE: %v", err)
	}
	parts := strings.SplitN(text, ":", 3)
	if len(parts) != 3 || parts[0] != SchemeE2EECiphertext {
		t.Fatalf("bad text %q", text)
	}
	for _, h := range parts[1:] {
		if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
			t.Fatalf("hash %q not 32-byte hex", h)
		}
	}
}

func TestStreamAggregation_MatchesManual(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	frames := sealFrames(t, ephPub, 3)

	text, err := SignedTextE2EEStream(req, frames)
	if err != nil {
		t.Fatalf("SignedTextE2EEStream: %v", err)
	}

	// Manual: respH = sha256( H(f0) ‖ H(f1) ‖ H(f2) ).
	var agg []byte
	for _, f := range frames {
		h, err := FrameBindingHash(f)
		if err != nil {
			t.Fatal(err)
		}
		agg = append(agg, h[:]...)
	}
	respH := sha256.Sum256(agg)
	reqH, _ := FrameBindingHash(req)
	want := formatText(SchemeE2EECiphertextStream, reqH, respH)
	if text != want {
		t.Fatalf("stream text = %q, want %q", text, want)
	}
}

func TestStreamBinder_MatchesBatch(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	frames := sealFrames(t, ephPub, 3)

	b, err := NewStreamBinder(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if err := b.AddFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	incremental, err := b.Text()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := SignedTextE2EEStream(req, frames)
	if err != nil {
		t.Fatal(err)
	}
	if incremental != batch {
		t.Fatalf("incremental %q != batch %q", incremental, batch)
	}
}

// --- verify ----------------------------------------------------------------

func TestVerifyE2EE_OK(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	resp := sealFrames(t, ephPub, 1)[0]
	text, _ := SignedTextE2EE(req, resp)

	if err := fakeSig(text).VerifyE2EE(req, resp, testSigner, stubRecover(testSigner)); err != nil {
		t.Fatalf("VerifyE2EE OK path failed: %v", err)
	}
}

func TestVerifyE2EE_TamperedResponse(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	frames := sealFrames(t, ephPub, 1)
	text, _ := SignedTextE2EE(req, frames[0])

	// Verify against a DIFFERENT response frame → binding mismatch.
	other := sealFrames(t, ephPub, 1)[0]
	err := fakeSig(text).VerifyE2EE(req, other, testSigner, stubRecover(testSigner))
	if err == nil || !strings.Contains(err.Error(), "content-binding mismatch") {
		t.Fatalf("want content-binding mismatch, got %v", err)
	}
}

func TestVerifyE2EE_WrongScheme(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	frames := sealFrames(t, ephPub, 2)
	streamText, _ := SignedTextE2EEStream(req, frames)

	// A stream-scheme text handed to the non-stream verifier must be rejected.
	err := fakeSig(streamText).VerifyE2EE(req, frames[0], testSigner, stubRecover(testSigner))
	if err == nil || !strings.Contains(err.Error(), "unexpected scheme") {
		t.Fatalf("want unexpected scheme, got %v", err)
	}
}

func TestVerifyE2EE_SignerMismatch(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	resp := sealFrames(t, ephPub, 1)[0]
	text, _ := SignedTextE2EE(req, resp)

	other := "0x0000000000000000000000000000000000000001"
	err := fakeSig(text).VerifyE2EE(req, resp, testSigner, stubRecover(other))
	if err == nil || !strings.Contains(err.Error(), "!= on-chain acknowledged") {
		t.Fatalf("want signer mismatch, got %v", err)
	}
}

func TestVerifyE2EE_Guards(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	resp := sealFrames(t, ephPub, 1)[0]
	text, _ := SignedTextE2EE(req, resp)

	if err := fakeSig(text).VerifyE2EE(req, resp, "", stubRecover(testSigner)); err == nil {
		t.Fatal("want error for empty expected signer")
	}
	if err := fakeSig(text).VerifyE2EE(req, resp, testSigner, nil); err == nil {
		t.Fatal("want error for nil recover")
	}
	bad := fakeSig(text)
	bad.Signature = "0xzz"
	if err := bad.VerifyE2EE(req, resp, testSigner, stubRecover(testSigner)); err == nil {
		t.Fatal("want error for malformed signature")
	}
}

func TestVerifyE2EEStream_OK(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	frames := sealFrames(t, ephPub, 3)
	text, _ := SignedTextE2EEStream(req, frames)

	if err := fakeSig(text).VerifyE2EEStream(req, frames, testSigner, stubRecover(testSigner)); err != nil {
		t.Fatalf("VerifyE2EEStream OK path failed: %v", err)
	}

	// Dropping the final frame changes respH → mismatch.
	err := fakeSig(text).VerifyE2EEStream(req, frames[:2], testSigner, stubRecover(testSigner))
	if err == nil || !strings.Contains(err.Error(), "content-binding mismatch") {
		t.Fatalf("want mismatch on dropped frame, got %v", err)
	}
}

// --- from-hash entry points (broker flow: reqH computed early, envelope dropped) ---

func TestSignedTextE2EEFromHashes_MatchesEnvelope(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	resp := sealFrames(t, ephPub, 1)[0]

	// Broker: hash the request at unseal time, keep only the 32 bytes.
	reqH, err := FrameBindingHash(req)
	if err != nil {
		t.Fatal(err)
	}
	respH, err := FrameBindingHash(resp)
	if err != nil {
		t.Fatal(err)
	}
	fromHashes := SignedTextE2EEFromHashes(reqH, respH)

	envelope, err := SignedTextE2EE(req, resp)
	if err != nil {
		t.Fatal(err)
	}
	if fromHashes != envelope {
		t.Fatalf("from-hashes %q != envelope %q", fromHashes, envelope)
	}
}

func TestNewStreamBinderFromReqHash_MatchesEnvelope(t *testing.T) {
	_, ephPub, _ := crypto.GenerateRecipientKey()
	req := sealReq(t, ephPub)
	frames := sealFrames(t, ephPub, 3)

	reqH, err := FrameBindingHash(req)
	if err != nil {
		t.Fatal(err)
	}
	b := NewStreamBinderFromReqHash(reqH)
	for _, f := range frames {
		if err := b.AddFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	fromHash, err := b.Text()
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := SignedTextE2EEStream(req, frames)
	if err != nil {
		t.Fatal(err)
	}
	if fromHash != envelope {
		t.Fatalf("from-reqHash %q != envelope %q", fromHash, envelope)
	}
}
