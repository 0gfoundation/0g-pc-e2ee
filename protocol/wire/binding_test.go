package wire

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// sealedResponseFrame seals one response frame to a fresh client ephemeral key
// and returns the frame plus the private key needed to open it.
func sealedResponseFrame(t *testing.T, unbound ...string) (Response, crypto.PrivateKey) {
	t.Helper()
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("gen eph key: %v", err)
	}
	rs, err := NewResponseSealer(ephPub, unbound...)
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}
	frame := Response{
		"model":   json.RawMessage(`"gpt-4o"`),
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"hi"}}]`),
	}
	sealed, err := rs.SealFrame(frame, nil, true)
	if err != nil {
		t.Fatalf("seal frame: %v", err)
	}
	return sealed, ephPriv
}

// TestFrameBinding_ReturnsAEADInputs proves FrameBinding returns exactly the aad
// and ciphertext the AEAD used: opening the returned ct under the returned aad
// must succeed. This is the property the §8 verifier relies on.
func TestFrameBinding_ReturnsAEADInputs(t *testing.T) {
	sealed, ephPriv := sealedResponseFrame(t)

	aad, ct, err := FrameBinding(sealed)
	if err != nil {
		t.Fatalf("FrameBinding: %v", err)
	}

	// ct must equal the base64url-decoded _e2ee.ciphertext.
	e2ee, err := sealed.E2EE()
	if err != nil {
		t.Fatalf("E2EE: %v", err)
	}
	wantCt, err := b64.DecodeString(e2ee.Ciphertext)
	if err != nil {
		t.Fatalf("decode ct: %v", err)
	}
	if !bytes.Equal(ct, wantCt) {
		t.Fatalf("ct mismatch: FrameBinding=%x want=%x", ct, wantCt)
	}

	// aad must be the exact associated data the AEAD authenticated: opening the
	// returned ct under the returned aad round-trips.
	enc, err := b64.DecodeString(e2ee.Enc)
	if err != nil {
		t.Fatalf("decode enc: %v", err)
	}
	opener, err := crypto.SetupReceiver(ephPriv, enc, []byte(RespInfo))
	if err != nil {
		t.Fatalf("setup receiver: %v", err)
	}
	if _, err := opener.Open(ct, aad); err != nil {
		t.Fatalf("open with FrameBinding outputs failed (aad is wrong): %v", err)
	}
}

// TestFrameBinding_UnboundExcluded confirms a router-injected unbound field does
// not change the binding: FrameBinding on the frame with and without the injected
// field yields the same aad (the field is outside the AAD by construction).
func TestFrameBinding_UnboundExcluded(t *testing.T) {
	sealed, _ := sealedResponseFrame(t, "x_0g_trace")

	aadBefore, _, err := FrameBinding(sealed)
	if err != nil {
		t.Fatalf("FrameBinding before: %v", err)
	}

	// Router folds in the unbound field after sealing.
	sealed["x_0g_trace"] = json.RawMessage(`{"cost":7}`)
	aadAfter, _, err := FrameBinding(sealed)
	if err != nil {
		t.Fatalf("FrameBinding after: %v", err)
	}
	if !bytes.Equal(aadBefore, aadAfter) {
		t.Fatalf("unbound injection changed the aad:\nbefore=%s\nafter=%s", aadBefore, aadAfter)
	}
}

func TestFrameBinding_Errors(t *testing.T) {
	if _, _, err := FrameBinding(map[string]json.RawMessage{"model": json.RawMessage(`"x"`)}); err == nil {
		t.Fatal("want error for envelope missing _e2ee")
	}
	noCt := map[string]json.RawMessage{"_e2ee": json.RawMessage(`{"sealed_fields":["choices"]}`)}
	if _, _, err := FrameBinding(noCt); err == nil {
		t.Fatal("want error for envelope with no ciphertext")
	}
}
