package crypto

import (
	"bytes"
	"testing"
)

// info string used across these tests (mirrors the request usage, SPEC §5.2).
var testInfo = []byte("0g-pc/v1/seal")

// The happy path: seal to a recipient's public key, open with its private key,
// get the exact plaintext back — and the ciphertext must not leak it.
func TestSealOpenRoundTrip(t *testing.T) {
	priv, pub, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	plaintext := []byte(`{"messages":[{"role":"user","content":"my secret prompt"}]}`)
	manifest := []byte(`{"model":"gpt-4o"}`) // cleartext, bound as AAD

	sealed, err := Seal(pub, plaintext, manifest, testInfo)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed.Ciphertext, []byte("secret prompt")) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	got, err := Open(priv, sealed, manifest, testInfo)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch:\n got  %q\n want %q", got, plaintext)
	}
}

// Flipping any ciphertext bit must be detected (AEAD integrity), not silently
// decrypted to garbage.
func TestOpenFailsOnTamperedCiphertext(t *testing.T) {
	priv, pub, _ := GenerateRecipientKey()
	sealed, err := Seal(pub, []byte("secret prompt"), []byte("model=x"), testInfo)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	sealed.Ciphertext[0] ^= 0xFF
	if _, err := Open(priv, sealed, []byte("model=x"), testInfo); err == nil {
		t.Fatal("expected Open to fail on tampered ciphertext, got nil")
	}
}

// The manifest-tamper story: a router reads the cleartext manifest to route, but
// must not be able to LIE about it. Change the AAD and Open fails, even though
// the sealed body is untouched.
func TestOpenFailsOnTamperedManifest(t *testing.T) {
	priv, pub, _ := GenerateRecipientKey()
	sealed, err := Seal(pub, []byte("secret prompt"), []byte(`{"model":"gpt-4o"}`), testInfo)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := Open(priv, sealed, []byte(`{"model":"cheap-model"}`), testInfo); err == nil {
		t.Fatal("expected Open to fail when the bound manifest is altered, got nil")
	}
}

// Only the intended recipient can open it: the wrong private key fails.
func TestOpenFailsWithWrongKey(t *testing.T) {
	_, pub, _ := GenerateRecipientKey()
	wrongPriv, _, _ := GenerateRecipientKey()

	sealed, err := Seal(pub, []byte("secret"), nil, testInfo)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(wrongPriv, sealed, nil, testInfo); err == nil {
		t.Fatal("expected Open to fail with the wrong recipient key, got nil")
	}
}

// A different info string must not open the message: info domain-separates uses
// (e.g. request "0g-pc/v1/seal" vs response "0g-pc/v1/resp").
func TestOpenFailsWithMismatchedInfo(t *testing.T) {
	priv, pub, _ := GenerateRecipientKey()
	sealed, err := Seal(pub, []byte("secret"), nil, []byte("0g-pc/v1/seal"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(priv, sealed, nil, []byte("0g-pc/v1/resp")); err == nil {
		t.Fatal("expected Open to fail with a mismatched info string, got nil")
	}
}

// The two-phase API: enc is available before Seal, so a caller can bind it into
// the AAD. Round-trips the same way as the one-shot form.
func TestSetupSenderReceiverRoundTrip(t *testing.T) {
	priv, pub, _ := GenerateRecipientKey()

	enc, sealer, err := SetupSender(pub, testInfo)
	if err != nil {
		t.Fatalf("setup sender: %v", err)
	}
	// enc is known here, before sealing — this is what the envelope binds as AAD.
	aad := append([]byte("enc="), enc...)
	ct, err := sealer.Seal([]byte("body"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	opener, err := SetupReceiver(priv, enc, testInfo)
	if err != nil {
		t.Fatalf("setup receiver: %v", err)
	}
	got, err := opener.Open(ct, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, []byte("body")) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

// mode_psk: the receiver opens a PSK context only with the sender's psk, and a
// base-mode sender — which is what anyone holding the public key can be —
// produces nothing a PSK receiver will open. That second half is the property
// the response binding relies on (SPEC §7.6).
func TestPSKModeAuthenticatesTheSender(t *testing.T) {
	priv, pub, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	psk := bytes.Repeat([]byte{7}, 32)
	pskID := []byte("test-psk")
	aad := []byte("aad")

	enc, s, err := SetupSenderPSK(pub, testInfo, psk, pskID)
	if err != nil {
		t.Fatalf("psk sender: %v", err)
	}
	ct, err := s.Seal([]byte("hello"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	o, err := SetupReceiverPSK(priv, enc, testInfo, psk, pskID)
	if err != nil {
		t.Fatalf("psk receiver: %v", err)
	}
	if pt, err := o.Open(ct, aad); err != nil || string(pt) != "hello" {
		t.Fatalf("open = %q, %v", pt, err)
	}

	// A different psk opens nothing.
	other := bytes.Repeat([]byte{8}, 32)
	o2, err := SetupReceiverPSK(priv, enc, testInfo, other, pskID)
	if err != nil {
		t.Fatalf("psk receiver: %v", err)
	}
	if _, err := o2.Open(ct, aad); err == nil {
		t.Fatal("a PSK context with the wrong psk opened the ciphertext")
	}

	// A base-mode sender (no psk) is not accepted by a PSK receiver.
	enc3, s3, err := SetupSender(pub, testInfo)
	if err != nil {
		t.Fatalf("base sender: %v", err)
	}
	ct3, err := s3.Seal([]byte("forged"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	o3, err := SetupReceiverPSK(priv, enc3, testInfo, psk, pskID)
	if err != nil {
		t.Fatalf("psk receiver: %v", err)
	}
	if _, err := o3.Open(ct3, aad); err == nil {
		t.Fatal("a PSK receiver opened a base-mode ciphertext")
	}
}

func TestPSKInputsAreChecked(t *testing.T) {
	_, pub, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, _, err := SetupSenderPSK(pub, testInfo, make([]byte, 31), []byte("id")); err == nil {
		t.Error("a 31-byte psk was accepted")
	}
	if _, _, err := SetupSenderPSK(pub, testInfo, make([]byte, 32), nil); err == nil {
		t.Error("an empty psk id was accepted")
	}
}
