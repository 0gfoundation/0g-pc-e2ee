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
