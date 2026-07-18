package crypto

import (
	"bytes"
	"testing"
)

// The happy path: seal to a recipient's public key, open with its private key,
// get the exact plaintext back — and the ciphertext must not leak it.
func TestSealOpenRoundTrip(t *testing.T) {
	priv, pub, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	plaintext := []byte(`{"messages":[{"role":"user","content":"my secret prompt"}]}`)
	manifest := []byte(`{"model":"gpt-4o"}`) // cleartext, bound as AAD

	sealed, err := Seal(pub, plaintext, manifest)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed.Ciphertext, []byte("secret prompt")) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	got, err := Open(priv, sealed, manifest)
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
	sealed, err := Seal(pub, []byte("secret prompt"), []byte("model=x"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	sealed.Ciphertext[0] ^= 0xFF
	if _, err := Open(priv, sealed, []byte("model=x")); err == nil {
		t.Fatal("expected Open to fail on tampered ciphertext, got nil")
	}
}

// The manifest-tamper story: a router reads the cleartext manifest to route, but
// must not be able to LIE about it. Change the AAD and Open fails, even though
// the sealed body is untouched.
func TestOpenFailsOnTamperedManifest(t *testing.T) {
	priv, pub, _ := GenerateRecipientKey()
	sealed, err := Seal(pub, []byte("secret prompt"), []byte(`{"model":"gpt-4o"}`))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := Open(priv, sealed, []byte(`{"model":"cheap-model"}`)); err == nil {
		t.Fatal("expected Open to fail when the bound manifest is altered, got nil")
	}
}

// Only the intended recipient can open it: the wrong private key fails.
func TestOpenFailsWithWrongKey(t *testing.T) {
	_, pub, _ := GenerateRecipientKey()
	wrongPriv, _, _ := GenerateRecipientKey()

	sealed, err := Seal(pub, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(wrongPriv, sealed, nil); err == nil {
		t.Fatal("expected Open to fail with the wrong recipient key, got nil")
	}
}
