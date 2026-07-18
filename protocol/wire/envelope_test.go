package wire_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc/protocol/crypto"
	"github.com/0gfoundation/0g-pc/protocol/wire"
)

var b64 = base64.RawURLEncoding

// testProvider is a well-formed 0x + 40-hex signer address for tests.
var testProvider = "0x" + strings.Repeat("a", 40)

// validEph is a well-formed (length-correct) X25519 public key for tests.
var validEph = bytes.Repeat([]byte{1}, 32)

// a representative OpenAI-shaped request; messages + tools are sensitive.
const sampleReq = `{
  "model": "gpt-4o",
  "temperature": 0.7,
  "max_tokens": 1024,
  "stream": true,
  "messages": [{"role":"user","content":"my secret prompt"}],
  "tools": [{"type":"function","function":{"name":"lookup"}}]
}`

func mustReq(t *testing.T, s string) wire.Request {
	t.Helper()
	var r wire.Request
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatalf("parse request: %v", err)
	}
	return r
}

func sealSample(t *testing.T) (crypto.PrivateKey, wire.Request) {
	t.Helper()
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey() // stand-in for a client eph key
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	env, err := wire.SealRequest(pub, mustReq(t, sampleReq),
		[]string{"messages", "tools"}, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return priv, env
}

func TestSealRequestRemovesSensitiveFieldsAndDoesNotLeak(t *testing.T) {
	_, env := sealSample(t)

	if _, ok := env["messages"]; ok {
		t.Fatal("messages left in cleartext")
	}
	if _, ok := env["tools"]; ok {
		t.Fatal("tools left in cleartext")
	}
	if _, ok := env["_e2ee"]; !ok {
		t.Fatal("missing _e2ee object")
	}
	// The prompt must appear nowhere in the transmitted bytes (ciphertext is
	// base64 of encrypted data, so the plaintext string cannot show up).
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal env: %v", err)
	}
	if bytes.Contains(raw, []byte("secret prompt")) {
		t.Fatal("prompt leaked into the transmitted envelope")
	}

	// The router can read routing metadata without decrypting.
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if e2ee.ProviderID != testProvider {
		t.Fatalf("provider_id not readable: %q", e2ee.ProviderID)
	}
	if !reflect.DeepEqual(e2ee.SealedFields, []string{"messages", "tools"}) {
		t.Fatalf("sealed_fields = %v", e2ee.SealedFields)
	}
	// Cleartext routing fields survive.
	if got := string(env["model"]); got != `"gpt-4o"` {
		t.Fatalf("model = %s", got)
	}
}

func TestOpenRequestRoundTrip(t *testing.T) {
	priv, env := sealSample(t)

	got, err := wire.OpenRequest(priv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Reconstructed request must equal the original (semantically) and carry no _e2ee.
	if _, ok := got["_e2ee"]; ok {
		t.Fatal("_e2ee should not survive reconstruction")
	}
	if !sameJSONObject(t, got, mustReq(t, sampleReq)) {
		gb, _ := json.Marshal(got)
		t.Fatalf("reconstructed request differs from original:\n%s", gb)
	}
}

func TestTamperedCleartextFieldFailsOpen(t *testing.T) {
	priv, env := sealSample(t)

	// Router tries to downgrade the model — a cleartext field bound in the AAD.
	env["model"] = json.RawMessage(`"cheap-model"`)
	if _, err := wire.OpenRequest(priv, env); err == nil {
		t.Fatal("expected Open to fail after cleartext tamper, got nil")
	}
}

func TestTamperedE2EEMetadataFailsOpen(t *testing.T) {
	priv, env := sealSample(t)

	// Flip client_eph_pub (would redirect the response) — it is inside the AAD.
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	e2ee.ClientEphPub = b64.EncodeToString(bytes.Repeat([]byte{0xAA}, 32))
	env["_e2ee"], _ = json.Marshal(e2ee)

	if _, err := wire.OpenRequest(priv, env); err == nil {
		t.Fatal("expected Open to fail after _e2ee metadata tamper, got nil")
	}
}

func TestTamperedCiphertextFailsOpen(t *testing.T) {
	priv, env := sealSample(t)

	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	ct, err := b64.DecodeString(e2ee.Ciphertext)
	if err != nil {
		t.Fatalf("decode ct: %v", err)
	}
	ct[0] ^= 0xFF
	e2ee.Ciphertext = b64.EncodeToString(ct)
	env["_e2ee"], _ = json.Marshal(e2ee)

	if _, err := wire.OpenRequest(priv, env); err == nil {
		t.Fatal("expected Open to fail after ciphertext tamper, got nil")
	}
}

func TestWrongRecipientKeyFailsOpen(t *testing.T) {
	_, env := sealSample(t)
	wrongPriv, _, _ := crypto.GenerateRecipientKey()

	if _, err := wire.OpenRequest(wrongPriv, env); err == nil {
		t.Fatal("expected Open to fail with the wrong recipient key, got nil")
	}
}

func TestSealRequestRejectsMissingSealedField(t *testing.T) {
	_, pub, _ := crypto.GenerateRecipientKey()
	req := mustReq(t, `{"model":"gpt-4o","messages":[]}`)
	if _, err := wire.SealRequest(pub, req, []string{"messages", "tools"}, testProvider, validEph); err == nil {
		t.Fatal("expected error when a declared sealed field is absent, got nil")
	}
}

func TestSealRequestRejectsWithoutMessages(t *testing.T) {
	_, pub, _ := crypto.GenerateRecipientKey()
	req := mustReq(t, `{"model":"gpt-4o","messages":[],"tools":[]}`)
	// Sealing tools but leaving the prompt cleartext defeats the purpose.
	if _, err := wire.SealRequest(pub, req, []string{"tools"}, testProvider, validEph); err == nil {
		t.Fatal("expected error when messages is not sealed, got nil")
	}
}

func TestSealRequestRejectsBadEphKey(t *testing.T) {
	_, pub, _ := crypto.GenerateRecipientKey()
	req := mustReq(t, sampleReq)
	// nil and short keys must be rejected — a stored bad key silently breaks the
	// response path, which is exactly what we want to catch at seal time.
	for _, eph := range [][]byte{nil, bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{1}, 33)} {
		if _, err := wire.SealRequest(pub, req, nil, testProvider, eph); err == nil {
			t.Fatalf("expected error for client_eph_pub of length %d, got nil", len(eph))
		}
	}
}

func TestSealRequestRejectsBadProviderID(t *testing.T) {
	_, pub, _ := crypto.GenerateRecipientKey()
	req := mustReq(t, sampleReq)
	bad := []string{"", "0xabc", strings.Repeat("a", 42), "0x" + strings.Repeat("z", 40)}
	for _, p := range bad {
		if _, err := wire.SealRequest(pub, req, nil, p, validEph); err == nil {
			t.Fatalf("expected error for provider_id %q, got nil", p)
		}
	}
}

func TestSealRequestNilUsesDefaultSet(t *testing.T) {
	priv, pub, _ := crypto.GenerateRecipientKey()
	env, err := wire.SealRequest(pub, mustReq(t, sampleReq), nil, testProvider, validEph)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if !reflect.DeepEqual(e2ee.SealedFields, []string{"messages", "tools"}) {
		t.Fatalf("nil sealedFields should use the default set, got %v", e2ee.SealedFields)
	}
	if _, err := wire.OpenRequest(priv, env); err != nil {
		t.Fatalf("open after default-set seal: %v", err)
	}
}

// sameJSONObject compares two field maps by normalizing through JSON so number
// and formatting differences (e.g. JCS canonicalization) don't matter.
func sameJSONObject(t *testing.T, a, b wire.Request) bool {
	t.Helper()
	norm := func(r wire.Request) any {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return v
	}
	return reflect.DeepEqual(norm(a), norm(b))
}
