package wire_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
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
	if e2ee.SignerAddr != testProvider {
		t.Fatalf("signer_addr not readable: %q", e2ee.SignerAddr)
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

func TestSealRequestRejectsBadSignerAddr(t *testing.T) {
	_, pub, _ := crypto.GenerateRecipientKey()
	req := mustReq(t, sampleReq)
	bad := []string{"", "0xabc", strings.Repeat("a", 42), "0x" + strings.Repeat("z", 40)}
	for _, p := range bad {
		if _, err := wire.SealRequest(pub, req, nil, p, validEph); err == nil {
			t.Fatalf("expected error for signer_addr %q, got nil", p)
		}
	}
}

// A nil sealed set is the profile default NARROWED to what the request carries.
// Both halves matter: the default must not be shrunk for a request that has
// every field, and it must not demand a field the request does not have — the
// chat default contains two optional payload fields, so an unfiltered default
// would refuse the ordinary request below.
func TestSealRequestNilUsesDefaultSetFilteredByPresence(t *testing.T) {
	priv, pub, _ := crypto.GenerateRecipientKey()

	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{
			name: "every default field present",
			body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],` +
				`"tools":[{"type":"function","function":{"name":"calc"}}],` +
				`"tool_choice":{"type":"function","function":{"name":"calc"}}}`,
			want: []string{"messages", "tools", "tool_choice"},
		},
		{
			// The ordinary tool-calling request: no tool_choice.
			name: "an optional default field is absent",
			body: sampleReq,
			want: []string{"messages", "tools"},
		},
		{
			// The ordinary chat request: neither optional field.
			name: "no optional default field at all",
			body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
			want: []string{"messages"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, err := wire.SealRequest(pub, mustReq(t, tc.body), nil, testProvider, validEph)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			e2ee, err := env.E2EE()
			if err != nil {
				t.Fatalf("read _e2ee: %v", err)
			}
			if !reflect.DeepEqual(e2ee.SealedFields, tc.want) {
				t.Fatalf("nil sealedFields = %v, want %v", e2ee.SealedFields, tc.want)
			}
			if _, err := wire.OpenRequest(priv, env); err != nil {
				t.Fatalf("open after default-set seal: %v", err)
			}
		})
	}
}

// Filtering must not weaken the mandatory payload rule: a request with no
// `messages` at all still fails closed, because the filtered set cannot contain
// what the request does not have.
func TestNilSealedSetStillFailsClosedWithoutThePayloadField(t *testing.T) {
	_, pub, _ := crypto.GenerateRecipientKey()
	_, err := wire.SealRequest(pub, mustReq(t, `{"model":"gpt-4o","temperature":0.5}`),
		nil, testProvider, validEph)
	if err == nil {
		t.Fatal("a request carrying no payload field must not seal, filtered default or not")
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

// ValidateUnboundFieldsFor must reject a set that unbinds a field the profile
// pins in cleartext, and must agree with what SealRequestFor enforces per
// request — the whole point of exposing it is that a caller can run the request
// path's check once at startup instead of discovering it on every request.
func TestValidateUnboundFieldsForMatchesWhatSealEnforces(t *testing.T) {
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}

	for _, tc := range []struct {
		name    string
		profile wire.Profile
		unbound []string
		// sealed overrides the profile default, for a fixture that does not carry
		// every field that default names (the Anthropic sample has no "tools").
		sealed  []string
		wantErr bool
	}{
		{
			// The pair that motivated this: valid for chat, unsealable for image.
			name:    "response_format unbound is fine for chat",
			profile: wire.ProfileChat,
			unbound: []string{"model", "response_format"},
		},
		{
			name:    "response_format unbound is refused for image (pinned cleartext)",
			profile: wire.ProfileImage,
			unbound: []string{"model", "response_format"},
			wantErr: true,
		},
		{
			name:    "a field cannot be both sealed and unbound",
			profile: wire.ProfileImage,
			unbound: []string{"prompt"},
			wantErr: true,
		},
		{
			name:    "an ordinary unbound field is fine",
			profile: wire.ProfileImage,
			unbound: []string{"model", "user"},
		},
		{
			// The Anthropic profile pins no cleartext field, so response_format is
			// ordinary there. Its row is here so the table covers every profile that
			// exists: the check follows the PROFILE, and a new profile that pins
			// something must not quietly inherit another's answer.
			name:    "anthropic pins nothing, so response_format is ordinary there",
			profile: wire.ProfileAnthropic,
			unbound: []string{"model", "response_format"},
			sealed:  []string{"messages", "system"},
		},
		{
			name:    "anthropic still refuses unbinding its own sealed system prompt",
			profile: wire.ProfileAnthropic,
			unbound: []string{"system"},
			sealed:  []string{"messages", "system"},
			wantErr: true,
		},
		{
			name:    "an empty set binds everything",
			profile: wire.ProfileImage,
		},
		{
			name:    "an unknown profile fails closed",
			profile: wire.Profile("speech-to-text"),
			unbound: []string{"model"},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed := tc.sealed
			if sealed == nil {
				sealed = wire.DefaultSealedFieldsFor(tc.profile)
			}
			gotErr := wire.ValidateUnboundFieldsFor(tc.profile, tc.unbound, sealed) != nil
			if gotErr != tc.wantErr {
				t.Fatalf("ValidateUnboundFieldsFor error = %v, want %v", gotErr, tc.wantErr)
			}
			// The startup check is only worth something if it agrees with the
			// per-request one. Seal the same combination and require both verdicts to
			// match: a startup check that is more lenient is the 100%-failure bug this
			// function exists to prevent, and one that is stricter refuses a
			// configuration that would have worked.
			body := sampleImageReq
			switch tc.profile {
			case wire.ProfileChat:
				body = sampleReq
			case wire.ProfileAnthropic:
				body = sampleAnthropicReq
			}
			// BOTH sides get the SAME resolved set — that is the invariant. Passing
			// tc.sealed (nil) to the seal instead would hand the two checks
			// different sets and make this table blind to the divergence it exists
			// to catch; see TestNilNarrowingMakesStartupValidationTheWorstCase for
			// what nil does differently and why that is deliberate.
			//
			// The body is widened to carry every field in that set, because an
			// explicit set demands each of its fields be present. That is a
			// property of explicit sets, not a workaround: the default now contains
			// optional payload fields, and a fixture missing one would make this
			// row assert "field not present" instead of the unbound verdict.
			reqBody := mustReq(t, body)
			for _, f := range sealed {
				if _, ok := reqBody[f]; !ok {
					reqBody[f] = json.RawMessage(`"x"`)
				}
			}
			_, sealErr := wire.SealRequestFor(tc.profile, pub, reqBody,
				sealed, testProvider, ephPub, tc.unbound...)
			if got := sealErr != nil; got != tc.wantErr {
				t.Errorf("SealRequestFor error = %v (%v), but startup validation said %v",
					got, sealErr, tc.wantErr)
			}
		})
	}
}
