package proof

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Golden known-answer vectors that pin the §8 signed-text FORMAT byte-for-byte:
// the BindingHash convention (sha256(sha256(aad)‖sha256(ct))), the FrameBinding
// AAD derivation (JCS minus ciphertext minus unbound_fields), the scheme tags,
// the hex encoding, and the streaming aggregation. The broker imports this same
// package to sign, so a change here that shifts any byte would silently break
// verification — this test makes such a change fail loudly instead. If a format
// change is intentional, it MUST bump the scheme version (SPEC §9) and these
// vectors are regenerated deliberately.
//
// The fixtures are hand-crafted sealed envelopes (fixed cleartext + fixed
// base64url ciphertext); no HPKE is involved, so the vectors are deterministic
// and need no keys.
const (
	katReqEnv  = `{"model":"gpt-4o","_e2ee":{"v":1,"kem_id":"X25519","key_id":"AAAAAAAAAAA","client_eph_pub":"Y2xpZW50ZXBo","enc":"ZW5jYXBz","sealed_fields":["messages"],"ciphertext":"AAECAwQF"}}`
	katRespEnv = `{"model":"gpt-4o","usage":{"total_tokens":3},"_e2ee":{"v":1,"enc":"cmVzcGVuYw","sealed_fields":["choices"],"unbound_fields":["model","x_0g_trace"],"final":true,"ciphertext":"BgcICQoL"}}`
	katFrame0  = `{"model":"gpt-4o","_e2ee":{"v":1,"enc":"cmVzcGVuYw","sealed_fields":["choices"],"unbound_fields":["model","x_0g_trace"],"final":false,"ciphertext":"DA0ODxAR"}}`
	katFrame1  = `{"model":"gpt-4o","_e2ee":{"sealed_fields":["choices"],"unbound_fields":["model","x_0g_trace"],"final":true,"ciphertext":"EhMUFRYX"}}`

	katBindingHash = "cd267304498951f9045bd85577a28b1c15f1a1c287987fdcedd81a62e8f507fc"
	katReqH        = "7142bf93edca74323dd450689f4e087fea152d0b811ed5c89ad3c7668f349b8e"
	katRespH       = "b45f993cafa582df20c1ebb03ce421cccd00f54aa2664ac6658a98f26ec55ff7"
	katNonStream   = "zg-sig-v1/e2ee-ct:" + katReqH + ":" + katRespH
	katStream      = "zg-sig-v1/e2ee-ct-stream:" + katReqH + ":4f41983a49ff197ec60de80a892ba9322f8e41051b4813a9edd817ac7ed8ea85"
)

func katEnv(t *testing.T, s string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return m
}

func TestKAT_BindingHash(t *testing.T) {
	got := BindingHash([]byte("kat-aad"), []byte("kat-ct"))
	if hex.EncodeToString(got[:]) != katBindingHash {
		t.Fatalf("BindingHash format drift:\n got  %x\n want %s", got, katBindingHash)
	}
}

func TestKAT_FrameBindingHash(t *testing.T) {
	reqH, err := FrameBindingHash(katEnv(t, katReqEnv))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(reqH[:]) != katReqH {
		t.Fatalf("request FrameBindingHash drift:\n got  %x\n want %s", reqH, katReqH)
	}
	respH, err := FrameBindingHash(katEnv(t, katRespEnv))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(respH[:]) != katRespH {
		t.Fatalf("response FrameBindingHash drift:\n got  %x\n want %s", respH, katRespH)
	}
}

func TestKAT_SignedTextE2EE(t *testing.T) {
	got, err := SignedTextE2EE(katEnv(t, katReqEnv), katEnv(t, katRespEnv))
	if err != nil {
		t.Fatal(err)
	}
	if got != katNonStream {
		t.Fatalf("non-stream signed-text drift:\n got  %s\n want %s", got, katNonStream)
	}
}

func TestKAT_SignedTextE2EEStream(t *testing.T) {
	got, err := SignedTextE2EEStream(katEnv(t, katReqEnv),
		[]map[string]json.RawMessage{katEnv(t, katFrame0), katEnv(t, katFrame1)})
	if err != nil {
		t.Fatal(err)
	}
	if got != katStream {
		t.Fatalf("stream signed-text drift:\n got  %s\n want %s", got, katStream)
	}
}
