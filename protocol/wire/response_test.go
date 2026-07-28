package wire_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func mustResp(t *testing.T, s string) wire.Response {
	t.Helper()
	var r wire.Response
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	return r
}

// clientEph mimics the ephemeral keypair the client puts in the request; the
// enclave seals the response to the public half.
func clientEph(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	return priv, pub
}

const sampleResp = `{
  "id": "chatcmpl-123",
  "model": "gpt-4o",
  "created": 1700000000,
  "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
  "choices": [{"index":0,"message":{"role":"assistant","content":"the secret answer"},"finish_reason":"stop"}]
}`

func TestResponseRoundTripNonStreaming(t *testing.T) {
	priv, pub := clientEph(t)

	env, err := wire.SealResponse(pub, mustResp(t, sampleResp), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// choices sealed away; billing/routing fields stay cleartext.
	if _, ok := env["choices"]; ok {
		t.Fatal("choices left in cleartext")
	}
	if _, ok := env["usage"]; !ok {
		t.Fatal("usage should stay cleartext for the router")
	}
	raw, _ := json.Marshal(env)
	if bytes.Contains(raw, []byte("secret answer")) {
		t.Fatal("completion leaked into the transmitted frame")
	}
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if !e2ee.Final {
		t.Fatal("single-frame response must be final")
	}

	got, err := wire.OpenResponse(priv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, ok := got["_e2ee"]; ok {
		t.Fatal("_e2ee should not survive reconstruction")
	}
	if !sameJSONObject(t, wire.Request(got), mustReq(t, sampleResp)) {
		gb, _ := json.Marshal(got)
		t.Fatalf("reconstructed response differs:\n%s", gb)
	}
}

func TestResponseStreamingRoundTrip(t *testing.T) {
	priv, pub := clientEph(t)

	frames := []wire.Response{
		mustResp(t, `{"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant"}}]}`),
		mustResp(t, `{"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"hel"}}]}`),
		mustResp(t, `{"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"lo"}}]}`),
		mustResp(t, `{"usage":{"total_tokens":5},"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`),
	}

	sealer, err := wire.NewResponseSealer(pub)
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}
	var sealed []wire.Response
	for i, f := range frames {
		final := i == len(frames)-1
		s, err := sealer.SealFrame(f, nil, final)
		if err != nil {
			t.Fatalf("seal frame %d: %v", i, err)
		}
		sealed = append(sealed, s)
	}

	// enc rides on the first frame only.
	first, _ := sealed[0].E2EE()
	if first.Enc == "" || first.V != 1 {
		t.Fatal("first frame must carry v and enc")
	}
	for i := 1; i < len(sealed); i++ {
		e, _ := sealed[i].E2EE()
		if e.Enc != "" {
			t.Fatalf("frame %d should not repeat enc", i)
		}
	}

	opener, err := wire.NewResponseOpener(priv, sealed[0])
	if err != nil {
		t.Fatalf("new opener: %v", err)
	}
	for i, s := range sealed {
		got, err := opener.OpenFrame(s)
		if err != nil {
			t.Fatalf("open frame %d: %v", i, err)
		}
		if !sameJSONObject(t, wire.Request(got), wire.Request(frames[i])) {
			t.Fatalf("frame %d mismatch", i)
		}
	}
}

func TestResponseFramesMustOpenInOrder(t *testing.T) {
	priv, pub := clientEph(t)

	sealer, _ := wire.NewResponseSealer(pub)
	f0, _ := sealer.SealFrame(mustResp(t, `{"choices":[{"index":0,"delta":{"content":"a"}}]}`), nil, false)
	f1, _ := sealer.SealFrame(mustResp(t, `{"choices":[{"index":0,"delta":{"content":"b"}}]}`), nil, true)

	opener, err := wire.NewResponseOpener(priv, f0)
	if err != nil {
		t.Fatalf("new opener: %v", err)
	}
	// Opening the second frame first must fail (AEAD sequence mismatch).
	if _, err := opener.OpenFrame(f1); err == nil {
		t.Fatal("expected out-of-order Open to fail, got nil")
	}
}

func TestResponseTamperedCleartextFailsOpen(t *testing.T) {
	priv, pub := clientEph(t)
	env, err := wire.SealResponse(pub, mustResp(t, sampleResp), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// A router inflating usage for billing — usage is cleartext but AAD-bound.
	env["usage"] = json.RawMessage(`{"total_tokens":999999}`)
	if _, err := wire.OpenResponse(priv, env); err == nil {
		t.Fatal("expected Open to fail after cleartext tamper, got nil")
	}
}

func TestResponseFinalFlipFailsOpen(t *testing.T) {
	priv, pub := clientEph(t)
	env, err := wire.SealResponse(pub, mustResp(t, sampleResp), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// `final` lives in _e2ee and is bound in the AAD; flipping it (e.g. a router
	// trying to make a complete response look like it has more frames coming, or
	// vice versa) must break Open.
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if !e2ee.Final {
		t.Fatal("precondition: single-frame response should be final")
	}
	e2ee.Final = false
	env["_e2ee"], _ = json.Marshal(e2ee)
	if _, err := wire.OpenResponse(priv, env); err == nil {
		t.Fatal("expected Open to fail after flipping final, got nil")
	}
}

func TestResponseWrongClientKeyFailsOpen(t *testing.T) {
	_, pub := clientEph(t)
	wrongPriv, _ := clientEph(t)

	env, err := wire.SealResponse(pub, mustResp(t, sampleResp), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := wire.OpenResponse(wrongPriv, env); err == nil {
		t.Fatal("expected Open to fail with the wrong client key, got nil")
	}
}

func TestFrameDebugSummarizesSealedFrame(t *testing.T) {
	_, pub := clientEph(t)
	env, err := wire.SealResponse(pub, mustResp(t, sampleResp), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	d := env.Debug()

	// First (and only) frame carries v and enc and is final.
	if !d.HasEnc || d.Version != wire.Version || !d.Final {
		t.Fatalf("first frame summary wrong: %+v", d)
	}
	if !reflect.DeepEqual(d.SealedFields, []string{"choices"}) {
		t.Errorf("sealed_fields = %v, want [choices]", d.SealedFields)
	}
	if d.CiphertextLen <= 0 {
		t.Errorf("ct len = %d, want > 0", d.CiphertextLen)
	}
	// Cleartext keys are the frame's non-sealed fields, sorted, with choices (sealed
	// away) and _e2ee (the envelope) both excluded.
	wantKeys := []string{"created", "id", "model", "usage"}
	if !reflect.DeepEqual(d.CleartextKeys, wantKeys) {
		t.Errorf("cleartext_keys = %v, want %v", d.CleartextKeys, wantKeys)
	}

	// Redaction: the summary must never carry the sealed plaintext.
	blob, _ := json.Marshal(d)
	if bytes.Contains(blob, []byte("secret answer")) {
		t.Fatalf("FrameDebug leaked sealed plaintext: %s", blob)
	}
}

func TestFrameDebugFlagsLaterFrameAndBadMetadata(t *testing.T) {
	_, pub := clientEph(t)
	sealer, _ := wire.NewResponseSealer(pub)
	_, _ = sealer.SealFrame(mustResp(t, `{"choices":[{"index":0,"delta":{"content":"a"}}]}`), nil, false)
	f1, _ := sealer.SealFrame(mustResp(t, `{"choices":[{"index":0,"delta":{"content":"b"}}]}`), nil, true)

	// A non-first frame carries neither v nor enc — the signal that separates a
	// first-frame setup failure from a later-frame ordering failure.
	if d := f1.Debug(); d.HasEnc || d.Version != 0 {
		t.Errorf("later frame should carry no enc/v: %+v", d)
	}

	// A frame with no _e2ee at all still yields its cleartext keys, with the
	// reason the metadata was unreadable recorded rather than panicking.
	bare := mustResp(t, `{"id":"x","model":"gpt-4o"}`)
	d := bare.Debug()
	if d.E2EEErr == "" {
		t.Error("missing _e2ee should be reported in E2EEErr")
	}
	if !reflect.DeepEqual(d.CleartextKeys, []string{"id", "model"}) {
		t.Errorf("cleartext_keys = %v, want [id model]", d.CleartextKeys)
	}
}
