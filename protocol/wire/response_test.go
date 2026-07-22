package wire_test

import (
	"bytes"
	"encoding/json"
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
