package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

var b64 = base64.RawURLEncoding

// mockBroker plays the provider enclave in-process: it holds the enc private key
// (which in production never leaves the TEE), opens sealed requests, runs a fake
// "model", and seals the response back to the client's ephemeral key. No
// network, no TEE — just enough to exercise the full envelope round trip.
type mockBroker struct {
	encPriv    crypto.PrivateKey
	signerAddr string // its own on-chain identity; requests must pin this
}

// openRequest opens the sealed request and returns the reconstructed OpenAI
// request plus the client's response ephemeral key (which the client placed in
// the sealed-and-bound _e2ee). It enforces the provider_id pin, the one policy
// check wire deliberately leaves to the broker.
func (b *mockBroker) openRequest(t *testing.T, env wire.Request) (wire.Request, crypto.PublicKey) {
	t.Helper()
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if e2ee.ProviderID != b.signerAddr {
		t.Fatalf("provider_id %q is not this broker %q", e2ee.ProviderID, b.signerAddr)
	}
	req, err := wire.OpenRequest(b.encPriv, env)
	if err != nil {
		t.Fatalf("broker OpenRequest: %v", err)
	}
	ephPub, err := b64.DecodeString(e2ee.ClientEphPub)
	if err != nil {
		t.Fatalf("bad client_eph_pub: %v", err)
	}
	return req, ephPub
}

// fakeChoices is the "model" output; it proves the broker actually saw the
// decrypted prompt by echoing part of it.
func fakeChoices(t *testing.T, req wire.Request) json.RawMessage {
	t.Helper()
	if _, ok := req["messages"]; !ok {
		t.Fatal("broker did not recover messages")
	}
	return json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"ack"},"finish_reason":"stop"}]`)
}

// sampleRequest is a chat request; messages carries the secret prompt.
func sampleRequest() wire.Request {
	return wire.Request{
		"model":       json.RawMessage(`"gpt-4o"`),
		"temperature": json.RawMessage(`0.7`),
		"messages":    json.RawMessage(`[{"role":"user","content":"the secret prompt"}]`),
		"tools":       json.RawMessage(`[{"type":"function","function":{"name":"calc"}}]`),
	}
}

var brokerSigner = "0x" + strings.Repeat("a", 40)

// The full non-streaming path: client seals a request; a router in the middle
// can route on cleartext but cannot read or tamper with the prompt; the broker
// opens it, "runs" the model, and seals the response; the client opens it.
func TestRoundTripNonStreaming(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enclave keygen: %v", err)
	}
	broker := &mockBroker{encPriv: encPriv, signerAddr: brokerSigner}

	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("client eph keygen: %v", err)
	}

	// --- client: seal the request ---
	env, err := wire.SealRequest(encPub, sampleRequest(), nil, brokerSigner, ephPub)
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}

	// --- router in the middle: reads model, never the prompt ---
	if _, ok := env["messages"]; ok {
		t.Fatal("router can see messages — prompt leaked")
	}
	if got := string(env["model"]); got != `"gpt-4o"` {
		t.Fatalf("router cannot read model for routing: %s", got)
	}
	wireBytes, _ := json.Marshal(env)
	if bytes.Contains(wireBytes, []byte("secret prompt")) {
		t.Fatal("prompt leaked into the transmitted request")
	}

	// --- broker: open, run the "model", seal the response ---
	req, clientEphPub := broker.openRequest(t, env)
	resp := wire.Response{
		"id":      json.RawMessage(`"chatcmpl-1"`),
		"model":   json.RawMessage(`"gpt-4o"`),
		"usage":   json.RawMessage(`{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}`),
		"choices": fakeChoices(t, req),
	}
	sealedResp, err := wire.SealResponse(clientEphPub, resp, nil)
	if err != nil {
		t.Fatalf("SealResponse: %v", err)
	}

	// --- router on the return path: reads usage for billing, not choices ---
	if _, ok := sealedResp["choices"]; ok {
		t.Fatal("router can see choices — completion leaked")
	}
	if _, ok := sealedResp["usage"]; !ok {
		t.Fatal("router cannot read usage for billing")
	}

	// --- client: open the response ---
	got, err := wire.OpenResponse(ephPriv, sealedResp)
	if err != nil {
		t.Fatalf("OpenResponse: %v", err)
	}
	if !bytes.Contains([]byte(got["choices"]), []byte(`"ack"`)) {
		t.Fatalf("client did not recover choices: %s", got["choices"])
	}
}

// The full streaming path: the broker emits several sealed frames under one
// context; the client opens them in order.
func TestRoundTripStreaming(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	broker := &mockBroker{encPriv: encPriv, signerAddr: brokerSigner}
	ephPriv, ephPub, _ := crypto.GenerateRecipientKey()

	env, err := wire.SealRequest(encPub, sampleRequest(), nil, brokerSigner, ephPub)
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	req, clientEphPub := broker.openRequest(t, env)
	if !bytes.Contains(req["messages"], []byte("the secret prompt")) {
		t.Fatalf("broker did not recover the prompt: %s", req["messages"])
	}

	// broker streams three chunks.
	deltas := []string{`{"content":"he"}`, `{"content":"ll"}`, `{"content":"o"}`}
	sealer, err := wire.NewResponseSealer(clientEphPub)
	if err != nil {
		t.Fatalf("NewResponseSealer: %v", err)
	}
	var frames []wire.Response
	for i, d := range deltas {
		frame := wire.Response{
			"model":   json.RawMessage(`"gpt-4o"`),
			"choices": json.RawMessage(`[{"index":0,"delta":` + d + `}]`),
		}
		final := i == len(deltas)-1
		s, err := sealer.SealFrame(frame, nil, final)
		if err != nil {
			t.Fatalf("SealFrame %d: %v", i, err)
		}
		frames = append(frames, s)
	}

	// client opens the stream in order and reassembles the content.
	opener, err := wire.NewResponseOpener(ephPriv, frames[0])
	if err != nil {
		t.Fatalf("NewResponseOpener: %v", err)
	}
	var content strings.Builder
	for i, f := range frames {
		got, err := opener.OpenFrame(f)
		if err != nil {
			t.Fatalf("OpenFrame %d: %v", i, err)
		}
		var choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		}
		if err := json.Unmarshal(got["choices"], &choices); err != nil {
			t.Fatalf("parse choices %d: %v", i, err)
		}
		content.WriteString(choices[0].Delta.Content)
	}
	if content.String() != "hello" {
		t.Fatalf("reassembled stream = %q, want %q", content.String(), "hello")
	}
}

// Streaming frames must be opened in the order they were sealed — the shared
// HPKE context's AEAD sequence increments per frame, so a reordered or dropped
// frame fails closed. This nails that property in the broker→client path.
func TestStreamingOutOfOrderFailsClosed(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	broker := &mockBroker{encPriv: encPriv, signerAddr: brokerSigner}
	ephPriv, ephPub, _ := crypto.GenerateRecipientKey()

	env, err := wire.SealRequest(encPub, sampleRequest(), nil, brokerSigner, ephPub)
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	_, clientEphPub := broker.openRequest(t, env)

	sealer, err := wire.NewResponseSealer(clientEphPub)
	if err != nil {
		t.Fatalf("NewResponseSealer: %v", err)
	}
	f0, err := sealer.SealFrame(wire.Response{"choices": json.RawMessage(`[{"index":0,"delta":{"content":"a"}}]`)}, nil, false)
	if err != nil {
		t.Fatalf("SealFrame 0: %v", err)
	}
	f1, err := sealer.SealFrame(wire.Response{"choices": json.RawMessage(`[{"index":0,"delta":{"content":"b"}}]`)}, nil, true)
	if err != nil {
		t.Fatalf("SealFrame 1: %v", err)
	}

	opener, err := wire.NewResponseOpener(ephPriv, f0)
	if err != nil {
		t.Fatalf("NewResponseOpener: %v", err)
	}
	// Opening the second frame before the first must fail.
	if _, err := opener.OpenFrame(f1); err == nil {
		t.Fatal("expected out-of-order OpenFrame to fail, got nil")
	}
}

// A router that tampers with a cleartext routing field (here, downgrading the
// model) is caught: the broker's OpenRequest fails closed.
func TestRouterTamperIsCaught(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	_, ephPub, _ := crypto.GenerateRecipientKey()

	env, err := wire.SealRequest(encPub, sampleRequest(), nil, brokerSigner, ephPub)
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	env["model"] = json.RawMessage(`"cheaper-model"`) // router tampers in transit

	if _, err := wire.OpenRequest(encPriv, env); err == nil {
		t.Fatal("broker accepted a tampered request; expected fail-closed")
	}
}
