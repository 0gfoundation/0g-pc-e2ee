package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc/client/core"
	"github.com/0gfoundation/0g-pc/protocol/crypto"
	"github.com/0gfoundation/0g-pc/protocol/wire"
)

// mockBroker is an httptest stand-in for the provider enclave: it opens the
// sealed request, checks the pin, "runs" a model, and seals the response back to
// the client's ephemeral key. It fails the test if the prompt ever arrives in
// cleartext.
func mockBroker(t *testing.T, encPriv crypto.PrivateKey, signer string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The sidecar must have sealed the prompt: it is NOT a cleartext field.
		if _, leaked := env["messages"]; leaked {
			t.Error("prompt reached the broker in cleartext")
			http.Error(w, "prompt not sealed", http.StatusBadRequest)
			return
		}
		e2ee, err := env.E2EE()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if e2ee.ProviderID != signer {
			http.Error(w, "wrong provider pin", http.StatusBadRequest)
			return
		}
		req, err := wire.OpenRequest(encPriv, env)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.Contains(req["messages"], []byte("the secret prompt")) {
			http.Error(w, "prompt not recovered in enclave", http.StatusInternalServerError)
			return
		}

		ephPub, err := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-mock"`),
			"model":   req["model"],
			"usage":   json.RawMessage(`{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"mock answer"},"finish_reason":"stop"}]`),
		}
		sealed, err := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(sealed)
	}))
}

// A real HTTP request through the sidecar to a mock broker and back: the user
// sends plain OpenAI JSON, the broker only ever sees the sealed prompt, and the
// user gets plaintext choices back. This is the e2e skeleton (real HTTP, real
// handlers, fake enclave + model).
func TestSidecarEndToEnd(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("provider keygen: %v", err)
	}
	signer := "0x" + strings.Repeat("a", 40)

	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	sidecar := httptest.NewServer(newHandler(client))
	defer sidecar.Close()

	// A tools-less chat request — the common case; the sidecar must not choke on
	// the missing "tools" field when applying the default sealed set.
	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"the secret prompt"}]}`
	httpResp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to sidecar: %v", err)
	}
	defer httpResp.Body.Close()
	respBody, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("sidecar returned %d: %s", httpResp.StatusCode, respBody)
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("sidecar response is not JSON: %v", err)
	}
	if !bytes.Contains(resp["choices"], []byte("mock answer")) {
		t.Fatalf("user did not get plaintext choices back: %s", respBody)
	}
	if _, ok := resp["_e2ee"]; ok {
		t.Fatal("sidecar returned a still-sealed response to the user")
	}
}

// A tampered cleartext field (a router downgrading the model) must make the
// whole call fail rather than silently reach the model.
func TestSidecarSurfacesTamper(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("b", 40)

	// A broker in front of which a "router" flips the model after sealing.
	inner := mockBroker(t, encPriv, signer)
	defer inner.Close()
	tamperer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		_ = json.Unmarshal(body, &env)
		env["model"] = json.RawMessage(`"cheaper-model"`) // tamper in transit
		b, _ := json.Marshal(env)
		resp, err := http.Post(inner.URL, "application/json", bytes.NewReader(b))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer tamperer.Close()

	client := core.New(core.Provider{URL: tamperer.URL, EncPubKey: encPub, SignerAddr: signer})
	sidecar := httptest.NewServer(newHandler(client))
	defer sidecar.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"the secret prompt"}]}`
	httpResp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to sidecar: %v", err)
	}
	defer httpResp.Body.Close()
	// The broker rejects the tampered request (400); the sidecar surfaces that
	// upstream status verbatim rather than flattening it.
	if httpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered request: got %d, want 400 (broker status passed through)", httpResp.StatusCode)
	}
}

// A non-2xx provider status (here 429) is surfaced verbatim, not flattened to
// 502, so OpenAI clients keep their retry/backoff behavior (429/5xx retry, 4xx
// fail fast).
func TestSidecarPassesUpstreamStatus(t *testing.T) {
	_, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	sidecar := httptest.NewServer(newHandler(client))
	defer sidecar.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	httpResp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to sidecar: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429 (upstream status passed through)", httpResp.StatusCode)
	}
}

// stream:true must be rejected loudly (501) rather than answered with a non-SSE
// body a streaming client cannot parse.
func TestSidecarRejectsStreaming(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("c", 40)
	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	sidecar := httptest.NewServer(newHandler(client))
	defer sidecar.Close()

	userReq := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	httpResp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to sidecar: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("stream:true: got %d, want 501", httpResp.StatusCode)
	}
}

// WithSealFields lets the operator seal an extra field (here "metadata"); it
// must reach the broker sealed, not in cleartext, and be recovered on open.
func TestSidecarSealsConfiguredExtraField(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, leaked := env["metadata"]; leaked {
			t.Error("metadata reached the broker in cleartext")
			http.Error(w, "metadata not sealed", http.StatusBadRequest)
			return
		}
		e2ee, _ := env.E2EE()
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		req, err := wire.OpenRequest(encPriv, env)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.Contains(req["metadata"], []byte("trace-42")) {
			http.Error(w, "metadata not recovered", http.StatusInternalServerError)
			return
		}
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-mock"`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	}))
	defer broker.Close()

	client := core.New(
		core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer},
		core.WithSealFields([]string{"messages", "metadata"}),
	)
	sidecar := httptest.NewServer(newHandler(client))
	defer sidecar.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"metadata":{"trace":"trace-42"}}`
	httpResp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to sidecar: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("got %d: %s", httpResp.StatusCode, b)
	}
}

// A malformed "stream" value (a string, not a bool) is a client error → 400,
// not silently treated as non-streaming.
func TestSidecarRejectsMalformedStream(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("e", 40)
	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	sidecar := httptest.NewServer(newHandler(client))
	defer sidecar.Close()

	userReq := `{"model":"gpt-4o","stream":"true","messages":[{"role":"user","content":"hi"}]}`
	httpResp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to sidecar: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed stream: got %d, want 400", httpResp.StatusCode)
	}
}

// A body over the limit is rejected with 413 rather than read unbounded.
func TestSidecarRejectsOversizedBody(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("f", 40)
	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	sidecar := httptest.NewServer(newHandler(client))
	defer sidecar.Close()

	huge := `{"model":"gpt-4o","messages":[{"role":"user","content":"` +
		strings.Repeat("a", (10<<20)+1) + `"}]}`
	httpResp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(huge))
	if err != nil {
		t.Fatalf("post to sidecar: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: got %d, want 413", httpResp.StatusCode)
	}
}

// A request with nothing to seal (no messages) is a client error → 400, not 502.
func TestSidecarBadRequestIs400(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("d", 40)
	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	sidecar := httptest.NewServer(newHandler(client))
	defer sidecar.Close()

	userReq := `{"model":"gpt-4o"}` // no messages
	httpResp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to sidecar: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("request with no messages: got %d, want 400", httpResp.StatusCode)
	}
}
