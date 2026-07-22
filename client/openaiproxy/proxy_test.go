package openaiproxy_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
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
		// The proxy must have sealed the prompt: it is NOT a cleartext field.
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

// A real HTTP request through the proxy to a mock broker and back: the user
// sends plain OpenAI JSON, the broker only ever sees the sealed prompt, and the
// user gets plaintext choices back. This is the e2e skeleton (real HTTP, real
// handlers, fake enclave + model).
func TestProxyEndToEnd(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("provider keygen: %v", err)
	}
	signer := "0x" + strings.Repeat("a", 40)

	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	// A tools-less chat request — the common case; the proxy must not choke on
	// the missing "tools" field when applying the default sealed set.
	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"the secret prompt"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	respBody, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("proxy returned %d: %s", httpResp.StatusCode, respBody)
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatalf("proxy response is not JSON: %v", err)
	}
	if !bytes.Contains(resp["choices"], []byte("mock answer")) {
		t.Fatalf("user did not get plaintext choices back: %s", respBody)
	}
	if _, ok := resp["_e2ee"]; ok {
		t.Fatal("proxy returned a still-sealed response to the user")
	}
}

// A tampered cleartext field (a router downgrading the model) must make the
// whole call fail rather than silently reach the model.
func TestProxySurfacesTamper(t *testing.T) {
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
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"the secret prompt"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	// The broker rejects the tampered request (400); the proxy surfaces that
	// upstream status verbatim rather than flattening it.
	if httpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered request: got %d, want 400 (broker status passed through)", httpResp.StatusCode)
	}
}

// A non-2xx provider status (here 429) is surfaced verbatim, not flattened to
// 502, so OpenAI clients keep their retry/backoff behavior (429/5xx retry, 4xx
// fail fast).
func TestProxyPassesUpstreamStatus(t *testing.T) {
	_, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429 (upstream status passed through)", httpResp.StatusCode)
	}
}

// mockStreamingBroker opens the sealed request and streams sealed response
// frames back as SSE, symmetric with the real broker's streaming path.
func mockStreamingBroker(t *testing.T, encPriv crypto.PrivateKey, signer string, deltas []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The broker reads "stream" from the cleartext envelope to know to stream.
		if s := env["stream"]; string(s) != "true" {
			http.Error(w, "expected stream:true in cleartext", http.StatusBadRequest)
			return
		}
		e2ee, _ := env.E2EE()
		if _, err := wire.OpenRequest(encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		sealer, err := wire.NewResponseSealer(crypto.PublicKey(ephPub))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i, d := range deltas {
			frame := wire.Response{"choices": json.RawMessage(`[{"index":0,"delta":` + d + `}]`)}
			sealed, err := sealer.SealFrame(frame, nil, i == len(deltas)-1)
			if err != nil {
				return
			}
			b, _ := json.Marshal(sealed)
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
}

// A streaming request flows end to end: the proxy emits plaintext SSE frames
// the user reassembles, terminated by [DONE], and the prompt never leaks.
func TestProxyStreaming(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("c", 40)
	broker := mockStreamingBroker(t, encPriv, signer, []string{`{"content":"he"}`, `{"content":"ll"}`, `{"content":"o"}`})
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"the secret prompt"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("stream: got %d", httpResp.StatusCode)
	}
	if ct := httpResp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	raw, _ := io.ReadAll(httpResp.Body)
	if bytes.Contains(raw, []byte("secret prompt")) {
		t.Fatal("prompt leaked into the response stream")
	}

	var content string
	sawDone := false
	for _, line := range strings.Split(string(raw), "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		if payload == "[DONE]" {
			sawDone = true
			continue
		}
		var frame struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			t.Fatalf("bad SSE frame %q: %v", payload, err)
		}
		if len(frame.Choices) > 0 {
			content += frame.Choices[0].Delta.Content
		}
	}
	if content != "hello" {
		t.Fatalf("reassembled stream = %q, want %q", content, "hello")
	}
	if !sawDone {
		t.Fatal("stream did not end with [DONE]")
	}
}

// WithSealFields lets the operator seal an extra field (here "metadata"); it
// must reach the broker sealed, not in cleartext, and be recovered on open.
func TestProxySealsConfiguredExtraField(t *testing.T) {
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
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"metadata":{"trace":"trace-42"}}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("got %d: %s", httpResp.StatusCode, b)
	}
}

// A stream that ends without a final frame (provider crash / dropped connection)
// must be surfaced as an error, not silently completed with [DONE]. The
// mid-stream error event must itself be valid JSON.
func TestProxyStreamingTruncated(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("c", 40)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		e2ee, _ := env.E2EE()
		if _, err := wire.OpenRequest(encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		sealer, _ := wire.NewResponseSealer(crypto.PublicKey(ephPub))
		frame := wire.Response{"choices": json.RawMessage(`[{"index":0,"delta":{"content":"par"}}]`)}
		sealed, _ := sealer.SealFrame(frame, nil, false) // NOT final
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		b, _ := json.Marshal(sealed)
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
		// Return without a final frame or [DONE] — a truncated stream.
	}))
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	raw, _ := io.ReadAll(httpResp.Body)

	if strings.Contains(string(raw), "[DONE]") {
		t.Fatal("a truncated stream must not be completed with [DONE]")
	}
	sawError := false
	for _, line := range strings.Split(string(raw), "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok || !strings.Contains(payload, "error") {
			continue
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(payload), &v); err != nil {
			t.Fatalf("error event is not valid JSON: %q", payload)
		}
		sawError = true
	}
	if !sawError {
		t.Fatal("truncated stream did not surface an error event")
	}
}

// A streaming request that hits an upstream non-2xx gets that status verbatim
// (a normal error response, not SSE), since it fails before any frame is sent.
func TestProxyStreamingUpstreamStatus(t *testing.T) {
	_, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("c", 40)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429 (upstream status passed through)", httpResp.StatusCode)
	}
}

// A provider that returns a non-SSE 200 for a stream request (ignored
// stream:true) fails loud (502) rather than yielding a silent empty stream.
func TestProxyStreamingNonSSEUpstream(t *testing.T) {
	_, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("c", 40)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"not":"a stream"}`))
	}))
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got %d, want 502 (non-SSE upstream)", httpResp.StatusCode)
	}
}

// A malformed "stream" value (a string, not a bool) is a client error → 400,
// not silently treated as non-streaming.
func TestProxyRejectsMalformedStream(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("e", 40)
	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","stream":"true","messages":[{"role":"user","content":"hi"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed stream: got %d, want 400", httpResp.StatusCode)
	}
}

// A body over the limit is rejected with 413 rather than read unbounded.
func TestProxyRejectsOversizedBody(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("f", 40)
	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	huge := `{"model":"gpt-4o","messages":[{"role":"user","content":"` +
		strings.Repeat("a", (10<<20)+1) + `"}]}`
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(huge))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: got %d, want 413", httpResp.StatusCode)
	}
}

// The caller's Authorization credential is forwarded verbatim to the provider
// on both the buffered and streaming paths, and no header is sent when the
// caller presents none.
func TestProxyForwardsCredential(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)

	const wantAuth = "Bearer 0g-secret-key"

	// A broker that records the Authorization header it received, then answers
	// like the plain mock broker (buffered or SSE, per stream:true).
	var gotAuth string
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		e2ee, _ := env.E2EE()
		req, err := wire.OpenRequest(encPriv, env)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)

		if string(env["stream"]) == "true" {
			sealer, _ := wire.NewResponseSealer(crypto.PublicKey(ephPub))
			frame := wire.Response{"choices": json.RawMessage(`[{"index":0,"delta":{"content":"hi"}}]`)}
			sealed, _ := sealer.SealFrame(frame, nil, true)
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			b, _ := json.Marshal(sealed)
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(b)
			_, _ = w.Write([]byte("\n\ndata: [DONE]\n\n"))
			flusher.Flush()
			return
		}
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-mock"`),
			"model":   req["model"],
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	}))
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	post := func(t *testing.T, auth, body string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post to proxy: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("got %d: %s", resp.StatusCode, b)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	t.Run("buffered", func(t *testing.T) {
		gotAuth = ""
		post(t, wantAuth, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
		if gotAuth != wantAuth {
			t.Fatalf("provider saw Authorization %q, want %q", gotAuth, wantAuth)
		}
	})

	t.Run("streaming", func(t *testing.T) {
		gotAuth = ""
		post(t, wantAuth, `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
		if gotAuth != wantAuth {
			t.Fatalf("provider saw Authorization %q, want %q", gotAuth, wantAuth)
		}
	})

	t.Run("no credential", func(t *testing.T) {
		gotAuth = "sentinel"
		post(t, "", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
		if gotAuth != "" {
			t.Fatalf("provider saw Authorization %q, want none forwarded", gotAuth)
		}
	})
}

// The X-0G-* routing directives are forwarded to the provider; any other
// inbound header (a cookie, an app-custom header) is dropped, not leaked to the
// router.
func TestProxyForwardsRoutingHeaders(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)

	var got http.Header
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		_ = json.Unmarshal(body, &env)
		e2ee, _ := env.E2EE()
		if _, err := wire.OpenRequest(encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-mock"`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	}))
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-0G-Provider-Address", "0x"+strings.Repeat("b", 40))
	req.Header.Set("X-0G-Provider-Sort", "latency")
	req.Header.Set("Cookie", "session=leak-me")    // must NOT reach the router
	req.Header.Set("X-App-Trace", "internal-only") // must NOT reach the router
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d: %s", resp.StatusCode, b)
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	// HTTP header names are case-insensitive; http.Header.Get canonicalizes, so
	// these match regardless of the wire casing.
	if v := got.Get("X-0G-Provider-Address"); v != "0x"+strings.Repeat("b", 40) {
		t.Errorf("X-0G-Provider-Address = %q, want it forwarded", v)
	}
	if v := got.Get("X-0G-Provider-Sort"); v != "latency" {
		t.Errorf("X-0G-Provider-Sort = %q, want %q", v, "latency")
	}
	if v := got.Get("Cookie"); v != "" {
		t.Errorf("Cookie leaked to provider: %q", v)
	}
	if v := got.Get("X-App-Trace"); v != "" {
		t.Errorf("non-routing header X-App-Trace leaked to provider: %q", v)
	}
}

// A request with nothing to seal (no messages) is a client error → 400, not 502.
func TestProxyBadRequestIs400(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("d", 40)
	broker := mockBroker(t, encPriv, signer)
	defer broker.Close()

	client := core.New(core.Provider{URL: broker.URL, EncPubKey: encPub, SignerAddr: signer})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o"}` // no messages
	httpResp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("request with no messages: got %d, want 400", httpResp.StatusCode)
	}
}
