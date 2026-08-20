package route

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

const (
	// testSigner is the broker's signer_address (envelope signer_addr / response
	// signer); testProviderAddr is the router's provider address (routing pin).
	// They are deliberately different to catch conflating the two.
	testSigner       = "0xd45b4301940B297F76d6e622c1CeA2AE660617d4"
	testProviderAddr = "0xC0FFEE0000000000000000000000000000000001"
)

// mockBroker serves the provider's control-plane e2ee pubkey API only. The
// data-plane chat request goes through the router (mockRouter), not here. It
// holds the keypair — encPub is published here, encPriv is lent to the router
// mock so it can open the sealed chat it "forwards". Counts pubkey hits so
// caching can be asserted.
type mockBroker struct {
	srv          *httptest.Server
	encPub       crypto.PublicKey
	encPriv      crypto.PrivateKey
	pubkeyHits   int32
	pubkeyStatus int    // override pubkey status; 0 = 200
	pubkeyRaw    string // if set, written verbatim instead of the JSON reply
	// Direct-mode data plane (POST /v1/proxy/chat/completions): the broker's own
	// chat endpoint under its "/v1/proxy" service prefix. Populated so direct-mode
	// tests can assert the sealed request landed on the right path with no router
	// pin. chatHits counts hits; lastChatPin records the X-0G-Provider-Address the
	// request carried (must be empty in direct mode).
	chatHits    int32
	lastChatPin string
}

func newMockBroker(t *testing.T) *mockBroker {
	t.Helper()
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}
	b := &mockBroker{encPub: encPub, encPriv: encPriv}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/e2ee/pubkey", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&b.pubkeyHits, 1)
		if b.pubkeyStatus != 0 {
			http.Error(w, "boom", b.pubkeyStatus)
			return
		}
		if b.pubkeyRaw != "" {
			_, _ = w.Write([]byte(b.pubkeyRaw))
			return
		}
		_ = json.NewEncoder(w).Encode(pubkeyResponse{
			V:             wire.Version,
			KEMID:         wire.KEMID,
			EncPub:        base64.RawURLEncoding.EncodeToString(encPub),
			KeyID:         "8RpY-WKSX_U",
			SignerAddress: testSigner,
		})
	})
	// Direct-mode data plane: the broker's own chat endpoint under "/v1/proxy"
	// (what the router would otherwise forward to). Opens the seal with encPriv and
	// seals a canned answer back — the direct client POSTs straight here, so a wrong
	// derived path (e.g. the router's /v1/chat/completions) would simply 404.
	mux.HandleFunc("POST /v1/proxy/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&b.chatHits, 1)
		b.lastChatPin = r.Header.Get("X-0G-Provider-Address")
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
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
		if _, err := wire.OpenRequest(b.encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-direct"`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"direct answer"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	})
	b.srv = httptest.NewServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

// mockRouter serves the route-preview API and the chat-completions data plane —
// the sealed request goes here (centralized auth), and the router "forwards" to
// the pinned provider, which the mock stands in for by opening the seal with the
// broker's encPriv. It records what the client sent so tests can assert the
// prompt never leaked and the pin/credential/headers were forwarded.
type mockRouter struct {
	srv             *httptest.Server
	lastPreview     map[string]json.RawMessage
	lastAuth        string
	lastHeaders     http.Header
	lastChatHeaders http.Header
	lastChatModel   string            // cleartext "model" the data-plane request carried
	status          int               // override preview response status; 0 = 200
	previewHits     int32             // preview attempts served (retry assertions)
	previewFailN    int32             // fail the first N preview attempts with previewFailStatus
	previewFailCode int               // status for previewFailN attempts (0 = 503)
	noProviders     bool              // preview returns no providers
	previewAddress  string            // head provider's address in preview (default testProviderAddr)
	extra           []previewProvider // extra candidates appended after the head
	failPin         string            // data plane fails for this X-0G-Provider-Address pin
	failStatus      int               // status returned for failPin (0 = 503)
	badBodyPin      string            // data plane returns 200 with an unopenable body for this pin
	truncBodyPin    string            // data plane returns 200 then truncates the body mid-read for this pin
}

func newMockRouter(t *testing.T, broker *mockBroker) *mockRouter {
	t.Helper()
	m := &mockRouter{previewAddress: testProviderAddr}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		hit := atomic.AddInt32(&m.previewHits, 1)
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &m.lastPreview)
		m.lastAuth = r.Header.Get("Authorization")
		m.lastHeaders = r.Header.Clone()
		if m.status != 0 {
			http.Error(w, "boom", m.status)
			return
		}
		// Fail the first previewFailN attempts, so a test can assert the client
		// retried its way past a transient router failure (and that each attempt
		// carried the full request again).
		if hit <= m.previewFailN {
			code := m.previewFailCode
			if code == 0 {
				code = http.StatusServiceUnavailable
			}
			http.Error(w, "transient router failure", code)
			return
		}
		providers := []previewProvider{{
			Address:     m.previewAddress,
			CanonicalID: "canon-1",
			Endpoint:    broker.srv.URL,
			ModelID:     "gpt-4o@v1",
		}}
		providers = append(providers, m.extra...)
		if m.noProviders {
			providers = nil
		}
		_ = json.NewEncoder(w).Encode(previewResponse{
			Object:      "routing.preview",
			ServiceType: "chatbot",
			Providers:   providers,
		})
	})

	// Data plane: the sealed request is POSTed here (to the router), which auths
	// and forwards to the pinned provider — the mock opens it with the broker's
	// key and seals a canned answer back.
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		m.lastChatHeaders = r.Header.Clone()
		pin := r.Header.Get("X-0G-Provider-Address")
		// Simulate a provider failure at the data plane: on a retryable status the
		// client should re-seal to the next candidate; on a 4xx it should fail fast.
		if m.failPin != "" && pin == m.failPin {
			status := m.failStatus
			if status == 0 {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, "provider failure", status)
			return
		}
		// Simulate a 200 whose sealed body cannot be opened: the client should fall
		// back (nothing was delivered to the caller yet).
		if m.badBodyPin != "" && pin == m.badBodyPin {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"not":"a sealed response"}`))
			return
		}
		// Simulate a 200 whose body drops mid-read: promise more bytes than we send,
		// then return so the connection closes — the client's read fails with an
		// unexpected EOF and should fall back.
		if m.truncBodyPin != "" && pin == m.truncBodyPin {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "4096")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"partial":`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, leaked := env["messages"]; leaked {
			t.Error("prompt reached the router in cleartext")
			http.Error(w, "prompt not sealed", http.StatusBadRequest)
			return
		}
		_ = json.Unmarshal(env["model"], &m.lastChatModel)
		e2ee, err := env.E2EE()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The envelope pin is the signer address; the routing pin header is the
		// provider address — distinct values.
		if e2ee.SignerAddr != testSigner {
			http.Error(w, "wrong provider pin (signer_addr)", http.StatusBadRequest)
			return
		}
		// A routing pin must always be set (so the router forwards to exactly the
		// sealed-to provider); the exact address varies across candidates on
		// fallback, so tests assert the specific value via lastChatHeaders.
		if got := r.Header.Get("X-0G-Provider-Address"); got == "" {
			t.Error("data-plane request carried no routing pin")
		}
		if _, err := wire.OpenRequest(broker.encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)

		// Stream sealed SSE frames when the (cleartext) envelope asked for it,
		// mirroring the real provider's streaming path; otherwise one JSON reply.
		if string(env["stream"]) == "true" {
			sealer, _ := wire.NewResponseSealer(crypto.PublicKey(ephPub))
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			deltas := []string{`{"content":"routed "}`, `{"content":"answer"}`}
			for i, d := range deltas {
				frame := wire.Response{"choices": json.RawMessage(`[{"index":0,"delta":` + d + `}]`)}
				sealed, _ := sealer.SealFrame(frame, nil, i == len(deltas)-1)
				b, _ := json.Marshal(sealed)
				fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-route"`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"routed answer"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	})

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func chatReq() wire.Request {
	return wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"the secret prompt"}]`),
		"stream":   json.RawMessage(`false`),
	}
}

// resolveHead runs Resolve and materializes the head candidate — the "preview +
// fetch the chosen provider's pubkey" the resolver's single Resolve used to do
// before per-candidate materialization was deferred for fallback.
func resolveHead(ctx context.Context, r *Router, req wire.Request) (core.Provider, error) {
	cands, err := r.Resolve(ctx, req)
	if err != nil {
		return core.Provider{}, err
	}
	return cands.Provider(ctx, 0)
}

// End to end: a core client using the route resolver previews, fetches the
// provider key, seals, and gets plaintext back — with the prompt never reaching
// either the router or the broker in cleartext.
func TestResolveEndToEnd(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)

	client := core.NewWithResolver(New(router.srv.URL))
	ctx := core.WithCredential(context.Background(), "Bearer sk-test")
	resp, err := client.Complete(ctx, chatReq())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	choices, _ := json.Marshal(resp["choices"])
	if !strings.Contains(string(choices), "routed answer") {
		t.Fatalf("did not get routed plaintext back: %s", choices)
	}

	// The router saw routing metadata but NOT the sealed prompt.
	if _, leaked := router.lastPreview["messages"]; leaked {
		t.Error("prompt was sent to the router in the preview call")
	}
	if _, ok := router.lastPreview["model"]; !ok {
		t.Error("preview call omitted the model")
	}
	if st := string(router.lastPreview["service_type"]); st != `"chatbot"` {
		t.Errorf("preview service_type = %s, want \"chatbot\"", st)
	}
	if _, leaked := router.lastPreview["type"]; leaked {
		t.Error("preview sent legacy \"type\" field instead of \"service_type\"")
	}
	if router.lastAuth != "Bearer sk-test" {
		t.Errorf("credential not forwarded to router: %q", router.lastAuth)
	}
	// The data-plane request names the head candidate's canonical_id, not the
	// caller's "gpt-4o" — the router preview's canonical_id is authoritative.
	if router.lastChatModel != "canon-1" {
		t.Errorf("data-plane model = %q, want canonical_id \"canon-1\"", router.lastChatModel)
	}

	// The data-plane chat request went to the router (not the broker) and pinned
	// the resolved provider (by provider address) so the router forwards to
	// exactly it, fallback off.
	if got := router.lastChatHeaders.Get("X-0G-Provider-Address"); got != testProviderAddr {
		t.Errorf("chat pin = %q, want provider address %q", got, testProviderAddr)
	}
	if got := router.lastChatHeaders.Get("X-0G-Allow-Fallbacks"); got != "false" {
		t.Errorf("chat allow-fallbacks = %q, want \"false\"", got)
	}
}

// A caller pins a specific provider with the X-0G-Provider-Address routing
// header; the resolver forwards it to the preview call so the router returns
// that provider. This is how "direct" provider selection works now that the
// gateway is route-only.
func TestPreviewForwardsRoutingHeaders(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)

	pin := http.Header{"X-0g-Provider-Address": []string{testProviderAddr}}
	ctx := core.WithForwardedHeaders(context.Background(), pin)
	if _, err := New(router.srv.URL).Resolve(ctx, chatReq()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := router.lastHeaders.Get("X-0g-Provider-Address"); got != testProviderAddr {
		t.Errorf("pin header not forwarded to preview: got %q, want %q", got, testProviderAddr)
	}
}

// Route mode also streams: preview + pubkey resolve, then the sealed request
// streams SSE frames back through the router, which the client opens in order.
func TestResolveStreamingEndToEnd(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)

	client := core.NewWithResolver(New(router.srv.URL))
	req := wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"the secret prompt"}]`),
		"stream":   json.RawMessage(`true`),
	}
	var got strings.Builder
	err := client.CompleteStream(context.Background(), req, func(frame wire.Response) error {
		got.Write(frame["choices"])
		return nil
	})
	if err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if !strings.Contains(got.String(), "routed ") || !strings.Contains(got.String(), "answer") {
		t.Fatalf("did not reassemble streamed deltas: %s", got.String())
	}
}

// Client-side fallback: the head candidate's provider is unavailable at the data
// plane, so the client re-seals to the second candidate (its own canonical_id,
// enc key) and retries — and gets plaintext back.
func TestCompleteFallsBackToNextCandidate(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	secondAddr := "0xC0FFEE0000000000000000000000000000000002"
	router.extra = []previewProvider{{
		Address:     secondAddr,
		CanonicalID: "canon-2",
		Endpoint:    broker.srv.URL,
		ModelID:     "gpt-4o@v2",
	}}
	router.failPin = testProviderAddr // the head candidate fails

	client := core.NewWithResolver(New(router.srv.URL))
	resp, err := client.Complete(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Complete should have fallen back and succeeded: %v", err)
	}
	choices, _ := json.Marshal(resp["choices"])
	if !strings.Contains(string(choices), "routed answer") {
		t.Fatalf("did not get plaintext back after fallback: %s", choices)
	}
	// The request that succeeded was pinned+sealed to the second candidate.
	if got := router.lastChatHeaders.Get("X-0G-Provider-Address"); got != secondAddr {
		t.Errorf("succeeded pin = %q, want fallback address %q", got, secondAddr)
	}
	if router.lastChatModel != "canon-2" {
		t.Errorf("data-plane model = %q, want fallback canonical_id \"canon-2\"", router.lastChatModel)
	}
}

// A 4xx from the head provider is a client fault that would recur on every
// candidate, so the client fails fast and does NOT fall back.
func TestCompleteDoesNotFallBackOn4xx(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	secondAddr := "0xC0FFEE0000000000000000000000000000000002"
	router.extra = []previewProvider{{
		Address:     secondAddr,
		CanonicalID: "canon-2",
		Endpoint:    broker.srv.URL,
		ModelID:     "gpt-4o@v2",
	}}
	router.failPin = testProviderAddr
	router.failStatus = http.StatusBadRequest

	client := core.NewWithResolver(New(router.srv.URL))
	_, err := client.Complete(context.Background(), chatReq())
	// The 400 is surfaced verbatim; a fallback would have hit the (healthy) second
	// candidate and returned success instead.
	assertStageStatus(t, err, core.StageUpstream, http.StatusBadRequest)
	if got := router.lastChatHeaders.Get("X-0G-Provider-Address"); got != testProviderAddr {
		t.Errorf("stopped at pin %q, want head %q (no fallback)", got, testProviderAddr)
	}
}

// A 200 whose sealed body cannot be opened is a provider fault with nothing yet
// returned to the caller, so the client falls back to the next candidate.
func TestCompleteFallsBackOnUnopenableResponse(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	secondAddr := "0xC0FFEE0000000000000000000000000000000002"
	router.extra = []previewProvider{{
		Address:     secondAddr,
		CanonicalID: "canon-2",
		Endpoint:    broker.srv.URL,
		ModelID:     "gpt-4o@v2",
	}}
	router.badBodyPin = testProviderAddr // head returns a 200 that won't open

	client := core.NewWithResolver(New(router.srv.URL))
	resp, err := client.Complete(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Complete should have fallen back after an unopenable response: %v", err)
	}
	choices, _ := json.Marshal(resp["choices"])
	if !strings.Contains(string(choices), "routed answer") {
		t.Fatalf("did not get plaintext back after fallback: %s", choices)
	}
	if got := router.lastChatHeaders.Get("X-0G-Provider-Address"); got != secondAddr {
		t.Errorf("succeeded pin = %q, want fallback address %q", got, secondAddr)
	}
}

// A response whose body drops mid-read is a provider-side failure with nothing
// delivered to the caller, so the client falls back to the next candidate.
func TestCompleteFallsBackOnBodyReadFailure(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	secondAddr := "0xC0FFEE0000000000000000000000000000000002"
	router.extra = []previewProvider{{
		Address:     secondAddr,
		CanonicalID: "canon-2",
		Endpoint:    broker.srv.URL,
		ModelID:     "gpt-4o@v2",
	}}
	router.truncBodyPin = testProviderAddr // head's body drops mid-read

	client := core.NewWithResolver(New(router.srv.URL))
	resp, err := client.Complete(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Complete should have fallen back after a truncated body: %v", err)
	}
	choices, _ := json.Marshal(resp["choices"])
	if !strings.Contains(string(choices), "routed answer") {
		t.Fatalf("did not get plaintext back after fallback: %s", choices)
	}
	if got := router.lastChatHeaders.Get("X-0G-Provider-Address"); got != secondAddr {
		t.Errorf("succeeded pin = %q, want fallback address %q", got, secondAddr)
	}
}

// A candidate with an empty canonical_id can't name the model in the sealed
// request — a router contract violation the client rejects (so core skips it).
func TestResolveRejectsMissingCanonicalID(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	cands, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Blank the head's canonical_id after the fact by re-driving through a router
	// that returns one; simplest is a direct check on materialization.
	rc := cands.(*routeCandidates)
	rc.providers[0].CanonicalID = ""
	if _, err := rc.Provider(context.Background(), 0); err == nil || !strings.Contains(err.Error(), "canonical_id") {
		t.Fatalf("want missing-canonical_id error, got %v", err)
	}
}

// Streaming fallback is pre-first-token only: the head candidate fails before any
// frame is delivered, so the client falls back to the second candidate and
// streams from it.
func TestCompleteStreamFallsBackBeforeFirstFrame(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	secondAddr := "0xC0FFEE0000000000000000000000000000000002"
	router.extra = []previewProvider{{
		Address:     secondAddr,
		CanonicalID: "canon-2",
		Endpoint:    broker.srv.URL,
		ModelID:     "gpt-4o@v2",
	}}
	router.failPin = testProviderAddr

	client := core.NewWithResolver(New(router.srv.URL))
	req := wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"the secret prompt"}]`),
		"stream":   json.RawMessage(`true`),
	}
	var got strings.Builder
	err := client.CompleteStream(context.Background(), req, func(frame wire.Response) error {
		got.Write(frame["choices"])
		return nil
	})
	if err != nil {
		t.Fatalf("CompleteStream should have fallen back and streamed: %v", err)
	}
	if !strings.Contains(got.String(), "answer") {
		t.Fatalf("did not stream after fallback: %s", got.String())
	}
	if got := router.lastChatHeaders.Get("X-0G-Provider-Address"); got != secondAddr {
		t.Errorf("streamed pin = %q, want fallback address %q", got, secondAddr)
	}
}

// WithSensitiveFields controls what the preview call withholds: the configured
// fields (here a custom one) are stripped, other fields pass through for routing.
func TestWithSensitiveFieldsStripsFromPreview(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	r := New(router.srv.URL, WithSensitiveFields([]string{"messages", "secret_field"}))

	req := wire.Request{
		"model":        json.RawMessage(`"gpt-4o"`),
		"messages":     json.RawMessage(`[{"role":"user","content":"hi"}]`),
		"secret_field": json.RawMessage(`"top secret"`),
		"temperature":  json.RawMessage(`0.5`),
	}
	if _, err := r.Resolve(context.Background(), req); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, leaked := router.lastPreview["messages"]; leaked {
		t.Error("messages leaked to preview")
	}
	if _, leaked := router.lastPreview["secret_field"]; leaked {
		t.Error("custom sensitive field leaked to preview")
	}
	if _, ok := router.lastPreview["temperature"]; !ok {
		t.Error("non-sensitive field should be forwarded for routing")
	}
}

func TestResolvePubkeyNon200(t *testing.T) {
	broker := newMockBroker(t)
	broker.pubkeyStatus = http.StatusNotFound
	router := newMockRouter(t, broker)

	_, err := resolveHead(context.Background(), New(router.srv.URL), chatReq())
	assertStageStatus(t, err, core.StageUpstream, http.StatusNotFound)
}

func TestResolvePubkeyMalformed(t *testing.T) {
	broker := newMockBroker(t)
	broker.pubkeyRaw = "not json at all"
	router := newMockRouter(t, broker)

	// A decode failure is an upstream error with no meaningful status (→ 502).
	_, err := resolveHead(context.Background(), New(router.srv.URL), chatReq())
	assertStageStatus(t, err, core.StageUpstream, 0)
}

func TestResolveProvider(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)

	p, err := resolveHead(context.Background(), New(router.srv.URL), chatReq())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.SignerAddr != testSigner {
		t.Errorf("signer = %q, want %q", p.SignerAddr, testSigner)
	}
	if p.Address != testProviderAddr {
		t.Errorf("address = %q, want %q", p.Address, testProviderAddr)
	}
	// Model is the candidate's canonical_id, written into the sealed request's
	// cleartext "model".
	if p.Model != "canon-1" {
		t.Errorf("model = %q, want canonical_id \"canon-1\"", p.Model)
	}
	// URL is the router's completions endpoint (auth/billing), not the provider's.
	if want := router.srv.URL + "/v1/chat/completions"; p.URL != want {
		t.Errorf("URL = %q, want %q", p.URL, want)
	}
	if len(p.EncPubKey) != x25519PubLen {
		t.Errorf("enc key len = %d, want %d", len(p.EncPubKey), x25519PubLen)
	}
}

func TestResolveCachesPubkey(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	r := New(router.srv.URL)

	for i := 0; i < 3; i++ {
		if _, err := resolveHead(context.Background(), r, chatReq()); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if hits := atomic.LoadInt32(&broker.pubkeyHits); hits != 1 {
		t.Fatalf("pubkey fetched %d times, want 1 (cached)", hits)
	}
}

func TestResolvePubkeyTTLDisablesCache(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	r := New(router.srv.URL, WithPubkeyTTL(0))

	for i := 0; i < 2; i++ {
		if _, err := resolveHead(context.Background(), r, chatReq()); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if hits := atomic.LoadInt32(&broker.pubkeyHits); hits != 2 {
		t.Fatalf("pubkey fetched %d times, want 2 (cache disabled)", hits)
	}
}

// "model" is optional on the preview path (matching the execute path): a request
// with no model resolves fine — the router previews any provider of the service
// type — and the preview call simply omits the model.
func TestResolveNoModelAllowed(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)

	req := wire.Request{"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`)}
	if _, err := resolveHead(context.Background(), New(router.srv.URL), req); err != nil {
		t.Fatalf("Resolve with no model: %v", err)
	}
	if _, sent := router.lastPreview["model"]; sent {
		t.Error("preview sent a model when the request had none")
	}
	if st := string(router.lastPreview["service_type"]); st != `"chatbot"` {
		t.Errorf("preview service_type = %s, want \"chatbot\"", st)
	}
}

func TestResolveSurfacesPreviewStatus(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.status = http.StatusUnauthorized

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	assertStageStatus(t, err, core.StageUpstream, http.StatusUnauthorized)
}

func TestResolveNoProvidersIs503(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.noProviders = true

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	assertStageStatus(t, err, core.StageUpstream, http.StatusServiceUnavailable)
}

// Preview is the one request-path dependency with no cache in front of it, so a
// transient router failure must not cost the caller its completion: the client
// retries and resolves off a later attempt.
func TestPreviewRetriesTransientFailure(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.previewFailN = previewAttempts - 1 // every attempt but the last

	provider, err := resolveHead(context.Background(), New(router.srv.URL), chatReq())
	if err != nil {
		t.Fatalf("Resolve after %d transient preview failures: %v", router.previewFailN, err)
	}
	if provider.Address != testProviderAddr {
		t.Errorf("provider address = %q, want %q", provider.Address, testProviderAddr)
	}
	if got := atomic.LoadInt32(&router.previewHits); got != previewAttempts {
		t.Errorf("preview attempts = %d, want %d", got, previewAttempts)
	}
	// Each attempt must carry the whole request again, not an already-drained body:
	// the retry re-wraps the marshaled payload rather than reusing one reader.
	if _, ok := router.lastPreview["service_type"]; !ok {
		t.Error("the succeeding attempt carried no service_type; the request body did not survive the retry")
	}
	if _, leaked := router.lastPreview["messages"]; leaked {
		t.Error("a retried preview leaked the prompt to the router")
	}
}

// A router that keeps failing is surfaced with its real status once the attempts
// run out — not masked by a retry-budget message, which would tell the caller
// nothing about what the router did.
func TestPreviewGivesUpAfterAttempts(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.previewFailN = previewAttempts + 5 // never recovers

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	assertStageStatus(t, err, core.StageUpstream, http.StatusServiceUnavailable)
	if got := atomic.LoadInt32(&router.previewHits); got != previewAttempts {
		t.Errorf("preview attempts = %d, want %d", got, previewAttempts)
	}
}

// A definitive failure is not retried: a 4xx recurs identically, and a 429 is the
// router's own limiter — another attempt would spend more of the caller's
// allowance to be told the same thing. Both must reach the caller on the first
// attempt, with their status intact.
func TestPreviewDoesNotRetryDefinitiveFailures(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusNotFound,
		http.StatusTooManyRequests,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			broker := newMockBroker(t)
			router := newMockRouter(t, broker)
			router.previewFailN = previewAttempts + 5
			router.previewFailCode = status

			_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
			assertStageStatus(t, err, core.StageUpstream, status)
			if got := atomic.LoadInt32(&router.previewHits); got != 1 {
				t.Errorf("preview attempts = %d, want 1 (a %d must not be retried)", got, status)
			}
		})
	}
}

// An empty candidate list is the router ANSWERING — negatively, but answering —
// so it is not retried either: the 503 is about the fleet, not about reaching the
// router.
func TestPreviewDoesNotRetryEmptyCandidateList(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.noProviders = true

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	assertStageStatus(t, err, core.StageUpstream, http.StatusServiceUnavailable)
	if got := atomic.LoadInt32(&router.previewHits); got != 1 {
		t.Errorf("preview attempts = %d, want 1", got)
	}
}

// A caller that has already given up must not be made to sit through the retry
// schedule: the cancelled context ends the sequence instead of the attempts doing.
func TestPreviewStopsRetryingOnCancelledContext(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.previewFailN = previewAttempts + 5

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel as soon as the first attempt has been served, so the cancellation lands
	// while the client is in (or about to enter) its first backoff.
	go func() {
		for atomic.LoadInt32(&router.previewHits) == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()

	_, err := New(router.srv.URL).Resolve(ctx, chatReq())
	if err == nil {
		t.Fatal("Resolve with a cancelled context: want error, got nil")
	}
	if got := atomic.LoadInt32(&router.previewHits); got >= previewAttempts {
		t.Errorf("preview attempts = %d, want fewer than %d (cancellation should cut the sequence short)", got, previewAttempts)
	}
}

// The point of metering the retries: a router degrading badly enough to need them
// must be visible even while every request still succeeds. ok_retried is that
// series, and it has to stay distinct from a clean first-attempt ok.
func TestPreviewMetricsSeparateAbsorbedFailuresFromCleanCalls(t *testing.T) {
	const (
		callsOK            = `zg_gateway_preview_calls_total{outcome="ok"}`
		callsRetried       = `zg_gateway_preview_calls_total{outcome="ok_retried"}`
		callsFailed        = `zg_gateway_preview_calls_total{outcome="failed"}`
		attemptsOK         = `zg_gateway_preview_attempts_total{result="ok"}`
		attemptsRetryable  = `zg_gateway_preview_attempts_total{result="retryable"}`
		attemptsDefinitive = `zg_gateway_preview_attempts_total{result="definitive"}`
	)
	before := map[string]float64{}
	for _, s := range []string{callsOK, callsRetried, callsFailed, attemptsOK, attemptsRetryable, attemptsDefinitive} {
		before[s] = metricValue(t, s)
	}
	delta := func(s string) float64 { return metricValue(t, s) - before[s] }

	// A router per phase: previewFailN counts attempts over the mock's whole life,
	// so a router reused across phases would have spent its failures already.
	newRouter := func() *mockRouter { return newMockRouter(t, newMockBroker(t)) }

	// A clean call: one ok attempt, outcome ok.
	if _, err := New(newRouter().srv.URL).Resolve(context.Background(), chatReq()); err != nil {
		t.Fatalf("clean Resolve: %v", err)
	}
	if got := delta(callsOK); got != 1 {
		t.Errorf("%s delta = %v, want 1", callsOK, got)
	}
	if got := delta(callsRetried); got != 0 {
		t.Errorf("a first-attempt success must not count as retried; %s delta = %v", callsRetried, got)
	}

	// A blip the retries absorb: the caller still succeeds, but the router's
	// degradation is on the record as ok_retried plus a retryable attempt.
	blip := newRouter()
	blip.previewFailN = 1
	if _, err := New(blip.srv.URL).Resolve(context.Background(), chatReq()); err != nil {
		t.Fatalf("Resolve across a transient failure: %v", err)
	}
	if got := delta(callsRetried); got != 1 {
		t.Errorf("%s delta = %v, want 1 — an absorbed failure is invisible", callsRetried, got)
	}
	if got := delta(callsOK); got != 1 {
		t.Errorf("a retried success must not also count as a clean ok; %s delta = %v, want 1", callsOK, got)
	}
	if got := delta(attemptsRetryable); got != 1 {
		t.Errorf("%s delta = %v, want 1", attemptsRetryable, got)
	}
	if got := delta(attemptsOK); got != 2 {
		t.Errorf("%s delta = %v, want 2 (one per successful attempt)", attemptsOK, got)
	}

	// A definitive failure: counted as definitive, never as retryable, and the call
	// as failed rather than absorbed.
	dead := newRouter()
	dead.previewFailN = previewAttempts + 5
	dead.previewFailCode = http.StatusUnauthorized
	if _, err := New(dead.srv.URL).Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("Resolve against a 401 router: want error, got nil")
	}
	if got := delta(attemptsDefinitive); got != 1 {
		t.Errorf("%s delta = %v, want 1", attemptsDefinitive, got)
	}
	if got := delta(attemptsRetryable); got != 1 {
		t.Errorf("a 401 must not be counted retryable; %s delta = %v, want 1 (unchanged)", attemptsRetryable, got)
	}
	if got := delta(callsFailed); got != 1 {
		t.Errorf("%s delta = %v, want 1", callsFailed, got)
	}
}

// Every preview call observes the duration histogram exactly once, whatever its
// outcome — the defer that records it must not be skipped on an error path.
func TestPreviewDurationObservedOnEveryCall(t *testing.T) {
	const series = `zg_gateway_preview_duration_seconds_count`
	before := metricValue(t, series)

	ok := newMockRouter(t, newMockBroker(t))
	if _, err := New(ok.srv.URL).Resolve(context.Background(), chatReq()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Its own router: previewFailN counts over the mock's whole life, so reusing the
	// one above would have to account for the attempt it already served.
	dead := newMockRouter(t, newMockBroker(t))
	dead.previewFailN = previewAttempts + 5
	dead.previewFailCode = http.StatusUnauthorized
	if _, err := New(dead.srv.URL).Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("want an error from a 401 router")
	}

	if got := metricValue(t, series) - before; got != 2 {
		t.Errorf("%s delta = %v, want 2 (one observation per call, success and failure alike)", series, got)
	}
}

func TestRetryablePreviewStatus(t *testing.T) {
	for status, want := range map[int]bool{
		http.StatusBadRequest:          false,
		http.StatusUnauthorized:        false,
		http.StatusNotFound:            false,
		http.StatusTooManyRequests:     false, // unlike the data plane — see previewOnce
		http.StatusInternalServerError: true,
		http.StatusBadGateway:          true,
		http.StatusServiceUnavailable:  true,
		http.StatusGatewayTimeout:      true,
	} {
		if got := retryablePreviewStatus(status); got != want {
			t.Errorf("retryablePreviewStatus(%d) = %v, want %v", status, got, want)
		}
	}
}

// A candidate without a USABLE address can't be pinned, so the router could
// re-route the sealed request to a provider that can't decrypt it — materializing
// it fails so core skips it.
//
// "Usable" is well-formed, not merely non-empty: this router-chosen string is also
// the key of a per-provider rate limiter, so accepting arbitrary text would let the
// router mint keys — and with them fresh allowances — at will.
func TestResolveRejectsUnusableAddress(t *testing.T) {
	for _, tc := range []struct{ name, addr string }{
		{"empty", ""},
		{"not hex", "0xZZZZccddeeff00112233445566778899aabbccdd"},
		{"too short", "0xaabb"},
		{"no 0x prefix", "aabbccddeeff00112233445566778899aabbccdd"},
		{"padded with spaces", " 0xaabbccddeeff00112233445566778899aabbccdd "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broker := newMockBroker(t)
			router := newMockRouter(t, broker)
			router.previewAddress = tc.addr

			_, err := resolveHead(context.Background(), New(router.srv.URL), chatReq())
			if err == nil || !strings.Contains(err.Error(), "usable address") {
				t.Fatalf("want unusable-address error, got %v", err)
			}
		})
	}
}

// The preview list is the fallback chain: Resolve returns every candidate the
// router ranked, so core can walk them, and each carries its own canonical_id.
func TestResolveReturnsFullCandidateChain(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.extra = []previewProvider{{
		Address:     "0xC0FFEE0000000000000000000000000000000002",
		CanonicalID: "canon-2",
		Endpoint:    broker.srv.URL,
		ModelID:     "gpt-4o@v2",
	}}

	cands, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cands.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (head + one fallback)", cands.Len())
	}
	second, err := cands.Provider(context.Background(), 1)
	if err != nil {
		t.Fatalf("materialize fallback candidate: %v", err)
	}
	if second.Model != "canon-2" || second.Address != "0xC0FFEE0000000000000000000000000000000002" {
		t.Errorf("fallback candidate = %+v, want canon-2 / ...0002", second)
	}
}

func TestValidatePubkey(t *testing.T) {
	_, encPub, _ := crypto.GenerateRecipientKey()
	good := pubkeyResponse{
		V: wire.Version, KEMID: wire.KEMID,
		EncPub: base64.RawURLEncoding.EncodeToString(encPub), SignerAddress: testSigner,
	}
	if _, _, err := validatePubkey(good); err != nil {
		t.Fatalf("good pubkey rejected: %v", err)
	}

	bad := map[string]pubkeyResponse{
		"wrong kem":     {V: wire.Version, KEMID: "0x9999", EncPub: good.EncPub, SignerAddress: testSigner},
		"wrong version": {V: 2, KEMID: wire.KEMID, EncPub: good.EncPub, SignerAddress: testSigner},
		"bad enc_pub":   {KEMID: wire.KEMID, EncPub: "!!!not-base64!!!", SignerAddress: testSigner},
		"short enc_pub": {KEMID: wire.KEMID, EncPub: base64.RawURLEncoding.EncodeToString([]byte("too short")), SignerAddress: testSigner},
		"bad signer":    {KEMID: wire.KEMID, EncPub: good.EncPub, SignerAddress: "not-an-address"},
	}
	for name, pk := range bad {
		if _, _, err := validatePubkey(pk); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}

func TestDerivePubkeyURL(t *testing.T) {
	cases := []struct{ endpoint, pubkey string }{
		{"https://host", "https://host/v1/e2ee/pubkey"},
		{"https://host:8443/", "https://host:8443/v1/e2ee/pubkey"},
		{"https://host/v1", "https://host/v1/e2ee/pubkey"},
		{"https://host/v1/chat/completions", "https://host/v1/e2ee/pubkey"},
		{"https://host/api", "https://host/api/v1/e2ee/pubkey"},
	}
	for _, c := range cases {
		pub, err := derivePubkeyURL(c.endpoint)
		if err != nil {
			t.Errorf("%s: %v", c.endpoint, err)
			continue
		}
		if pub != c.pubkey {
			t.Errorf("%s: pubkey = %q, want %q", c.endpoint, pub, c.pubkey)
		}
	}
	for _, bad := range []string{"", "not a url", "/relative/only", "host-no-scheme.com/v1"} {
		if _, err := derivePubkeyURL(bad); err == nil {
			t.Errorf("derivePubkeyURL(%q): expected error", bad)
		}
	}
}

func TestPubkeyCacheExpires(t *testing.T) {
	c := newPubkeyCache(20 * time.Millisecond)
	c.put("k", crypto.PublicKey{1, 2, 3}, testSigner)
	if _, _, ok := c.get("k"); !ok {
		t.Fatal("entry should be fresh")
	}
	time.Sleep(40 * time.Millisecond)
	if _, _, ok := c.get("k"); ok {
		t.Fatal("entry should have expired")
	}
}

// assertStageStatus checks err is a *core.Error with the given stage and status.
func assertStageStatus(t *testing.T, err error, stage string, status int) {
	t.Helper()
	var e *core.Error
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.As(err, &e) {
		t.Fatalf("error is not *core.Error: %v", err)
	}
	if e.Stage != stage {
		t.Errorf("stage = %q, want %q", e.Stage, stage)
	}
	if e.Status != status {
		t.Errorf("status = %d, want %d", e.Status, status)
	}
}

// meteredClient is a route-resolving core client with the real Prometheus adapter
// wired in, so the data-plane assertions below read the same series the dashboard
// does rather than a test double's idea of them.
func meteredClient(routerURL string) *core.Client {
	return core.NewWithResolver(New(routerURL), core.WithMetrics(metrics.CoreMetrics{}))
}

func upstreamAttempt(kind, outcome string) string {
	return fmt.Sprintf(`zg_gateway_upstream_attempts_total{kind="%s",outcome="%s"}`, kind, outcome)
}

// A clean buffered completion books exactly one buffered/ok attempt, observes the
// attempt-duration histogram once, and reports no fallback.
func TestUpstreamMetricsOnCleanCompletion(t *testing.T) {
	ok := upstreamAttempt("buffered", "ok")
	dur := `zg_gateway_upstream_attempt_duration_seconds_count{kind="buffered"}`
	fb := `zg_gateway_candidate_fallbacks_total{reason="upstream"}`
	before := map[string]float64{ok: metricValue(t, ok), dur: metricValue(t, dur), fb: metricValue(t, fb)}

	router := newMockRouter(t, newMockBroker(t))
	if _, err := meteredClient(router.srv.URL).Complete(context.Background(), chatReq()); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	for series, want := range map[string]float64{ok: 1, dur: 1, fb: 0} {
		if got := metricValue(t, series) - before[series]; got != want {
			t.Errorf("%s delta = %v, want %v", series, got, want)
		}
	}
}

// The fallback counter is the only signal that the router's ranking put a bad
// provider first — the request itself succeeded, so nothing else records it. The
// failing head must also land in the bucket for the status it actually returned.
func TestUpstreamMetricsRecordFallbackAndStatus(t *testing.T) {
	fb := `zg_gateway_candidate_fallbacks_total{reason="upstream"}`
	s5xx := upstreamAttempt("buffered", "http_5xx")
	ok := upstreamAttempt("buffered", "ok")
	before := map[string]float64{fb: metricValue(t, fb), s5xx: metricValue(t, s5xx), ok: metricValue(t, ok)}

	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	secondAddr := "0xC0FFEE0000000000000000000000000000000002"
	router.extra = []previewProvider{{
		Address: secondAddr, CanonicalID: "canon-2", Endpoint: broker.srv.URL, ModelID: "gpt-4o@v2",
	}}
	router.failPin = testProviderAddr // the head 503s; the second serves

	if _, err := meteredClient(router.srv.URL).Complete(context.Background(), chatReq()); err != nil {
		t.Fatalf("Complete should have fallen back and succeeded: %v", err)
	}

	for series, want := range map[string]float64{fb: 1, s5xx: 1, ok: 1} {
		if got := metricValue(t, series) - before[series]; got != want {
			t.Errorf("%s delta = %v, want %v", series, got, want)
		}
	}
}

// 429 gets its own bucket rather than joining the 4xx crowd: it says the provider
// is saturated, not that the request was wrong, and it is the 4xx the client falls
// back on.
func TestUpstreamMetricsSeparateRateLimitFromOther4xx(t *testing.T) {
	s429, s4xx := upstreamAttempt("buffered", "http_429"), upstreamAttempt("buffered", "http_4xx")
	before := map[string]float64{s429: metricValue(t, s429), s4xx: metricValue(t, s4xx)}

	for _, tc := range []struct {
		status int
		series string
	}{
		{http.StatusTooManyRequests, s429},
		{http.StatusBadRequest, s4xx},
	} {
		router := newMockRouter(t, newMockBroker(t))
		router.failPin = testProviderAddr
		router.failStatus = tc.status
		if _, err := meteredClient(router.srv.URL).Complete(context.Background(), chatReq()); err == nil {
			t.Fatalf("Complete against a %d provider: want error", tc.status)
		}
	}

	for series, want := range map[string]float64{s429: 1, s4xx: 1} {
		if got := metricValue(t, series) - before[series]; got != want {
			t.Errorf("%s delta = %v, want %v", series, got, want)
		}
	}
}

// A 2xx whose sealed body will not open is its own diagnosis — the provider
// answered, the crypto did not line up — and must not be filed as a transport or
// status failure.
func TestUpstreamMetricsRecordUnopenableBody(t *testing.T) {
	series := upstreamAttempt("buffered", "undecodable")
	before := metricValue(t, series)

	router := newMockRouter(t, newMockBroker(t))
	router.badBodyPin = testProviderAddr
	if _, err := meteredClient(router.srv.URL).Complete(context.Background(), chatReq()); err == nil {
		t.Fatal("Complete against an unopenable body: want error")
	}

	if got := metricValue(t, series) - before; got != 1 {
		t.Errorf("%s delta = %v, want 1", series, got)
	}
}

// A stream books a stream-kind attempt and, separately, its time to first frame —
// the latency a streaming caller feels, which the attempt duration cannot show
// because it measures how long the stream stayed open.
func TestUpstreamMetricsRecordStreamAndFirstFrame(t *testing.T) {
	ok := upstreamAttempt("stream", "ok")
	ttff := `zg_gateway_upstream_stream_ttff_seconds_count`
	dur := `zg_gateway_upstream_attempt_duration_seconds_count{kind="stream"}`
	// The buffered histogram is watched too: mixing a stream's open duration into it
	// is exactly what makes a completion-latency panel unreadable, so the split has
	// to be asserted, not assumed.
	buffered := `zg_gateway_upstream_attempt_duration_seconds_count{kind="buffered"}`
	before := map[string]float64{
		ok: metricValue(t, ok), ttff: metricValue(t, ttff),
		dur: metricValue(t, dur), buffered: metricValue(t, buffered),
	}

	router := newMockRouter(t, newMockBroker(t))
	req := chatReq()
	req["stream"] = json.RawMessage(`true`)
	frames := 0
	if err := meteredClient(router.srv.URL).CompleteStream(context.Background(), req,
		func(wire.Response) error { frames++; return nil }); err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if frames < 2 {
		t.Fatalf("got %d frames, want at least 2 (so first-frame is distinct from last)", frames)
	}

	for series, want := range map[string]float64{ok: 1, ttff: 1, dur: 1, buffered: 0} {
		if got := metricValue(t, series) - before[series]; got != want {
			t.Errorf("%s delta = %v, want %v — a stream must book one attempt, ONE first-frame, and nothing buffered", series, got, want)
		}
	}
}

// onFrame can fail two ways and core cannot see inside it: the caller
// disconnected, or the caller's handler broke on its own. They must not share a
// bucket — "canceled" is excluded from every alert, so filing a gateway bug there
// hides it, and filing a disconnect under "internal" cries wolf on every closed
// tab. The split is decided by asking the parent context.
func TestStreamOnFrameFailureAttribution(t *testing.T) {
	internal := upstreamAttempt("stream", "internal")
	canceled := upstreamAttempt("stream", "canceled")

	streamReq := func() wire.Request {
		req := chatReq()
		req["stream"] = json.RawMessage(`true`)
		return req
	}

	// The handler fails while the caller's context is still live: our fault.
	t.Run("handler failure with a live caller is internal", func(t *testing.T) {
		before := map[string]float64{internal: metricValue(t, internal), canceled: metricValue(t, canceled)}
		router := newMockRouter(t, newMockBroker(t))
		err := meteredClient(router.srv.URL).CompleteStream(context.Background(), streamReq(),
			func(wire.Response) error { return errors.New("could not serialize the frame") })
		if err == nil {
			t.Fatal("want the handler's error back")
		}
		if got := metricValue(t, internal) - before[internal]; got != 1 {
			t.Errorf("%s delta = %v, want 1", internal, got)
		}
		if got := metricValue(t, canceled) - before[canceled]; got != 0 {
			t.Errorf("a live caller must not be counted canceled; %s delta = %v", canceled, got)
		}
	})

	// The caller went away: not our fault, and not the provider's.
	t.Run("handler failure with a gone caller is canceled", func(t *testing.T) {
		before := map[string]float64{internal: metricValue(t, internal), canceled: metricValue(t, canceled)}
		router := newMockRouter(t, newMockBroker(t))
		ctx, cancel := context.WithCancel(context.Background())
		err := meteredClient(router.srv.URL).CompleteStream(ctx, streamReq(),
			func(wire.Response) error {
				cancel() // the client hung up as this frame was being written
				return errors.New("write: broken pipe")
			})
		cancel()
		if err == nil {
			t.Fatal("want the handler's error back")
		}
		if got := metricValue(t, canceled) - before[canceled]; got != 1 {
			t.Errorf("%s delta = %v, want 1", canceled, got)
		}
		if got := metricValue(t, internal) - before[internal]; got != 0 {
			t.Errorf("a disconnect must not be counted internal; %s delta = %v", internal, got)
		}
	})
}
