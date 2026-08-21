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
		callsOK           = `zg_gateway_preview_calls_total{outcome="ok"}`
		callsRetried      = `zg_gateway_preview_calls_total{outcome="ok_retried"}`
		callsRejected     = `zg_gateway_preview_calls_total{outcome="rejected"}`
		callsFailed       = `zg_gateway_preview_calls_total{outcome="failed"}`
		attemptsOK        = `zg_gateway_preview_attempts_total{result="ok"}`
		attemptsRetryable = `zg_gateway_preview_attempts_total{result="retryable"}`
		attemptsRejected  = `zg_gateway_preview_attempts_total{result="rejected"}`
	)
	series := []string{callsOK, callsRetried, callsRejected, callsFailed, attemptsOK, attemptsRetryable, attemptsRejected}
	before := map[string]float64{}
	for _, s := range series {
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

	// A 401: the router ANSWERED. It must be counted rejected, never retryable, and
	// — the point of the split — the CALL must not land in "failed", which is the
	// series an alert reads as "the router is unwell". One tenant with a bad key
	// would otherwise pin it.
	dead := newRouter()
	dead.previewFailN = previewAttempts + 5
	dead.previewFailCode = http.StatusUnauthorized
	if _, err := New(dead.srv.URL).Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("Resolve against a 401 router: want error, got nil")
	}
	if got := delta(attemptsRejected); got != 1 {
		t.Errorf("%s delta = %v, want 1", attemptsRejected, got)
	}
	if got := delta(attemptsRetryable); got != 1 {
		t.Errorf("a 401 must not be counted retryable; %s delta = %v, want 1 (unchanged)", attemptsRetryable, got)
	}
	if got := delta(callsRejected); got != 1 {
		t.Errorf("%s delta = %v, want 1", callsRejected, got)
	}
	if got := delta(callsFailed); got != 0 {
		t.Errorf("a caller's own 401 must not be counted a router failure; %s delta = %v, want 0", callsFailed, got)
	}

	// A router that only ever 5xxes IS the router being unwell: that one is failed.
	broken := newRouter()
	broken.previewFailN = previewAttempts + 5
	if _, err := New(broken.srv.URL).Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("Resolve against a 503 router: want error, got nil")
	}
	if got := delta(callsFailed); got != 1 {
		t.Errorf("%s delta = %v, want 1", callsFailed, got)
	}
}

// An empty candidate list is the router answering about the FLEET, not failing —
// so it is rejected, and must not read as the router being unwell either.
func TestPreviewEmptyCandidateListIsRejectedNotFailed(t *testing.T) {
	const (
		callsRejected = `zg_gateway_preview_calls_total{outcome="rejected"}`
		callsFailed   = `zg_gateway_preview_calls_total{outcome="failed"}`
	)
	before := map[string]float64{callsRejected: metricValue(t, callsRejected), callsFailed: metricValue(t, callsFailed)}

	router := newMockRouter(t, newMockBroker(t))
	router.noProviders = true
	if _, err := New(router.srv.URL).Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("want a 503 error")
	}
	if got := metricValue(t, callsRejected) - before[callsRejected]; got != 1 {
		t.Errorf("%s delta = %v, want 1", callsRejected, got)
	}
	if got := metricValue(t, callsFailed) - before[callsFailed]; got != 0 {
		t.Errorf("%s delta = %v, want 0", callsFailed, got)
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

func TestPreviewStatusResult(t *testing.T) {
	for status, want := range map[int]previewResult{
		// The router answered. Retrying cannot change any of these, and they are
		// usually about the caller, not the router — see previewRejected.
		http.StatusBadRequest:      previewRejected,
		http.StatusUnauthorized:    previewRejected,
		http.StatusNotFound:        previewRejected,
		http.StatusTooManyRequests: previewRejected, // unlike the data plane — see previewOnce
		// The router faulted, and may not next time.
		http.StatusInternalServerError: previewRetryable,
		http.StatusBadGateway:          previewRetryable,
		http.StatusServiceUnavailable:  previewRetryable,
		http.StatusGatewayTimeout:      previewRetryable,
	} {
		if got := previewStatusResult(status); got != want {
			t.Errorf("previewStatusResult(%d) = %q, want %q", status, got, want)
		}
	}
}

// The call-level outcome must keep a definitive negative out of "failed": a tenant
// with a misconfigured key would otherwise pin an alert meant for the router.
func TestPreviewResultCallOutcome(t *testing.T) {
	for res, want := range map[previewResult]string{
		previewRejected:  "rejected",
		previewCanceled:  "canceled",
		previewBroken:    "failed",
		previewRetryable: "failed",
	} {
		if got := res.callOutcome(); got != want {
			t.Errorf("%q.callOutcome() = %q, want %q", res, got, want)
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

// The per-attempt deadline is what makes the retry ceiling a fact. Without it the
// shared client bounds only the wait for HEADERS, so a router that dribbles (or
// never finishes) a body leaves an attempt — and therefore the whole preview —
// unbounded, and the retry budget, which only gates ENTRY to an attempt, cannot
// cap anything.
//
// This is the regression test for the claim that used to be wrong: a probe failing
// each attempt slowly measured ~2× the "budget", because the budget check had
// already passed when the next attempt began.
func TestPreviewAttemptIsBounded(t *testing.T) {
	// Headers go out immediately so ResponseHeaderTimeout cannot be what saves us;
	// the body then never arrives. Only a bound on the whole attempt ends this.
	release := make(chan struct{})
	defer close(release)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	router := New(srv.URL)
	const attempt = 150 * time.Millisecond
	router.previewAttemptTO = attempt

	start := time.Now()
	if _, err := router.Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("want an error from a router that never finishes a body")
	}
	elapsed := time.Since(start)

	// A hung body reads as a retryable failure, so the budget admits more attempts;
	// what must hold is that each one is bounded, so the total stays near a small
	// multiple of the attempt bound rather than running forever.
	if max := time.Duration(previewAttempts) * attempt * 4; elapsed > max {
		t.Errorf("preview took %s against a %s attempt bound (max %s): the attempt is not bounded",
			elapsed, attempt, max)
	}
	if got := atomic.LoadInt32(&hits); got == 0 {
		t.Fatal("the router was never called")
	}
	t.Logf("bounded: %s over %d attempt(s) at %s each", elapsed.Truncate(time.Millisecond), atomic.LoadInt32(&hits), attempt)
}

// The caller's own deadline still wins when it is shorter — the per-attempt bound
// is a ceiling, not a floor that could outlive the request it serves.
func TestPreviewAttemptHonoursAShorterCallerDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	router := New(srv.URL)
	router.previewAttemptTO = 10 * time.Second // deliberately far longer than the caller's

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := router.Resolve(ctx, chatReq()); err == nil {
		t.Fatal("want an error once the caller's deadline passes")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("preview took %s; the caller's 150ms deadline should have ended it", elapsed)
	}
}

// The exact scenario that disproved the original claim: each attempt fails slowly
// but well short of its own bound, so the budget check passes and a second attempt
// starts. The end-to-end cost is then budget + one attempt — NOT one attempt, which
// is what the code used to claim. This pins the real ceiling.
func TestPreviewCeilingIsBudgetPlusOneAttempt(t *testing.T) {
	// Scaled to the shape that was actually measured against the shipped constants
	// (20s failures under a 30s budget cost 40s): a failure that spends most of the
	// budget but is well inside the attempt bound. previewRetryBackoff is a real
	// constant and is NOT scaled, so the budget has to leave room for it.
	const (
		attemptTO = time.Second
		budgetTO  = time.Second
		failAfter = 600 * time.Millisecond
	)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		select {
		case <-time.After(failAfter):
			http.Error(w, "slow failure", http.StatusServiceUnavailable)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	router := New(srv.URL)
	router.previewAttemptTO, router.previewBudgetTO = attemptTO, budgetTO

	start := time.Now()
	if _, err := router.Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("want an error from a router that always 503s")
	}
	elapsed := time.Since(start)

	// Two attempts is the expected shape: the first spends most of the budget, the
	// second is admitted, and the third is not.
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("attempts = %d, want 2 (one, then one the budget still admitted)", got)
	}
	// The ceiling the comment now states. Generous slack for scheduling; the point
	// is that it is a CEILING at all — before the attempt was bounded, a slow body
	// on this path had none.
	if ceiling := budgetTO + attemptTO; elapsed > ceiling+500*time.Millisecond {
		t.Errorf("preview took %s, past the stated ceiling of budget+attempt = %s", elapsed, ceiling)
	}
	// And it really is MORE than one attempt: the old comment claimed otherwise.
	if elapsed <= attemptTO {
		t.Errorf("preview took only %s; this scenario is supposed to cost more than one attempt (%s)", elapsed, attemptTO)
	}
	t.Logf("elapsed %s over %d attempts (ceiling %s)", elapsed.Truncate(time.Millisecond), atomic.LoadInt32(&hits), budgetTO+attemptTO)
}

// The retry gate exists so a router outage cannot be amplified back at the router
// (previewAttempts× the traffic) or at us (each request holding its concurrency
// slot for the retry ceiling instead of one attempt). The first attempt is never
// suppressed, so every request still gets its real error.
func TestPreviewRetriesSuppressedWhileRouterIsDown(t *testing.T) {
	const suppressed = `zg_gateway_preview_retries_suppressed_total`
	before := metricValue(t, suppressed)

	router := newMockRouter(t, newMockBroker(t))
	router.previewFailN = 1 << 20 // never recovers
	r := New(router.srv.URL)

	// Trip the gate: each call burns its full attempt allowance.
	for i := 0; i < previewRetryTripAfter; i++ {
		if _, err := r.Resolve(context.Background(), chatReq()); err == nil {
			t.Fatal("want an error from a dead router")
		}
	}
	tripped := atomic.LoadInt32(&router.previewHits)
	if want := int32(previewRetryTripAfter * previewAttempts); tripped != want {
		t.Fatalf("attempts before tripping = %d, want %d", tripped, want)
	}

	// From here each call costs ONE attempt, not previewAttempts.
	if _, err := r.Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("want an error from a dead router")
	}
	if got := atomic.LoadInt32(&router.previewHits) - tripped; got != 1 {
		t.Errorf("attempts after tripping = %d, want 1 (retries should be suppressed)", got)
	}
	if got := metricValue(t, suppressed) - before; got == 0 {
		t.Error("no suppression was counted; the gate is invisible to an operator")
	}
}

// A router that comes back must get its retries back — the gate is a cooldown, not
// a latch, and any answer at all is proof of reachability.
func TestPreviewRetryGateReopensOnAnAnswer(t *testing.T) {
	router := newMockRouter(t, newMockBroker(t))
	router.previewFailN = 1 << 20
	r := New(router.srv.URL)
	for i := 0; i < previewRetryTripAfter; i++ {
		_, _ = r.Resolve(context.Background(), chatReq())
	}

	// The router recovers; the one attempt the gate still allows finds it.
	router.previewFailN = 0
	if _, err := r.Resolve(context.Background(), chatReq()); err != nil {
		t.Fatalf("Resolve after recovery: %v", err)
	}

	// Retries are back: a fresh transient blip is absorbed again.
	base := atomic.LoadInt32(&router.previewHits)
	router.previewFailN = base + 1 // fail exactly the next attempt
	if _, err := r.Resolve(context.Background(), chatReq()); err != nil {
		t.Fatalf("Resolve across a blip after recovery: %v", err)
	}
	if got := atomic.LoadInt32(&router.previewHits) - base; got != 2 {
		t.Errorf("attempts = %d, want 2 (the gate should have reopened)", got)
	}
}

// lateCancelCtx reports Err() as canceled once flipped, while its Done channel is
// never closed — so an HTTP request already in flight is NOT torn down. That models
// exactly the race the ordering fix is about ("the caller went away in the gap
// after a successful attempt returned") without having to win it: a real
// cancellation would abort the request and never reach the branch under test.
type lateCancelCtx struct {
	context.Context
	done     chan struct{}
	canceled *atomic.Bool
}

func (c lateCancelCtx) Done() <-chan struct{} { return c.done }

func (c lateCancelCtx) Err() error {
	if c.canceled.Load() {
		return context.Canceled
	}
	return nil
}

// A cancellation that lands between a successful attempt returning and the loop
// inspecting it must not turn that attempt into "canceled": the call is counted ok,
// and two series that disagree about the same attempt are worse than either alone.
func TestPreviewSuccessNotReattributedToLateCancellation(t *testing.T) {
	const (
		attemptsOK       = `zg_gateway_preview_attempts_total{result="ok"}`
		attemptsCanceled = `zg_gateway_preview_attempts_total{result="canceled"}`
		callsOK          = `zg_gateway_preview_calls_total{outcome="ok"}`
		callsCanceled    = `zg_gateway_preview_calls_total{outcome="canceled"}`
	)
	series := []string{attemptsOK, attemptsCanceled, callsOK, callsCanceled}
	before := map[string]float64{}
	for _, s := range series {
		before[s] = metricValue(t, s)
	}

	var canceled atomic.Bool
	router := newMockRouter(t, newMockBroker(t))
	ctx := lateCancelCtx{
		Context:  context.Background(),
		done:     make(chan struct{}),
		canceled: &canceled,
	}

	// The preview succeeds, and the caller is gone by the time the loop looks.
	r := New(router.srv.URL)
	providers, err := r.preview(ctx, chatReq())
	canceled.Store(true)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(providers) == 0 {
		t.Fatal("preview returned no candidates")
	}
	// Re-run with the flag already set: this is the ordering under test.
	if _, err := r.preview(ctx, chatReq()); err != nil {
		t.Fatalf("preview with an already-done caller: %v", err)
	}

	if got := metricValue(t, attemptsOK) - before[attemptsOK]; got != 2 {
		t.Errorf("%s delta = %v, want 2", attemptsOK, got)
	}
	if got := metricValue(t, attemptsCanceled) - before[attemptsCanceled]; got != 0 {
		t.Errorf("a successful attempt was re-attributed to a late cancellation; %s delta = %v, want 0",
			attemptsCanceled, got)
	}
	if got := metricValue(t, callsOK) - before[callsOK]; got != 2 {
		t.Errorf("%s delta = %v, want 2", callsOK, got)
	}
	if got := metricValue(t, callsCanceled) - before[callsCanceled]; got != 0 {
		t.Errorf("%s delta = %v, want 0 — the attempt and call series must agree", callsCanceled, got)
	}
}

// The suppression counter measures amplification shed, so it must count the retry
// ATTEMPTS not made — one increment per affected call under-reported it by up to
// previewAttempts-1, while the metric's name, its Help and the runbook all read it
// as attempts.
func TestPreviewSuppressionCountsAttemptsNotCalls(t *testing.T) {
	const suppressed = `zg_gateway_preview_retries_suppressed_total`

	router := newMockRouter(t, newMockBroker(t))
	router.previewFailN = 1 << 20
	r := New(router.srv.URL)
	for i := 0; i < previewRetryTripAfter; i++ {
		_, _ = r.Resolve(context.Background(), chatReq())
	}

	// One more call, now with the gate shut: it makes attempt 0 and is turned away
	// at attempt 1, so previewAttempts-1 retries were shed.
	before := metricValue(t, suppressed)
	_, _ = r.Resolve(context.Background(), chatReq())
	if got, want := metricValue(t, suppressed)-before, float64(previewAttempts-1); got != want {
		t.Errorf("%s delta = %v, want %v (the attempts not made, not one per call)", suppressed, got, want)
	}
}

// The router picks the candidate list and nothing else bounds its length, while
// core walks it serially — so N is one of the two factors in what a failing chain
// costs a caller. Trimming is safe because the list arrives ranked best-first.
func TestPreviewCapsTheCandidateList(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	// One head plus far more extras than the cap allows.
	for i := 0; i < maxPreviewCandidates*3; i++ {
		router.extra = append(router.extra, previewProvider{
			Address:     fmt.Sprintf("0xC0FFEE%035X", i+2),
			CanonicalID: "canon-x",
			Endpoint:    broker.srv.URL,
			ModelID:     "gpt-4o@v1",
		})
	}

	cands, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := cands.Len(); got != maxPreviewCandidates {
		t.Errorf("candidate chain length = %d, want %d — the walk's length must be ours, not the router's",
			got, maxPreviewCandidates)
	}
}

// A cancellation may only re-attribute a RETRYABLE attempt. previewBroken is the
// router answering with a body that will not decode — the constant defines it as the
// router misbehaving — and previewInternal is our own fault; relabelling either
// "canceled" hides it in the bucket every alert deliberately ignores. Same bug the
// verifyOutcome allowlist fixed, in the other file.
func TestPreviewBrokenSurvivesALateCancellation(t *testing.T) {
	const (
		attemptsBroken   = `zg_gateway_preview_attempts_total{result="broken"}`
		attemptsCanceled = `zg_gateway_preview_attempts_total{result="canceled"}`
		callsFailed      = `zg_gateway_preview_calls_total{outcome="failed"}`
		callsCanceled    = `zg_gateway_preview_calls_total{outcome="canceled"}`
	)
	series := []string{attemptsBroken, attemptsCanceled, callsFailed, callsCanceled}
	before := map[string]float64{}
	for _, s := range series {
		before[s] = metricValue(t, s)
	}

	// A 200 whose body will not decode: previewBroken.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providers": not-json`))
	}))
	defer srv.Close()

	// The caller is already gone by the time the loop classifies the failure — the
	// same shape as the late-cancellation test above, so the race need not be won.
	var canceled atomic.Bool
	canceled.Store(true)
	ctx := lateCancelCtx{Context: context.Background(), done: make(chan struct{}), canceled: &canceled}

	if _, err := New(srv.URL).preview(ctx, chatReq()); err == nil {
		t.Fatal("want an error from an undecodable preview body")
	}

	if got := metricValue(t, attemptsBroken) - before[attemptsBroken]; got != 1 {
		t.Errorf("%s delta = %v, want 1", attemptsBroken, got)
	}
	if got := metricValue(t, attemptsCanceled) - before[attemptsCanceled]; got != 0 {
		t.Errorf("the router misbehaving was relabelled canceled; %s delta = %v, want 0", attemptsCanceled, got)
	}
	if got := metricValue(t, callsFailed) - before[callsFailed]; got != 1 {
		t.Errorf("%s delta = %v, want 1", callsFailed, got)
	}
	if got := metricValue(t, callsCanceled) - before[callsCanceled]; got != 0 {
		t.Errorf("%s delta = %v, want 0", callsCanceled, got)
	}
}

// The gate must not be reopened by a definitive rejection. During a router-layer
// outage a load balancer commonly mixes 404s and 403s in with the 502s; resetting on
// those put the 502 requests back to full amplification and back to holding a
// LimitInFlight slot for the whole ceiling — the gateway-level cascade this gate
// exists to prevent. Only a preview that SUCCEEDED is evidence retries are worth
// making again.
func TestRetryGateNotReopenedByARejection(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.previewFailN = 1 << 20 // 503s forever
	r := New(router.srv.URL)
	for i := 0; i < previewRetryTripAfter; i++ {
		_, _ = r.Resolve(context.Background(), chatReq())
	}
	if r.previewRetries.allow() {
		t.Fatal("the gate should be shut after consecutive answerless calls")
	}

	// The LB now answers some requests definitively (a 401). This must not reopen it.
	router.previewFailCode = http.StatusUnauthorized
	if _, err := r.Resolve(context.Background(), chatReq()); err == nil {
		t.Fatal("want an error from a 401 router")
	}
	if r.previewRetries.allow() {
		t.Error("a definitive rejection reopened the gate; the 502 traffic goes back to 3x amplification")
	}

	// A success does reopen it — that is the one signal that retries are useful.
	router.previewFailN = 0
	if _, err := r.Resolve(context.Background(), chatReq()); err != nil {
		t.Fatalf("Resolve after recovery: %v", err)
	}
	if !r.previewRetries.allow() {
		t.Error("a successful preview must reopen the gate")
	}
}
