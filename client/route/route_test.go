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
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &m.lastPreview)
		m.lastAuth = r.Header.Get("Authorization")
		m.lastHeaders = r.Header.Clone()
		if m.status != 0 {
			http.Error(w, "boom", m.status)
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

// A candidate with no address can't be pinned, so the router could re-route the
// sealed request to a provider that can't decrypt it — materializing it fails so
// core skips it.
func TestResolveRejectsMissingAddress(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.previewAddress = "" // preview returns a head candidate with no address

	_, err := resolveHead(context.Background(), New(router.srv.URL), chatReq())
	if err == nil || !strings.Contains(err.Error(), "no address") {
		t.Fatalf("want missing-address error, got %v", err)
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
