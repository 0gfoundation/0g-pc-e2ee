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
	status          int    // override preview response status; 0 = 200
	noProviders     bool   // preview returns no providers
	previewAddress  string // provider address in preview (default testSigner)
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
		if m.noProviders {
			providers = nil
		}
		_ = json.NewEncoder(w).Encode(previewResponse{
			Object:    "routing.preview",
			Type:      "chat",
			Providers: providers,
		})
	})

	// Data plane: the sealed request is POSTed here (to the router), which auths
	// and forwards to the pinned provider — the mock opens it with the broker's
	// key and seals a canned answer back.
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		m.lastChatHeaders = r.Header.Clone()
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
		if got := r.Header.Get("X-0G-Provider-Address"); got != testProviderAddr {
			t.Errorf("routing pin header = %q, want provider address %q", got, testProviderAddr)
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
	if typ := string(router.lastPreview["type"]); typ != `"chat"` {
		t.Errorf("preview type = %s, want \"chat\"", typ)
	}
	if router.lastAuth != "Bearer sk-test" {
		t.Errorf("credential not forwarded to router: %q", router.lastAuth)
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

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	assertStageStatus(t, err, core.StageUpstream, http.StatusNotFound)
}

func TestResolvePubkeyMalformed(t *testing.T) {
	broker := newMockBroker(t)
	broker.pubkeyRaw = "not json at all"
	router := newMockRouter(t, broker)

	// A decode failure is an upstream error with no meaningful status (→ 502).
	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	assertStageStatus(t, err, core.StageUpstream, 0)
}

func TestResolveProvider(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)

	p, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.SignerAddr != testSigner {
		t.Errorf("signer = %q, want %q", p.SignerAddr, testSigner)
	}
	if p.Address != testProviderAddr {
		t.Errorf("address = %q, want %q", p.Address, testProviderAddr)
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
		if _, err := r.Resolve(context.Background(), chatReq()); err != nil {
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
		if _, err := r.Resolve(context.Background(), chatReq()); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if hits := atomic.LoadInt32(&broker.pubkeyHits); hits != 2 {
		t.Fatalf("pubkey fetched %d times, want 2 (cache disabled)", hits)
	}
}

func TestResolveNoModelIsBadRequest(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)

	req := wire.Request{"messages": json.RawMessage(`[]`)}
	_, err := New(router.srv.URL).Resolve(context.Background(), req)
	assertStageStatus(t, err, core.StageRequest, 0)
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

// A provider with no address can't be pinned, so the router could re-route the
// sealed request to a provider that can't decrypt it — reject up front.
func TestResolveRejectsMissingAddress(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	router.previewAddress = "" // preview returns a provider with no address

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	if err == nil || !strings.Contains(err.Error(), "no address") {
		t.Fatalf("want missing-address error, got %v", err)
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
