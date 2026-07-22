package route

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

const testSigner = "0xd45b4301940B297F76d6e622c1CeA2AE660617d4"

// mockBroker serves both control-plane and data-plane provider endpoints: the
// e2ee pubkey API and the sealed chat-completions API. It fails the test if the
// prompt ever arrives in cleartext, and counts pubkey hits so caching can be
// asserted.
type mockBroker struct {
	srv        *httptest.Server
	encPub     crypto.PublicKey
	pubkeyHits int32
}

func newMockBroker(t *testing.T) *mockBroker {
	t.Helper()
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}
	b := &mockBroker{encPub: encPub}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/e2ee/pubkey", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&b.pubkeyHits, 1)
		_ = json.NewEncoder(w).Encode(pubkeyResponse{
			V:             wire.Version,
			KEMID:         wire.KEMID,
			EncPub:        base64.RawURLEncoding.EncodeToString(encPub),
			KeyID:         "8RpY-WKSX_U",
			SignerAddress: testSigner,
		})
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
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
		if e2ee.ProviderID != testSigner {
			http.Error(w, "wrong provider pin", http.StatusBadRequest)
			return
		}
		if _, err := wire.OpenRequest(encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-route"`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"routed answer"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	})
	b.srv = httptest.NewServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

// mockRouter serves the route-preview API, pointing every request at the given
// broker endpoint. It records the last preview body so a test can assert what
// the gateway forwarded (and did not).
type mockRouter struct {
	srv         *httptest.Server
	lastPreview map[string]json.RawMessage
	lastAuth    string
	status      int // override response status; 0 = 200
	noProviders bool
}

func newMockRouter(t *testing.T, brokerEndpoint string) *mockRouter {
	t.Helper()
	m := &mockRouter{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &m.lastPreview)
		m.lastAuth = r.Header.Get("Authorization")
		if m.status != 0 {
			http.Error(w, "boom", m.status)
			return
		}
		providers := []previewProvider{{
			Address:     testSigner,
			CanonicalID: "canon-1",
			Endpoint:    brokerEndpoint,
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
	}))
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
	router := newMockRouter(t, broker.srv.URL)

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
}

func TestResolveProvider(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker.srv.URL)

	p, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.SignerAddr != testSigner {
		t.Errorf("signer = %q, want %q", p.SignerAddr, testSigner)
	}
	if want := broker.srv.URL + "/v1/chat/completions"; p.URL != want {
		t.Errorf("URL = %q, want %q", p.URL, want)
	}
	if len(p.EncPubKey) != x25519PubLen {
		t.Errorf("enc key len = %d, want %d", len(p.EncPubKey), x25519PubLen)
	}
}

func TestResolveCachesPubkey(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker.srv.URL)
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
	router := newMockRouter(t, broker.srv.URL)
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
	router := newMockRouter(t, broker.srv.URL)

	req := wire.Request{"messages": json.RawMessage(`[]`)}
	_, err := New(router.srv.URL).Resolve(context.Background(), req)
	assertStageStatus(t, err, core.StageRequest, 0)
}

func TestResolveSurfacesPreviewStatus(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker.srv.URL)
	router.status = http.StatusUnauthorized

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	assertStageStatus(t, err, core.StageUpstream, http.StatusUnauthorized)
}

func TestResolveNoProvidersIs503(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker.srv.URL)
	router.noProviders = true

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	assertStageStatus(t, err, core.StageUpstream, http.StatusServiceUnavailable)
}

func TestResolveRejectsAddressMismatch(t *testing.T) {
	broker := newMockBroker(t)
	// Router claims a different provider than the broker signs as.
	router := newMockRouter(t, broker.srv.URL)
	router.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(previewResponse{
			Providers: []previewProvider{{
				Address:  "0x" + strings.Repeat("b", 40),
				Endpoint: broker.srv.URL,
			}},
		})
	})

	_, err := New(router.srv.URL).Resolve(context.Background(), chatReq())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want address-mismatch error, got %v", err)
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

func TestDeriveURLs(t *testing.T) {
	cases := []struct {
		endpoint, completions, pubkey string
	}{
		{"https://host", "https://host/v1/chat/completions", "https://host/v1/e2ee/pubkey"},
		{"https://host:8443/", "https://host:8443/v1/chat/completions", "https://host:8443/v1/e2ee/pubkey"},
		{"https://host/v1", "https://host/v1/chat/completions", "https://host/v1/e2ee/pubkey"},
		{"https://host/v1/chat/completions", "https://host/v1/chat/completions", "https://host/v1/e2ee/pubkey"},
	}
	for _, c := range cases {
		comp, pub, err := deriveURLs(c.endpoint)
		if err != nil {
			t.Errorf("%s: %v", c.endpoint, err)
			continue
		}
		if comp != c.completions {
			t.Errorf("%s: completions = %q, want %q", c.endpoint, comp, c.completions)
		}
		if pub != c.pubkey {
			t.Errorf("%s: pubkey = %q, want %q", c.endpoint, pub, c.pubkey)
		}
	}
	for _, bad := range []string{"", "not a url", "/relative/only", "host-no-scheme.com/v1"} {
		if _, _, err := deriveURLs(bad); err == nil {
			t.Errorf("deriveURLs(%q): expected error", bad)
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
