package openaiproxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// The provider address the client resolves and pins, versus the one a dishonest
// router reports having served. The whole point of the header change is that the
// user sees the former.
const (
	pinnedProvider = "0x1111111111111111111111111111111111111111"
	routerClaim    = "0x2222222222222222222222222222222222222222"
)

// A router that forwards the request to the pinned provider exactly as asked, and
// then names a DIFFERENT address on the way back, must not get its claim in front
// of the user. Nothing else in the chain would catch this: the routing was never
// changed, so the seal opens and any signature still verifies.
func TestProxy_ProviderHeaderIsThePinNotTheRouterClaim(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("provider keygen: %v", err)
	}
	signer := "0x" + strings.Repeat("a", 40)

	// mockBroker answers honestly; wrap it so the reply also carries the router's
	// false X-Provider, which is where the header used to come from.
	honest := mockBroker(t, encPriv, signer)
	defer honest.Close()
	lying := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		honest.Config.Handler.ServeHTTP(rec, r)
		for k, vs := range rec.Header() {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("X-Provider", routerClaim)
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	defer lying.Close()

	client := core.New(core.Provider{
		URL: lying.URL, EncPubKey: encPub, SignerAddr: signer, Address: pinnedProvider,
	})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"the secret prompt"}]}`
	resp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy returned %d: %s", resp.StatusCode, body)
	}

	got := resp.Header.Values("X-Provider")
	if len(got) != 1 || got[0] != pinnedProvider {
		t.Errorf("X-Provider = %v, want exactly [%s] (the pin, not the router's %s)",
			got, pinnedProvider, routerClaim)
	}
}

// The same must hold on the streaming path, where headers are flushed before the
// first frame. It works because the claim — "we sealed this to X and pinned the
// route to X" — is settled at stream commit, unlike a §8-verified claim, which
// could not be made until after the final frame.
func TestProxy_ProviderHeaderOnStreamingPath(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("c", 40)
	broker := mockStreamingBroker(t, encPriv, signer, []string{`{"content":"the secret prompt"}`})
	defer broker.Close()

	client := core.New(core.Provider{
		URL: broker.URL, EncPubKey: encPub, SignerAddr: signer, Address: pinnedProvider,
	})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"the secret prompt"}]}`
	resp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream: got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Provider"); got != pinnedProvider {
		t.Errorf("X-Provider = %q, want the pinned %s", got, pinnedProvider)
	}
	_, _ = io.ReadAll(resp.Body)
}

// On a failed request no provider served anything, so there is no address to
// report — and the router's claim must not fill the gap. The rate-limit headers
// beside it still come through, which is what makes this a real check rather than
// a test of an empty passthrough.
func TestProxy_NoProviderHeaderOnErrorPath(t *testing.T) {
	_, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)

	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Provider", routerClaim)
		w.Header().Set("Retry-After", "42")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer broker.Close()

	client := core.New(core.Provider{
		URL: broker.URL, EncPubKey: encPub, SignerAddr: signer, Address: pinnedProvider,
	})
	proxy := httptest.NewServer(openaiproxy.Handler(client))
	defer proxy.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"the secret prompt"}]}`
	resp, err := http.Post(proxy.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post to proxy: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if got := resp.Header.Get("X-Provider"); got != "" {
		t.Errorf("X-Provider = %q on a failed request, want absent", got)
	}
	if got := resp.Header.Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q, want 42 — the rest of the error passthrough must still work", got)
	}
}
