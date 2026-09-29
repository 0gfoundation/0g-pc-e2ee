package core_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/sig"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// rotatedProvider is a provider whose enclave rotated its enc key: a request
// sealed to any key but current gets the broker's 409 e2ee_key_mismatch, the
// rest is served by fakeProvider.
type rotatedProvider struct {
	mu      sync.Mutex
	current crypto.PublicKey
	posts   int
	next    http.Handler
}

func keyIDOf(pub crypto.PublicKey) string {
	h := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(h[:8])
}

func (p *rotatedProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		p.next.ServeHTTP(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var env struct {
		E2EE struct {
			KeyID string `json:"key_id"`
		} `json:"_e2ee"`
	}
	_ = json.Unmarshal(body, &env)
	p.mu.Lock()
	p.posts++
	want := keyIDOf(p.current)
	p.mu.Unlock()
	if env.E2EE.KeyID != want {
		// The broker's exact shape (errors.Response over ctrl.ErrE2EEKeyMismatch).
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "e2ee_key_mismatch: sealed request key_id \"" +
			env.E2EE.KeyID + "\" is not the enclave's current enc key (current \"" + want + "\"); re-fetch the enc key and re-seal"})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	p.next.ServeHTTP(w, r)
}

// cachedCandidates is one candidate whose cached key is stale; refreshing
// yields fresh (a KeyRefresher).
type cachedCandidates struct {
	prov      core.Provider
	fresh     crypto.PublicKey
	refreshes int
}

func (c *cachedCandidates) Len() int { return 1 }
func (c *cachedCandidates) Provider(context.Context, int) (core.Provider, error) {
	return c.prov, nil
}
func (c *cachedCandidates) RefreshProvider(_ context.Context, _ int, stale core.Provider) (core.Provider, error) {
	c.refreshes++
	if !bytes.Equal(stale.EncPubKey, c.prov.EncPubKey) {
		return core.Provider{}, errors.New("refreshed with the wrong stale key")
	}
	c.prov.EncPubKey = c.fresh
	return c.prov, nil
}

type fixedRes struct{ c core.Candidates }

func (f fixedRes) Resolve(context.Context, endpoint.Endpoint, wire.Request) (core.Candidates, error) {
	return f.c, nil
}

func newKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// setup returns a provider that rotated to current, and candidates that cache
// stale and refresh to fresh.
func setup(t *testing.T, current, fresh crypto.PublicKey) (*rotatedProvider, *cachedCandidates, *core.Client) {
	signer := newE2ESigner(t)
	rp := &rotatedProvider{current: current, next: newFakeProvider(signer).handler()}
	srv := httptest.NewServer(rp)
	t.Cleanup(srv.Close)
	cands := &cachedCandidates{
		prov:  core.Provider{URL: srv.URL + "/v1/chat/completions", Endpoint: srv.URL, EncPubKey: newKey(t), SignerAddr: signer.addr},
		fresh: fresh,
	}
	c := core.NewWithResolver(fixedRes{cands}, core.WithResponseVerification(httpFetcher{hc: srv.Client()}, sig.Recover))
	return rp, cands, c
}

func run(c *core.Client, stream bool) error {
	if stream {
		return c.CompleteStream(context.Background(), chatReq(true), func(wire.Response) error { return nil })
	}
	_, err := c.Complete(context.Background(), chatReq(false))
	return err
}

// A rotated key costs one refresh and one retry, and the request succeeds.
func TestKeyMismatchRefreshesOnceAndRetries(t *testing.T) {
	for _, stream := range []bool{false, true} {
		current := newKey(t)
		rp, cands, c := setup(t, current, current)
		if err := run(c, stream); err != nil {
			t.Fatalf("stream=%v: want success after refresh, got %v", stream, err)
		}
		if cands.refreshes != 1 || rp.posts != 2 {
			t.Fatalf("stream=%v: refreshes=%d posts=%d, want 1 and 2", stream, cands.refreshes, rp.posts)
		}
	}
}

// A refreshed key that is refused again surfaces the 409; it does not loop.
func TestKeyMismatchAfterRefreshDoesNotLoop(t *testing.T) {
	for _, stream := range []bool{false, true} {
		rp, cands, c := setup(t, newKey(t), newKey(t))
		err := run(c, stream)
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Status != http.StatusConflict {
			t.Fatalf("stream=%v: want the 409 surfaced, got %v", stream, err)
		}
		if cands.refreshes != 1 || rp.posts != 2 {
			t.Fatalf("stream=%v: refreshes=%d posts=%d, want 1 and 2", stream, cands.refreshes, rp.posts)
		}
	}
}

// A refresh that returns the same key is not retried: it would be refused alike.
func TestKeyMismatchUnchangedKeyIsNotRetried(t *testing.T) {
	rp, cands, c := setup(t, newKey(t), nil)
	cands.fresh = cands.prov.EncPubKey
	if err := run(c, false); err == nil {
		t.Fatal("want the 409 surfaced")
	}
	if cands.refreshes != 1 || rp.posts != 1 {
		t.Fatalf("refreshes=%d posts=%d, want 1 and 1", cands.refreshes, rp.posts)
	}
}
