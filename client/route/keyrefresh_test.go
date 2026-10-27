package route

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// rotatedReportData is report_data naming encPub, so a test can model a broker
// whose live quote carries a key other than the one cached.
func rotatedReportData(t *testing.T, encPub []byte) [64]byte {
	t.Helper()
	var rd [64]byte
	copy(rd[0:32], encPub)
	copy(rd[32:52], mustHex(t, qvSignerHex))
	rd[55] = 1
	return rd
}

// refresherFor resolves the one-candidate preview against a router whose quote
// cache holds cached, and returns the candidate list as a core.KeyRefresher.
func refresherFor(t *testing.T, r *Router, endpointURL string, cached []byte) core.KeyRefresher {
	t.Helper()
	quoteURL, err := deriveQuoteURL(endpointURL)
	if err != nil {
		t.Fatalf("deriveQuoteURL: %v", err)
	}
	r.quoteCache.put(quoteURL, quoteResult{encPub: cached, signer: qvSignerStr})
	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	kr, ok := cands.(core.KeyRefresher)
	if !ok {
		t.Fatal("route candidates must implement core.KeyRefresher")
	}
	return kr
}

// The provider rejected the key our cache still holds: the refresh must look past
// the cache and come back with what the live, verified quote says.
func TestRefreshProvider_ReverifiesPastAStaleCacheEntry(t *testing.T) {
	var quoteHits int32
	srv := rotatingQuoteServer(t, &quoteHits)
	live := mustHex(t, qvEncPubHex)
	rd := rotatedReportData(t, live)
	r := New(srv.URL, WithQuoteVerification(rotatingVerifier(t, qvMeasurement(0xaa), &rd), discardLogger()))

	stale := bytes.Repeat([]byte{0x11}, 32)
	kr := refresherFor(t, r, srv.URL, stale)

	prov, err := kr.RefreshProvider(context.Background(), 0, stale)
	if err != nil {
		t.Fatalf("RefreshProvider: %v", err)
	}
	if !bytes.Equal(prov.EncPubKey, live) {
		t.Errorf("EncPubKey = %x, want the live quote's %x", prov.EncPubKey, live)
	}
	if got := atomic.LoadInt32(&quoteHits); got != 1 {
		t.Errorf("quote fetches = %d, want 1", got)
	}
}

// Requests that raced one rotation all come back with the same stale key. The first
// refresh re-verifies; the rest find a different key already cached and must use
// it rather than verifying again.
func TestRefreshProvider_UsesAKeyAnotherRequestAlreadyRefreshed(t *testing.T) {
	var quoteHits int32
	srv := rotatingQuoteServer(t, &quoteHits)
	live := mustHex(t, qvEncPubHex)
	rd := rotatedReportData(t, live)
	r := New(srv.URL, WithQuoteVerification(rotatingVerifier(t, qvMeasurement(0xaa), &rd), discardLogger()))

	kr := refresherFor(t, r, srv.URL, live)
	prov, err := kr.RefreshProvider(context.Background(), 0, bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatalf("RefreshProvider: %v", err)
	}
	if !bytes.Equal(prov.EncPubKey, live) {
		t.Errorf("EncPubKey = %x, want the cached %x", prov.EncPubKey, live)
	}
	if got := atomic.LoadInt32(&quoteHits); got != 0 {
		t.Errorf("quote fetches = %d, want 0", got)
	}
}

// The trigger is a 409 the untrusted router can forge. The forced re-verification
// shares reverifiedProvider's once-per-TTL throttle, so replayed 409s cannot turn
// every request into a live DCAP verification; a throttled refresh fails, and the
// client falls back.
func TestRefreshProvider_IsThrottled(t *testing.T) {
	var quoteHits int32
	srv := rotatingQuoteServer(t, &quoteHits)
	stale := mustHex(t, qvEncPubHex)
	rd := rotatedReportData(t, stale) // the live quote still names the "rejected" key
	r := New(srv.URL, WithQuoteVerification(rotatingVerifier(t, qvMeasurement(0xaa), &rd), discardLogger()))

	kr := refresherFor(t, r, srv.URL, stale)
	if _, err := kr.RefreshProvider(context.Background(), 0, stale); err != nil {
		t.Fatalf("first RefreshProvider: %v", err)
	}
	if _, err := kr.RefreshProvider(context.Background(), 0, stale); err == nil {
		t.Fatal("a second forced re-verification within the TTL must be refused")
	}
	if got := atomic.LoadInt32(&quoteHits); got != 1 {
		t.Errorf("quote fetches = %d, want 1", got)
	}
}

// The legacy pubkey path: a cached key the provider rejected is dropped and fetched
// again; a cached key that differs from the rejected one is kept.
func TestRefreshProvider_PubkeyPath(t *testing.T) {
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	r := New(router.srv.URL)

	cands, err := r.Resolve(context.Background(), endpoint.Chat, chatReq())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err != nil {
		t.Fatalf("Provider: %v", err)
	}
	kr := cands.(core.KeyRefresher)

	other, err := otherKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.RefreshProvider(context.Background(), 0, other); err != nil {
		t.Fatalf("RefreshProvider (different key cached): %v", err)
	}
	if hits := atomic.LoadInt32(&broker.pubkeyHits); hits != 1 {
		t.Fatalf("pubkey fetched %d times, want 1 — the cached key was not the rejected one", hits)
	}
	if _, err := kr.RefreshProvider(context.Background(), 0, broker.encPub); err != nil {
		t.Fatalf("RefreshProvider (rejected key cached): %v", err)
	}
	if hits := atomic.LoadInt32(&broker.pubkeyHits); hits != 2 {
		t.Fatalf("pubkey fetched %d times, want 2 — the rejected key must be fetched again", hits)
	}
}

// Direct-broker mode refreshes the same way.
func TestRefreshProvider_Direct(t *testing.T) {
	broker := newMockBroker(t)
	res, err := NewDirect(broker.srv.URL)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	cands, err := res.Resolve(context.Background(), endpoint.Chat, chatReq())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err != nil {
		t.Fatalf("Provider: %v", err)
	}
	if _, err := cands.(core.KeyRefresher).RefreshProvider(context.Background(), 0, broker.encPub); err != nil {
		t.Fatalf("RefreshProvider: %v", err)
	}
	if hits := atomic.LoadInt32(&broker.pubkeyHits); hits != 2 {
		t.Fatalf("pubkey fetched %d times, want 2", hits)
	}
}

func otherKey() (crypto.PublicKey, error) {
	_, pub, err := crypto.GenerateRecipientKey()
	return pub, err
}

// A broker rollout under steady traffic: many requests sealed to the old key are
// rejected while the first refresh's live verification is still running. They must
// join that verification, not be turned away by the throttle it already stamped —
// with a single candidate, a request turned away fails outright.
func TestRefreshProvider_ConcurrentRejectionsShareOneVerification(t *testing.T) {
	const n = 8
	var quoteHits int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	srv := countingQVServer(t, &quoteHits, entered, release)
	t.Cleanup(unblock) // registered after the server, so it runs before srv.Close
	live := mustHex(t, qvEncPubHex)
	rd := rotatedReportData(t, live)
	r := New(srv.URL, WithQuoteVerification(rotatingVerifier(t, qvMeasurement(0xaa), &rd), discardLogger()))

	stale := bytes.Repeat([]byte{0x11}, 32)
	kr := refresherFor(t, r, srv.URL, stale)

	type result struct {
		key []byte
		err error
	}
	results := make(chan result, n)
	refresh := func() {
		p, err := kr.RefreshProvider(context.Background(), 0, stale)
		results <- result{p.EncPubKey, err}
	}
	go refresh()
	<-entered // the leader's live verification is in flight, the cache still stale
	for i := 1; i < n; i++ {
		go refresh()
	}
	// Turned-away callers return at once; joiners wait for the leader.
	select {
	case res := <-results:
		t.Fatalf("a refresh returned while the verification was still running: err=%v", res.err)
	case <-time.After(100 * time.Millisecond):
	}
	unblock()

	for i := 0; i < n; i++ {
		res := <-results
		if res.err != nil {
			t.Errorf("refresh %d: %v", i, res.err)
			continue
		}
		if !bytes.Equal(res.key, live) {
			t.Errorf("refresh %d: key = %x, want %x", i, res.key, live)
		}
	}
	if got := atomic.LoadInt32(&quoteHits); got != 1 {
		t.Errorf("quote fetches = %d, want 1", got)
	}
}
