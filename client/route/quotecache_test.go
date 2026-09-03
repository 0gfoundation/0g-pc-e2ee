package route

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// qvVerifier is a verifier that accepts the fixed fake quote (measurement 0xaa,
// allowlisted → MeasurementTrusted, no warn log).
func qvVerifier(t *testing.T) *attest.Verifier {
	t.Helper()
	m := qvMeasurement(0xaa)
	return attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(m)}},
		attest.WithQuoteParser(qvParser(m, qvReportData(t))))
}

// countingQVServer serves the preview + /v1/quote, counting quote fetches. If
// block is non-nil, the quote handler waits on it (after signaling entered on
// the first entry) so a test can hold a verification in-flight.
func countingQVServer(t *testing.T, hits *int32, entered chan<- struct{}, block <-chan struct{}) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(previewResponse{
			Object:      "routing.preview",
			ServiceType: "chatbot",
			Providers: []previewProvider{{
				Address: testProviderAddr, CanonicalID: "canon-1", Endpoint: srv.URL, ModelID: "m",
			}},
		})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(hits, 1) == 1 && entered != nil {
			entered <- struct{}{}
		}
		if block != nil {
			<-block
		}
		_, _ = w.Write([]byte(`{"quote":"00"}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func qvResolveHead(t *testing.T, r *Router) error {
	t.Helper()
	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		return err
	}
	_, err = cands.Provider(context.Background(), 0)
	return err
}

func TestQuoteCache_HitAvoidsRefetch(t *testing.T) {
	var hits int32
	srv := countingQVServer(t, &hits, nil, nil)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), nil))

	for i := 0; i < 3; i++ {
		if err := qvResolveHead(t, r); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("quote fetched %d times, want 1 (subsequent requests hit the cache)", got)
	}
}

func TestQuoteCache_DisabledRefetchesEachTime(t *testing.T) {
	var hits int32
	srv := countingQVServer(t, &hits, nil, nil)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), nil), WithQuoteTTL(0))

	for i := 0; i < 3; i++ {
		if err := qvResolveHead(t, r); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("quote fetched %d times, want 3 (caching disabled)", got)
	}
}

func TestQuoteCache_SingleflightCollapsesConcurrentMisses(t *testing.T) {
	var hits int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := countingQVServer(t, &hits, entered, release)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), nil))

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = qvResolveHead(t, r)
		}(i)
	}

	// Leader is now inside the quote handler (blocked on release); give the
	// followers time to queue on singleflight, then let the leader finish. The
	// leader stays blocked until we close release, so all followers join the same
	// in-flight verification rather than starting their own.
	<-entered
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d: %v", i, e)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("quote fetched %d times, want 1 (singleflight should collapse concurrent misses)", got)
	}
}

// TestQuoteCache_CallerCancelDoesNotPoisonOthers verifies the DoChan fix: one
// coalesced caller cancelling its context must return promptly for THAT caller
// without failing the shared verification for the others.
func TestQuoteCache_CallerCancelDoesNotPoisonOthers(t *testing.T) {
	var hits int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := countingQVServer(t, &hits, entered, release)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), nil))

	type result struct {
		enc crypto.PublicKey
		err error
	}
	// Caller A leads the verification (it enters the blocked quote handler first).
	ctxA, cancelA := context.WithCancel(context.Background())
	aCh := make(chan result, 1)
	go func() {
		enc, _, err := r.verifiedKeys(ctxA, srv.URL)
		aCh <- result{enc, err}
	}()
	<-entered // A is now in-flight (handler blocked on release)

	// Caller B (independent, live context) coalesces onto the same verification.
	bCh := make(chan result, 1)
	go func() {
		enc, _, err := r.verifiedKeys(context.Background(), srv.URL)
		bCh <- result{enc, err}
	}()
	time.Sleep(50 * time.Millisecond) // let B join the in-flight Do

	// Cancel A: it must return promptly with an error, WITHOUT releasing the
	// handler — the shared verification is still blocked.
	cancelA()
	select {
	case a := <-aCh:
		if a.err == nil {
			t.Error("caller A: want cancellation error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller A did not return on its own context cancellation (poisoned by shared work)")
	}

	// A's cancellation must NOT have killed the shared verification: release it and
	// B must still succeed with the genuine keys.
	close(release)
	select {
	case b := <-bCh:
		if b.err != nil {
			t.Fatalf("caller B failed after A cancelled: %v", b.err)
		}
		if hex.EncodeToString(b.enc) != qvEncPubHex {
			t.Errorf("caller B enc_pub = %x, want %s", b.enc, qvEncPubHex)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller B did not complete (shared work was killed by A's cancel)")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("quote fetched %d times, want 1", got)
	}
}
