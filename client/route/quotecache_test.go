package route

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// qvVerifier is a verifier that accepts the fixed fake quote (measurement 0xaa,
// allowlisted → MeasurementTrusted, no warn log).
func qvVerifier(t *testing.T) *attest.Verifier {
	t.Helper()
	m := qvMeasurement(0xaa)
	return attest.New(attest.Policy{Allowed: []attest.Measurement{m}},
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
	cands, err := r.Resolve(context.Background(), wire.Request{})
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
