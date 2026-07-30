package route

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeResolver resolves every provider address to one endpoint URL.
type fakeResolver struct{ url string }

func (f fakeResolver) ServiceInfo(context.Context, string) (chain.ServiceInfo, error) {
	return chain.ServiceInfo{URL: f.url, Signer: qvSignerStr, Acknowledged: true}, nil
}

// countingRegistry counts AcknowledgedSigner calls (to check grounding warming).
type countingRegistry struct {
	n      int32
	signer string
	ack    bool
}

func (c *countingRegistry) AcknowledgedSigner(context.Context, string) (string, bool, error) {
	atomic.AddInt32(&c.n, 1)
	return c.signer, c.ack, nil
}

// warmerServer serves /v1/providers (the given addresses) and /v1/quote (counted
// in hits; status != 0 makes it fail).
func warmerServer(t *testing.T, hits *int32, addrs []string, status *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/providers", func(w http.ResponseWriter, r *http.Request) {
		type entry struct {
			Address string `json:"address"`
		}
		data := make([]entry, 0, len(addrs))
		for _, a := range addrs {
			data = append(data, entry{Address: a})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if s := int(atomic.LoadInt32(status)); s != 0 {
			http.Error(w, "boom", s)
			return
		}
		_, _ = w.Write([]byte(`{"quote":"00"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestWarmer_ListProviderAddrs(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa", "0xb"}, &status)
	addrs, err := New(srv.URL).listProviderAddrs(context.Background())
	if err != nil {
		t.Fatalf("listProviderAddrs: %v", err)
	}
	if len(addrs) != 2 || addrs[0] != "0xa" || addrs[1] != "0xb" {
		t.Errorf("addrs = %v, want [0xa 0xb]", addrs)
	}
}

func TestWarmer_WarmThenServeFromCacheThenRefresh(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()))
	res := fakeResolver{url: srv.URL}

	// Warm: one verification.
	r.WarmOnce(context.Background(), res)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("after warm: hits = %d, want 1", got)
	}
	// A request-path lookup now hits the warm cache — no new fetch.
	if _, _, err := r.verifiedKeys(context.Background(), srv.URL); err != nil {
		t.Fatalf("verifiedKeys: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("request should hit warm cache: hits = %d, want 1", got)
	}
	// Refresh-ahead forces a re-verification (must NOT be a cache hit).
	r.WarmOnce(context.Background(), res)
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("refresh should re-verify: hits = %d, want 2", got)
	}
}

func TestWarmer_EvictsOnRefreshFailure(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()))
	res := fakeResolver{url: srv.URL}

	r.WarmOnce(context.Background(), res) // success → cached
	quoteURL, err := deriveQuoteURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.quoteCache.get(quoteURL); !ok {
		t.Fatal("expected a warm cache entry")
	}

	atomic.StoreInt32(&status, http.StatusServiceUnavailable) // quote now fails
	r.WarmOnce(context.Background(), res)                     // refresh fails → evict
	if _, _, ok := r.quoteCache.get(quoteURL); ok {
		t.Error("stale entry should be evicted after a failed refresh")
	}
}

func TestWarmer_WarmsGroundingCache(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	reg := &countingRegistry{signer: qvSignerStr, ack: true}
	r := New(srv.URL,
		WithQuoteVerification(qvVerifier(t), discardLogger()),
		WithOnChainVerification(reg, false, discardLogger()))

	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	if got := atomic.LoadInt32(&reg.n); got != 1 {
		t.Errorf("grounding warm calls = %d, want 1", got)
	}
}

func TestWarmer_RunWarmerStopsOnCancel(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.RunWarmer(ctx, time.Hour, fakeResolver{url: srv.URL})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunWarmer did not return after context cancellation")
	}
}

func TestWarmer_NoopWithoutVerifier(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	// No WithQuoteVerification → warmer is a no-op.
	New(srv.URL).WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("warmer without verifier should be a no-op: hits = %d, want 0", got)
	}
}
