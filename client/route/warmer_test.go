package route

import (
	"context"
	"encoding/json"
	"errors"
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

// countingRegistry counts lookups, split by whether they went through the cache
// (AcknowledgedSigner) or forced a live read (RefreshSigner) — the warmer must do
// the latter, or a still-fresh entry would satisfy it and nothing gets warmed.
type countingRegistry struct {
	n         int32
	refreshes int32
	signer    string
	ack       bool
	// failing, when set, makes every lookup fail — the shape of an unreachable chain
	// RPC, which a sweep must not count as a prepared provider.
	failing atomic.Bool
}

func (c *countingRegistry) AcknowledgedSigner(context.Context, string) (chain.Signer, error) {
	atomic.AddInt32(&c.n, 1)
	if c.failing.Load() {
		return chain.Signer{}, errors.New("rpc down")
	}
	return chain.Signer{Address: c.signer, Acknowledged: c.ack}, nil
}

func (c *countingRegistry) RefreshSigner(ctx context.Context, providerAddr string) (chain.Signer, error) {
	atomic.AddInt32(&c.refreshes, 1)
	return c.AcknowledgedSigner(ctx, providerAddr)
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

func TestWarmer_ListProviderAddrsDedup(t *testing.T) {
	var hits, status int32
	// A provider serving several models appears once per model — the same address
	// repeated, in mixed casing. listProviderAddrs must collapse those to one,
	// case-insensitively, keeping first-seen order and the original casing.
	srv := warmerServer(t, &hits, []string{"0xa", "0xB", "0xa", "0xc", "0xA", "0xb"}, &status)
	addrs, err := New(srv.URL).listProviderAddrs(context.Background())
	if err != nil {
		t.Fatalf("listProviderAddrs: %v", err)
	}
	want := []string{"0xa", "0xB", "0xc"}
	if len(addrs) != len(want) {
		t.Fatalf("addrs = %v, want %v", addrs, want)
	}
	for i := range want {
		if addrs[i] != want[i] {
			t.Errorf("addrs[%d] = %q, want %q (full: %v)", i, addrs[i], want[i], addrs)
		}
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

// A provider counts as prepared only when the whole chain of preconditions a
// request needs is satisfied. A deployment gate reads this number, so an
// unreachable chain RPC has to show up in it — otherwise a side that can verify
// nobody would still look ready to cut traffic over to.
func TestWarmer_WarmStateCountsOnlyFullyPreparedProviders(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	reg := &countingRegistry{signer: qvSignerStr, ack: true}
	r := New(srv.URL,
		WithQuoteVerification(qvVerifier(t), discardLogger()),
		WithOnChainVerification(reg, true, discardLogger()))
	res := fakeResolver{url: srv.URL}

	r.WarmOnce(context.Background(), res)
	s := r.WarmState()
	if s.At.IsZero() {
		t.Fatal("a completed sweep must stamp WarmState.At")
	}
	if s.Ready != 1 || s.Total != 1 {
		t.Errorf("WarmState = %+v, want Ready 1 of 1", s)
	}

	// The quote endpoint goes down: nothing is servable, so nothing is ready.
	atomic.StoreInt32(&status, http.StatusServiceUnavailable)
	r.WarmOnce(context.Background(), res)
	if s := r.WarmState(); s.Ready != 0 || s.Total != 1 {
		t.Errorf("WarmState = %+v, want Ready 0 of 1 once quotes fail", s)
	}

	// Quotes recover but the chain does not: under enforce a request still could not
	// use this provider, so it must not count as ready.
	atomic.StoreInt32(&status, 0)
	reg.failing.Store(true)
	r.WarmOnce(context.Background(), res)
	if s := r.WarmState(); s.Ready != 0 {
		t.Errorf("WarmState = %+v, want Ready 0 while the chain RPC is unreadable", s)
	}
}

// A sweep that cannot even enumerate providers prepared none of them — the honest
// readiness answer, and not one that should leave a previous "ready" standing.
func TestWarmer_WarmStateRecordedWhenListFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()))

	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	s := r.WarmState()
	if s.At.IsZero() {
		t.Error("a failed enumeration should still stamp a sweep time")
	}
	if s.Ready != 0 {
		t.Errorf("WarmState = %+v, want Ready 0", s)
	}
}

// Shutdown must not make a healthy process look unready on its way out.
func TestWarmer_CancelledSweepLeavesWarmStateAlone(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()))
	res := fakeResolver{url: srv.URL}

	r.WarmOnce(context.Background(), res)
	before := r.WarmState()
	if before.Ready != 1 {
		t.Fatalf("setup: WarmState = %+v, want Ready 1", before)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.WarmOnce(ctx, res)

	// The READINESS fields must survive: a shutdown must not publish "nothing is
	// ready" on its way out. Started does advance — a sweep really did begin — and
	// that only ever makes the process look more current, never less.
	got := r.WarmState()
	if got.At != before.At || got.Ready != before.Ready || got.Total != before.Total {
		t.Errorf("WarmState = %+v after a cancelled sweep, want its result untouched (%+v)", got, before)
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
	// It must be a FORCED read: an ordinary lookup is satisfied by a still-fresh
	// entry, so the sweep would warm nothing and the entry would expire on its own
	// schedule — the phase-luck this refresh-ahead exists to remove.
	if got := atomic.LoadInt32(&reg.refreshes); got != 1 {
		t.Errorf("grounding refreshes = %d, want 1 (the warmer must force a live read)", got)
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

// A lookup that SUCCEEDS but does not vouch for the quote-bound signer is not a
// prepared provider: enforce would skip it, so counting it ready would send
// traffic to a side where every request fails. The warmer has to ask the same
// question a request asks, not merely "did the RPC answer".
func TestWarmer_UnacknowledgedSignerIsNotReadyUnderEnforce(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	reg := &countingRegistry{signer: qvSignerStr, ack: false} // answers, but vouches for nobody
	r := New(srv.URL,
		WithQuoteVerification(qvVerifier(t), discardLogger()),
		WithOnChainVerification(reg, true, discardLogger()))

	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	if s := r.WarmState(); s.Ready != 0 {
		t.Errorf("WarmState = %+v, want Ready 0 (the chain acknowledges no signer)", s)
	}
}

// Same for a signer that disagrees with the quote.
func TestWarmer_MismatchedSignerIsNotReadyUnderEnforce(t *testing.T) {
	var hits, status int32
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	reg := &countingRegistry{signer: "0x0000000000000000000000000000000000000009", ack: true}
	r := New(srv.URL,
		WithQuoteVerification(qvVerifier(t), discardLogger()),
		WithOnChainVerification(reg, true, discardLogger()))

	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	if s := r.WarmState(); s.Ready != 0 {
		t.Errorf("WarmState = %+v, want Ready 0 (chain and quote name different signers)", s)
	}
}

// Under WARN mode the request path proceeds ungrounded, so a chain problem must
// not make this side look unusable — reporting our own RPC's bad day as the
// standby's would block a cutover to a process serving every request fine. The
// shipped compose runs warn mode, so this is the live configuration.
func TestWarmer_ChainProblemsDoNotBlockReadinessUnderWarn(t *testing.T) {
	for _, tc := range []struct {
		name string
		reg  *countingRegistry
		down bool
	}{
		{"unacknowledged", &countingRegistry{signer: qvSignerStr, ack: false}, false},
		{"mismatch", &countingRegistry{signer: "0x0000000000000000000000000000000000000009", ack: true}, false},
		{"rpc down", &countingRegistry{signer: qvSignerStr, ack: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits, status int32
			srv := warmerServer(t, &hits, []string{"0xa"}, &status)
			if tc.down {
				tc.reg.failing.Store(true)
			}
			r := New(srv.URL,
				WithQuoteVerification(qvVerifier(t), discardLogger()),
				WithOnChainVerification(tc.reg, false, discardLogger())) // warn

			r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
			if s := r.WarmState(); s.Ready != 1 {
				t.Errorf("WarmState = %+v, want Ready 1: warn mode serves this provider fine", s)
			}
		})
	}
}

// A sweep cancelled while working on its LAST provider leaves the loop by exhausting
// it, not through the in-loop guard, so the guard has to be repeated after the loop.
// Without it the sweep falls through and publishes "0 of N prepared" on shutdown —
// the alert series and the WarmState /readyz answers from, both wrong, and reachable
// on every deploy rather than in some corner.
func TestWarmer_CancelDuringLastProviderDoesNotPublishSweep(t *testing.T) {
	var hits, status int32
	// One provider, so cancelling while its quote is in flight cancels the sweep on
	// its way out of the last iteration.
	srv := warmerServer(t, &hits, []string{"0xa"}, &status)
	res := fakeResolver{url: srv.URL}

	// The registry cancels the sweep from inside the per-provider work, once the
	// loop's top-of-iteration guard has already let the only provider through.
	ctx, cancel := context.WithCancel(context.Background())
	reg := &cancellingRegistry{cancel: cancel}
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()),
		WithOnChainVerification(reg, false, discardLogger()))

	r.WarmOnce(context.Background(), res) // prime, so a real Ready count exists to clobber
	primed := r.WarmState()
	if primed.Ready != 1 {
		t.Fatalf("setup: WarmState = %+v, want Ready 1", primed)
	}

	// Armed only now: cancelling during the priming sweep would leave ctx already done
	// at the next sweep's entry, where the loop's own guard catches it — testing the
	// guard that was already there instead of the one after the loop.
	reg.arm()
	sweeps := metricValue(t, `zg_gateway_warmer_sweeps_total{result="ok"}`)
	r.WarmOnce(ctx, res)

	if got := r.WarmState(); got.At != primed.At || got.Ready != primed.Ready {
		t.Errorf("WarmState = %+v after a sweep cancelled on its last provider, want its result untouched (%+v)",
			got, primed)
	}
	if got := metricValue(t, `zg_gateway_warmer_sweeps_total{result="ok"}`); got != sweeps {
		t.Errorf("warmer_sweeps_total{result=ok} moved by %v, want 0: a cancelled sweep is not a success", got-sweeps)
	}
}

// cancellingRegistry cancels the sweep's context from inside the per-provider work,
// after the loop's top-of-iteration guard has already let that provider through. It
// stays inert until armed, so a priming sweep can run to completion first.
type cancellingRegistry struct {
	cancel context.CancelFunc
	armed  atomic.Bool
}

func (c *cancellingRegistry) arm() { c.armed.Store(true) }

func (c *cancellingRegistry) AcknowledgedSigner(context.Context, string) (chain.Signer, error) {
	return chain.Signer{Address: qvSignerStr, Acknowledged: true}, nil
}

func (c *cancellingRegistry) RefreshSigner(ctx context.Context, addr string) (chain.Signer, error) {
	if c.armed.Load() {
		c.cancel()
	}
	return chain.Signer{Address: qvSignerStr, Acknowledged: true}, nil
}
