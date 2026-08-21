package route

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
)

func TestDeriveSignatureURL(t *testing.T) {
	cases := []struct {
		endpoint, key, want string
		wantErr             bool
	}{
		{"https://p.example.com", "ck-1", "https://p.example.com/v1/proxy/signature/ck-1", false},
		{"https://p.example.com/v1", "ck-1", "https://p.example.com/v1/proxy/signature/ck-1", false},
		{"https://p.example.com/v1/chat/completions", "ck_1", "https://p.example.com/v1/proxy/signature/ck_1", false},
		{"https://p.example.com", "../etc/passwd", "", true}, // path traversal rejected
		{"https://p.example.com", "", "", true},
		{"not-a-url", "ck-1", "", true},
	}
	for _, tc := range cases {
		got, err := deriveSignatureURL(tc.endpoint, tc.key)
		if tc.wantErr {
			if err == nil {
				t.Errorf("deriveSignatureURL(%q,%q) = %q, want error", tc.endpoint, tc.key, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("deriveSignatureURL(%q,%q) = %q,%v, want %q", tc.endpoint, tc.key, got, err, tc.want)
		}
	}
}

func TestFetchSignature_RoundTrip(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"zg-sig-v1/e2ee-ct:aa:bb","signature":"0x1c","signing_address":"0xabc","signing_algo":"ecdsa"}`))
	}))
	defer srv.Close()

	f := NewSignatureFetcher(srv.Client())
	sig, err := f.FetchSignature(context.Background(), core.Provider{Endpoint: srv.URL}, "ck-9")
	if err != nil {
		t.Fatalf("FetchSignature: %v", err)
	}
	if gotPath != "/v1/proxy/signature/ck-9" {
		t.Fatalf("server saw path %q", gotPath)
	}
	if sig.Text != "zg-sig-v1/e2ee-ct:aa:bb" || sig.SigningAddress != "0xabc" {
		t.Fatalf("decoded unexpected signature: %+v", sig)
	}
}

func TestFetchSignature_Errors(t *testing.T) {
	f := NewSignatureFetcher(nil)
	if _, err := f.FetchSignature(context.Background(), core.Provider{}, "ck-1"); err == nil {
		t.Fatal("want error for empty endpoint")
	}

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"chat_id_not_found"}`, http.StatusNotFound)
	}))
	defer notFound.Close()
	_, err := NewSignatureFetcher(notFound.Client()).FetchSignature(context.Background(), core.Provider{Endpoint: notFound.URL}, "ck-1")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want 404 error, got %v", err)
	}
}

func TestFetchSignature_RetriesThenSucceeds(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 { // 404 twice (broker not-yet-cached), then serve
			http.Error(w, `{"error":"chat_id_not_found"}`, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"text":"zg-sig-v1/e2ee-ct:aa:bb","signature":"0x1c","signing_address":"0xabc","signing_algo":"ecdsa"}`))
	}))
	defer srv.Close()

	sig, err := NewSignatureFetcher(srv.Client()).FetchSignature(context.Background(), core.Provider{Endpoint: srv.URL}, "ck-1")
	if err != nil {
		t.Fatalf("expected success after transient 404s: %v", err)
	}
	if sig.Text == "" {
		t.Fatal("empty signature after retry")
	}
	if got := atomic.LoadInt32(&n); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestFetchSignature_NoRetryOn4xx(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := NewSignatureFetcher(srv.Client()).FetchSignature(context.Background(), core.Provider{Endpoint: srv.URL}, "ck-1")
	if err == nil {
		t.Fatal("want error for 400")
	}
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Fatalf("a 400 must not be retried, got %d attempts", got)
	}
}

// The §8 fetch is serial with every verified response, so it needs its own
// latency and outcome series. ok_retried in particular is expected traffic — the
// broker writes the signature at end-of-response, so a just-finished response can
// momentarily 404 — and must be distinguishable from a clean fetch, otherwise a
// broker that has started 404ing on EVERY response looks identical to a healthy one.
func TestSignatureFetchMetrics(t *testing.T) {
	const (
		callsOK      = `zg_gateway_signature_fetch_calls_total{outcome="ok"}`
		callsRetried = `zg_gateway_signature_fetch_calls_total{outcome="ok_retried"}`
		callsFailed  = `zg_gateway_signature_fetch_calls_total{outcome="failed"}`
		durCount     = `zg_gateway_signature_fetch_duration_seconds_count`
	)
	before := map[string]float64{}
	for _, s := range []string{callsOK, callsRetried, callsFailed, durCount} {
		before[s] = metricValue(t, s)
	}
	delta := func(s string) float64 { return metricValue(t, s) - before[s] }

	// Any decodable body will do — this test is about the metric, not the signature;
	// verification is covered by the §8 tests.
	sig := proof.ChatSignature{Text: "t", Signature: "0xsig", SigningAlgo: "ecdsa-secp256k1"}
	fetcher := NewSignatureFetcher(nil)
	provider := func(u string) core.Provider { return core.Provider{Endpoint: u} }
	key := "11111111-1111-1111-1111-111111111111"

	// Clean fetch.
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(sig)
	}))
	defer clean.Close()
	if _, err := fetcher.FetchSignature(context.Background(), provider(clean.URL), key); err != nil {
		t.Fatalf("clean fetch: %v", err)
	}

	// The 404-then-ready race the retry exists for.
	var hits int32
	racy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			http.Error(w, "not cached yet", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(sig)
	}))
	defer racy.Close()
	if _, err := fetcher.FetchSignature(context.Background(), provider(racy.URL), key); err != nil {
		t.Fatalf("fetch across the 404 race: %v", err)
	}

	// A broker that never produces it.
	gone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer gone.Close()
	if _, err := fetcher.FetchSignature(context.Background(), provider(gone.URL), key); err == nil {
		t.Fatal("fetch against a permanently-404 broker: want error")
	}

	for series, want := range map[string]float64{callsOK: 1, callsRetried: 1, callsFailed: 1, durCount: 3} {
		if got := delta(series); got != want {
			t.Errorf("%s delta = %v, want %v", series, got, want)
		}
	}
}

// Both pre-flight checks — no endpoint, and an endpoint/chatKey that will not form
// a URL — are fail-closed verification failures. They used to return before the
// metrics defer was installed, leaving the §8 panel at zero while responses went
// unverified: the exact blind spot this counter exists to close.
func TestSignatureFetchMetersPreflightFailures(t *testing.T) {
	const (
		callsFailed = `zg_gateway_signature_fetch_calls_total{outcome="failed"}`
		durCount    = `zg_gateway_signature_fetch_duration_seconds_count`
	)
	before := map[string]float64{callsFailed: metricValue(t, callsFailed), durCount: metricValue(t, durCount)}

	f := NewSignatureFetcher(nil)
	for _, tc := range []struct {
		name     string
		provider core.Provider
		chatKey  string
	}{
		{"no endpoint", core.Provider{}, "11111111-1111-1111-1111-111111111111"},
		{"unusable endpoint", core.Provider{Endpoint: "not-a-url"}, "11111111-1111-1111-1111-111111111111"},
		{"unusable chatKey", core.Provider{Endpoint: "https://broker.test"}, "../../escape"},
	} {
		if _, err := f.FetchSignature(context.Background(), tc.provider, tc.chatKey); err == nil {
			t.Errorf("%s: want an error", tc.name)
		}
	}

	if got := metricValue(t, callsFailed) - before[callsFailed]; got != 3 {
		t.Errorf("%s delta = %v, want 3 — a pre-flight failure is still a failed fetch", callsFailed, got)
	}
	if got := metricValue(t, durCount) - before[durCount]; got != 3 {
		t.Errorf("%s delta = %v, want 3 — every exit path must observe once", durCount, got)
	}
}

// The context this fetcher receives is derived from the ATTEMPT, not from the
// caller, so a done context is not evidence of a disconnect: our own
// providerTimeout expiring mid-fetch arrives here looking the same. Counting both
// as "canceled" put our deadline in the bucket every alert ignores.
func TestSignatureFetchSeparatesOurDeadlineFromTheCaller(t *testing.T) {
	const (
		callsTimeout  = `zg_gateway_signature_fetch_calls_total{outcome="timeout"}`
		callsCanceled = `zg_gateway_signature_fetch_calls_total{outcome="canceled"}`
	)
	before := map[string]float64{
		callsTimeout:  metricValue(t, callsTimeout),
		callsCanceled: metricValue(t, callsCanceled),
	}

	// A broker that never answers, so only the context ends the fetch.
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	f := NewSignatureFetcher(srv.Client())
	prov := core.Provider{Endpoint: srv.URL}
	key := "11111111-1111-1111-1111-111111111111"

	// A DEADLINE — what core's providerTimeout looks like from in here.
	dl, cancelDL := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancelDL()
	if _, err := f.FetchSignature(dl, prov, key); err == nil {
		t.Fatal("want an error once the deadline fires")
	}
	if got := metricValue(t, callsTimeout) - before[callsTimeout]; got != 1 {
		t.Errorf("%s delta = %v, want 1 — our own deadline must not read as a disconnect", callsTimeout, got)
	}
	if got := metricValue(t, callsCanceled) - before[callsCanceled]; got != 0 {
		t.Errorf("%s delta = %v, want 0", callsCanceled, got)
	}

	// A CANCEL — what a caller going away looks like.
	cc, cancelCC := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancelCC() }()
	if _, err := f.FetchSignature(cc, prov, key); err == nil {
		t.Fatal("want an error once the caller cancels")
	}
	if got := metricValue(t, callsCanceled) - before[callsCanceled]; got != 1 {
		t.Errorf("%s delta = %v, want 1", callsCanceled, got)
	}
	if got := metricValue(t, callsTimeout) - before[callsTimeout]; got != 1 {
		t.Errorf("%s delta = %v, want 1 (unchanged) — a cancel is not our timeout", callsTimeout, got)
	}
}
