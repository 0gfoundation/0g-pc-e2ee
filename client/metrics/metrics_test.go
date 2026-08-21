package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
)

// RouteLabel must map only the known served routes to themselves and collapse
// everything else to "other", so a raw (possibly caller-controlled or sensitive)
// path can never become a high-cardinality label value.
func TestRouteLabel(t *testing.T) {
	cases := map[string]string{
		"/v1/chat/completions":       "/v1/chat/completions",
		"/healthz":                   "/healthz",
		"/quote":                     "other", // no longer a gateway route (#59); proxied to router
		"/v1/models":                 "other",
		"/../etc/passwd":             "other",
		"/v1/chat/completions/extra": "other",
		"":                           "other",
		// The evidence bundle collapses to ONE label, filename and all: the names are
		// caller-suppliable (any 404 under the prefix would otherwise mint a series).
		"/evidences":                     "/evidences/",
		"/evidences/":                    "/evidences/",
		"/evidences/quote.json":          "/evidences/",
		"/evidences/cert-example.io.pem": "/evidences/",
		"/evidences/../etc/passwd":       "/evidences/",
		"/evidencesfoo":                  "other", // prefix match must not be a substring match
	}
	for path, want := range cases {
		if got := RouteLabel(path); got != want {
			t.Errorf("RouteLabel(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestHTTPRequestMetered(t *testing.T) {
	c := httpRequests.WithLabelValues("/quote", "GET", "501")
	before := testutil.ToFloat64(c)
	HTTPRequest("/quote", "GET", 501, 3*time.Millisecond)
	if got := testutil.ToFloat64(c) - before; got != 1 {
		t.Fatalf("http_requests_total delta = %v, want 1", got)
	}
	// The duration histogram records under the route label; its observation count
	// (a distinct series) must advance too.
	if got := testutil.CollectAndCount(httpDuration); got == 0 {
		t.Fatal("http_request_duration_seconds recorded no series")
	}
}

func TestInFlightGauge(t *testing.T) {
	before := testutil.ToFloat64(httpInFlight)
	IncInFlight()
	if got := testutil.ToFloat64(httpInFlight) - before; got != 1 {
		t.Fatalf("in-flight after Inc = %v, want +1", got)
	}
	DecInFlight()
	if got := testutil.ToFloat64(httpInFlight) - before; got != 0 {
		t.Fatalf("in-flight after Dec = %v, want back to baseline", got)
	}
}

func TestCompletionLabels(t *testing.T) {
	ok := completions.WithLabelValues("success", "none", "none")
	upstream := completions.WithLabelValues("error", "upstream", "upstream")
	okBefore, upBefore := testutil.ToFloat64(ok), testutil.ToFloat64(upstream)

	Completion("success", "none", "none")
	Completion("error", "upstream", "upstream")

	if got := testutil.ToFloat64(ok) - okBefore; got != 1 {
		t.Errorf("success completion delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(upstream) - upBefore; got != 1 {
		t.Errorf("upstream error completion delta = %v, want 1", got)
	}
}

func TestQuoteCacheHitMiss(t *testing.T) {
	hit := quoteCache.WithLabelValues("hit")
	miss := quoteCache.WithLabelValues("miss")
	hitBefore, missBefore := testutil.ToFloat64(hit), testutil.ToFloat64(miss)

	QuoteCacheLookup(true)
	QuoteCacheLookup(false)
	QuoteCacheLookup(false)

	if got := testutil.ToFloat64(hit) - hitBefore; got != 1 {
		t.Errorf("hit delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(miss) - missBefore; got != 2 {
		t.Errorf("miss delta = %v, want 2", got)
	}
}

// CoreMetrics is the adapter core uses (via core.MetricsHook) so core need not
// import this package; it must land on the same counter as the direct call.
func TestCoreMetricsOpenFailure(t *testing.T) {
	before := testutil.ToFloat64(openFailures)
	CoreMetrics{}.ResponseOpenFailure()
	if got := testutil.ToFloat64(openFailures) - before; got != 1 {
		t.Fatalf("response_open_failures_total delta = %v, want 1", got)
	}
}

func TestVerificationFailureByReason(t *testing.T) {
	fetch := verificationFailures.WithLabelValues("fetch")
	sig := verificationFailures.WithLabelValues("signature")
	fetchBefore, sigBefore := testutil.ToFloat64(fetch), testutil.ToFloat64(sig)

	// Exercise both the package helper and the core adapter — they must land on
	// the same reason-labelled series.
	ResponseVerificationFailure("fetch")
	CoreMetrics{}.ResponseVerificationFailure("signature")

	if got := testutil.ToFloat64(fetch) - fetchBefore; got != 1 {
		t.Errorf("fetch-reason delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(sig) - sigBefore; got != 1 {
		t.Errorf("signature-reason delta = %v, want 1", got)
	}
}

// Handler serves the exposition format over the dedicated registry, including a
// metric a caller just incremented.
func TestHandlerServesExposition(t *testing.T) {
	MeasurementUntrusted()

	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	// A domain metric and the free Go-runtime collector should both be present.
	for _, want := range []string{"zg_gateway_quote_measurement_untrusted_total", "go_goroutines"} {
		if !strings.Contains(text, want) {
			t.Errorf("exposition missing %q", want)
		}
	}
}

// attemptResult carries two of core's outcome strings as literals, because this
// package deliberately does not import core (core defines the hook interface so it
// need not depend on Prometheus). Nothing but this test stops the two from
// drifting: rename core.UpstreamOK and every attempt would silently be labelled
// result="failed", turning the completion-latency panel into a panel of failures.
func TestAttemptResultMatchesCoreVocabulary(t *testing.T) {
	for outcome, want := range map[string]string{
		core.UpstreamOK:          "ok",
		core.UpstreamCanceled:    "canceled",
		core.UpstreamHTTP4xx:     "failed",
		core.UpstreamHTTP5xx:     "failed",
		core.UpstreamTransport:   "failed",
		core.UpstreamTimeout:     "failed",
		core.UpstreamUnverified:  "failed",
		core.UpstreamInternal:    "failed",
		core.UpstreamUndecodable: "failed",
	} {
		if got := attemptResult(outcome); got != want {
			t.Errorf("attemptResult(%q) = %q, want %q", outcome, got, want)
		}
	}
}

// The duration histogram must observe under the coarsened result label while the
// counter keeps the full outcome — the split that stops a 4xx rejected in
// milliseconds from sitting in the completion-latency distribution.
func TestUpstreamAttemptSplitsCounterOutcomeFromHistogramResult(t *testing.T) {
	c4xx := upstreamAttempts.WithLabelValues(core.UpstreamBuffered, core.UpstreamHTTP4xx)
	hOK := upstreamDuration.WithLabelValues(core.UpstreamBuffered, "ok")
	hFailed := upstreamDuration.WithLabelValues(core.UpstreamBuffered, "failed")
	cBefore := testutil.ToFloat64(c4xx)
	okBefore, failedBefore := histCount(t, hOK), histCount(t, hFailed)

	UpstreamAttempt(core.UpstreamBuffered, core.UpstreamHTTP4xx, 20*time.Millisecond)

	if got := testutil.ToFloat64(c4xx) - cBefore; got != 1 {
		t.Errorf("counter{outcome=http_4xx} delta = %v, want 1 — the full outcome is the counter's job", got)
	}
	if got := histCount(t, hFailed) - failedBefore; got != 1 {
		t.Errorf("histogram{result=failed} delta = %v, want 1", got)
	}
	if got := histCount(t, hOK) - okBefore; got != 0 {
		t.Errorf("histogram{result=ok} delta = %v, want 0 — a rejection is not completion latency", got)
	}
}

// histCount reads a histogram child's sample count; testutil.ToFloat64 refuses
// histograms.
func histCount(t *testing.T, o prometheus.Observer) float64 {
	t.Helper()
	m, ok := o.(prometheus.Metric)
	if !ok {
		t.Fatalf("%T is not a prometheus.Metric", o)
	}
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return float64(pb.GetHistogram().GetSampleCount())
}
