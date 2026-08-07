package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

// identityLabels drops what the guest agent could not supply, so a partial
// identity still yields the part that matters (instance_id separates colliding
// replica series; app_id only adds the blue/green dimension).
func TestIdentityLabels(t *testing.T) {
	cases := []struct {
		instanceID, appID string
		want              prometheus.Labels
	}{
		{"aa11", "bb22", prometheus.Labels{"instance_id": "aa11", "app_id": "bb22"}},
		{"aa11", "", prometheus.Labels{"instance_id": "aa11"}},
		{"", "", prometheus.Labels{}},
	}
	for _, c := range cases {
		got := identityLabels(c.instanceID, c.appID)
		if len(got) != len(c.want) {
			t.Fatalf("identityLabels(%q,%q) = %v, want %v", c.instanceID, c.appID, got, c.want)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("identityLabels(%q,%q)[%s] = %q, want %q", c.instanceID, c.appID, k, got[k], v)
			}
		}
	}
}

// The whole point of the identity labels: two replicas of one app_id are scraped
// through identical target and external labels, so unless the exporter stamps a
// per-CVM label their series collide in the shared remote-write store. Register
// into a throwaway registry (the package one is a once-only, process-wide value)
// and check the labels actually reach the exposition — on a domain metric AND on
// the runtime collectors, which collide just as badly.
func TestInstanceLabelsStampExposition(t *testing.T) {
	reg := prometheus.NewRegistry()
	register(reg, identityLabels("aa11bb22", "cc33dd44"))

	MeasurementUntrusted()
	srv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	for _, want := range []string{
		`zg_gateway_quote_measurement_untrusted_total{app_id="cc33dd44",instance_id="aa11bb22"}`,
		`go_goroutines{app_id="cc33dd44",instance_id="aa11bb22"}`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("exposition missing %q\ngot:\n%s", want, text)
		}
	}
}
