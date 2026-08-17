// Package metrics defines the Prometheus instrumentation shared by the two
// client-core proxy forms and exposes the /metrics handler the gateway serves.
//
// The collectors are process-global and registered once here; every proxy form
// that (transitively) imports this package increments them, but only the
// gateway mounts Handler() — on a SEPARATE internal listener that is not
// published through the dstack tproxy ingress — so the local sidecar carries the
// instrumentation without ever exposing or shipping it (cmd/sidecar starts no
// metrics server).
//
// Redaction discipline (load-bearing): the gateway is a confidential-TEE enclave
// (docs/design/cloud-gateway.md), so its operator-visible metrics must not become
// a side channel for the plaintext the E2EE seal protects — the same constraint
// openaiproxy.LogRequests keeps for the access log. Every label defined here is
// low-cardinality and content-free: route templates, HTTP methods, status codes,
// and fixed outcome enums. A provider address, endpoint URL, request id, model
// name, or any other caller-supplied value must NEVER become a label value.
//
// Which CVM produced a series is deliberately NOT decided here. It is a TARGET
// label, applied by the scraper from the file_sd document cmd/cvmid writes (see
// deploy/phala/docker-compose.yml). Stamping it exporter-side instead — via
// WrapRegistererWith, which this package briefly did — cannot work: Prometheus
// synthesises up, scrape_duration_seconds and the other per-scrape series from
// target labels alone, so they would never carry it. `up` is the extreme case;
// it exists precisely when the exposition could NOT be read, so no label this
// process produces can ever reach it — and `up` per replica is the signal most
// worth alerting on. client_golang says the same thing about its own API:
// WrapRegistererWith "should not be used to add fixed labels to all metrics
// exposed".
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// namespace/subsystem prefix every metric with zg_gateway_ (the scraped form is
// always the gateway; the sidecar shares the code but is never scraped).
const (
	namespace = "zg"
	subsystem = "gateway"
)

// registry is a dedicated registry rather than the global default: it keeps the
// exposition to exactly the collectors registered here (plus Go/process), and
// avoids cross-test double-registration panics on the global default.
var registry = prometheus.NewRegistry()

// verifyBuckets sizes latency histograms for the DCAP verify + collateral paths,
// which range from a warm-cache few milliseconds to multi-second cold fetches —
// wider and longer-tailed than the default HTTP buckets.
var verifyBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

var (
	// HTTP layer (openaiproxy.LogRequests) — the RED signals for every request.
	httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "http_requests_total",
		Help: "Total HTTP requests handled, by route template, method, and status code.",
	}, []string{"route", "method", "status"})
	httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "http_request_duration_seconds",
		Help: "HTTP request handling latency, by route template.", Buckets: prometheus.DefBuckets,
	}, []string{"route"})
	httpInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "http_requests_in_flight",
		Help: "HTTP requests currently being served.",
	})

	// Overload shedding (openaiproxy.LimitInFlight) — the sealed inference path's
	// concurrency ceiling. The limit is exported alongside the counter so an alert
	// can watch headroom (in-flight approaching the cap) without hardcoding a
	// number only the deployment knows.
	//
	// Mind the scope mismatch if you write that ratio: http_requests_in_flight
	// counts EVERY request (health probes, the router passthrough), while this
	// limit bounds only the sealed path. Those extras are short-lived and sealed
	// requests are the long-held ones, so the ratio is a good approximation of
	// headroom — but it is an approximation, and it reads slightly high.
	inFlightLimit = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "inflight_limit",
		Help: "Configured max concurrent sealed inference requests; 0 when the cap is disabled.",
	})
	// Sheds also land in http_requests_total{status="503"}, so a naive 5xx alert
	// pages on the limiter doing its job. Subtract this series to get faults
	// alone; the access log makes the same split with shed=true at Warn.
	requestsShed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "requests_shed_total",
		Help: "Sealed inference requests refused with 503 because the in-flight limit was reached. Also counted in http_requests_total{status=\"503\"} — subtract this to isolate genuine faults.",
	})

	// Completion outcome (openaiproxy) — attributes each chat completion to where
	// a failure originated (core.Error.Source/Stage), so a gateway-side fault is
	// distinguishable from a router/provider one without parsing logs.
	completions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "completions_total",
		Help: "Chat completions by result (success|error), originating source, and stage.",
	}, []string{"result", "source", "stage"})

	// E2EE open failures (core.logOpenFailure) — an AEAD open failure is a
	// security-relevant signal (key/enc/AAD mismatch, dropped/reordered frame, or
	// an intermediary-injected bound field); a rising rate is worth alerting on.
	openFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "response_open_failures_total",
		Help: "Sealed-response frames that failed to open (AEAD authentication failure).",
	})
	verificationFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "response_verification_failures_total",
		Help: "§8 response-signature verification failures by reason (fetch|signature).",
	}, []string{"reason"})

	// Attestation / quote verification (route) — the trust-model core.
	quoteVerify = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "quote_verifications_total",
		Help: "DCAP quote verifications actually performed (cache misses), by result.",
	}, []string{"result"})
	quoteVerifyDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "quote_verification_duration_seconds",
		Help: "Latency of a performed DCAP quote verification (quote fetch + verify).", Buckets: verifyBuckets,
	})
	quoteCache = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "quote_cache_lookups_total",
		Help: "Quote-cache lookups by result (hit|miss); the warmer exists to keep hit high.",
	}, []string{"result"})
	measurementUntrusted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "quote_measurement_untrusted_total",
		Help: "Genuine quotes whose measurement was not in the allowlist (attest warn mode).",
	})

	// On-chain signer grounding (route.groundSignerOnChain, trust-chain hop 5).
	// The outcome label separates the two classes an operator must not conflate:
	// mismatch/not_acknowledged are verdicts about the PROVIDER (the reason enforce
	// mode exists), while lookup_failed is a verdict about OUR OWN chain RPC. In
	// warn mode this counter is the baseline that says whether enforce can be
	// turned on at all; after that, a nonzero mismatch rate is the alert-worthy
	// signal, since it means a quote-bound signer disagreed with the chain.
	onchainGrounding = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "onchain_grounding_total",
		Help: "On-chain signer grounding attempts by outcome " +
			"(ok|ok_stale|mismatch|not_acknowledged|lookup_failed).",
	}, []string{"outcome"})
	onchainRevalidations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "onchain_revalidations_total",
		Help: "Live re-reads forced because a negative verdict rested on stale or cached " +
			"evidence, by what the fresh evidence then said (ok|negative|lookup_failed).",
	}, []string{"result"})

	// Warmer (route/warmer.go) — the background sweep keeping the quote cache hot.
	warmerSweeps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "warmer_sweeps_total",
		Help: "Warmer sweeps by result (ok|list_failed).",
	}, []string{"result"})
	warmerProviderRefresh = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "warmer_provider_refreshes_total",
		Help: "Per-provider warmer refreshes by result (ok|endpoint_failed|verify_failed).",
	}, []string{"result"})
	warmerSignerRefresh = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "warmer_signer_refreshes_total",
		Help: "Per-provider on-chain signer refreshes by the warmer, by result (ok|failed). " +
			"A sustained failed rate means requests are paying the chain RPC themselves.",
	}, []string{"result"})
	warmerReadyProviders = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "warmer_ready_providers",
		Help: "Providers the last warmer sweep prepared end to end (endpoint + quote + " +
			"on-chain signer). Zero while the process is up means no request could be " +
			"served — alert on it; it is also what the blue/green standby probe gates on.",
	})
	warmerLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "warmer_last_success_timestamp_seconds",
		Help: "Unix time of the last completed warmer sweep; alert if it stops advancing.",
	})

	// DCAP collateral fetch/cache (dcap/collateral.go) — the Intel PCS / PCCS
	// dependency and the dedup cache that shields it (quantifies #44).
	collateralCache = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "collateral_cache_lookups_total",
		Help: "DCAP collateral cache lookups by result (hit|miss).",
	}, []string{"result"})
	collateralFetch = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "collateral_fetches_total",
		Help: "DCAP collateral fetches to the upstream (PCCS/Intel PCS) by result.",
	}, []string{"result"})
	collateralFetchDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "collateral_fetch_duration_seconds",
		Help: "Latency of an upstream DCAP collateral fetch (cache miss).", Buckets: verifyBuckets,
	})
)

func init() {
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		httpRequests, httpDuration, httpInFlight, inFlightLimit, requestsShed,
		completions, openFailures, verificationFailures,
		quoteVerify, quoteVerifyDuration, quoteCache, measurementUntrusted,
		onchainGrounding, onchainRevalidations,
		warmerSweeps, warmerProviderRefresh, warmerSignerRefresh,
		warmerReadyProviders, warmerLastSuccess,
		collateralCache, collateralFetch, collateralFetchDuration,
	)
}

// Handler returns the HTTP handler that serves the Prometheus exposition format.
// The gateway mounts it on a separate internal listener that is NOT published
// through the dstack tproxy ingress, so the metrics stay reachable only from the
// CVM-internal docker network (the co-located Prometheus-agent scraper), never
// the public endpoint.
func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

// RouteLabel maps a request path to a bounded route-template label, so the raw
// path (which could carry caller-controlled, high-cardinality, or sensitive
// content on an unexpected route) never becomes a label value. Only the routes
// the gateway serves itself get their own label; everything else — including the
// paths the gateway reverse-proxies to the router — collapses to "other".
func RouteLabel(path string) string {
	switch path {
	case "/v1/chat/completions", "/healthz", "/readyz":
		return path
	default:
		return "other"
	}
}

// HTTPRequest records one completed HTTP request: its count (by route/method/
// status) and its handling latency (by route).
func HTTPRequest(route, method string, status int, dur time.Duration) {
	httpRequests.WithLabelValues(route, method, strconv.Itoa(status)).Inc()
	httpDuration.WithLabelValues(route).Observe(dur.Seconds())
}

// IncInFlight / DecInFlight bracket a request for the in-flight gauge.
func IncInFlight() { httpInFlight.Inc() }
func DecInFlight() { httpInFlight.Dec() }

// SetInFlightLimit publishes the configured concurrency ceiling (0 = disabled).
// Called once at wiring time, so the series exists before any load arrives —
// otherwise an alert on the in-flight/limit ratio would have no denominator on a
// gateway that has not yet been busy.
func SetInFlightLimit(n int) { inFlightLimit.Set(float64(n)) }

// RequestShed records one request refused because the gateway was at capacity.
// Worth alerting on at any sustained non-zero rate: it means real requests are
// being turned away, which is the intended behavior but never a steady state.
func RequestShed() { requestsShed.Inc() }

// Completion records one chat-completion outcome. For a success, source and
// stage are "none"; for a failure they carry core.Error.Source()/Stage.
func Completion(result, source, stage string) {
	completions.WithLabelValues(result, source, stage).Inc()
}

// ResponseOpenFailure counts one sealed-response frame that failed to open.
func ResponseOpenFailure() { openFailures.Inc() }

// ResponseVerificationFailure counts one §8 response-signature verification
// failure, by reason ("fetch" or "signature").
func ResponseVerificationFailure(reason string) {
	verificationFailures.WithLabelValues(reason).Inc()
}

// QuoteVerification records one performed (cache-miss) DCAP verification and its
// latency; ok distinguishes a successful verify from a failed one.
func QuoteVerification(ok bool, dur time.Duration) {
	quoteVerify.WithLabelValues(result(ok)).Inc()
	quoteVerifyDuration.Observe(dur.Seconds())
}

// QuoteCacheLookup records a quote-cache lookup outcome (hit or miss).
func QuoteCacheLookup(hit bool) { quoteCache.WithLabelValues(hitMiss(hit)).Inc() }

// MeasurementUntrusted counts a genuine quote whose measurement was not in the
// allowlist (only reachable in attest warn mode; enforce fails the verify).
func MeasurementUntrusted() { measurementUntrusted.Inc() }

// OnChainGrounding records the outcome of one on-chain signer-grounding attempt.
// outcome is a fixed low-cardinality label: ok, ok_stale, mismatch,
// not_acknowledged, or lookup_failed.
func OnChainGrounding(outcome string) { onchainGrounding.WithLabelValues(outcome).Inc() }

// OnChainRevalidation records a live re-read forced because a negative verdict
// would otherwise have rested on stale or cached evidence. result is what the
// fresh evidence said: ok (the negative was an artifact of staleness — typically
// a benign signer rotation), negative (the verdict survived), or lookup_failed
// (no fresh evidence could be obtained).
func OnChainRevalidation(result string) { onchainRevalidations.WithLabelValues(result).Inc() }

// WarmerSignerRefresh records one provider's on-chain signer refresh by the
// warmer (result: ok|failed).
func WarmerSignerRefresh(result string) { warmerSignerRefresh.WithLabelValues(result).Inc() }

// WarmerReadyProviders records how many providers the last sweep prepared end to
// end (endpoint resolved, quote verified, on-chain signer read).
func WarmerReadyProviders(n int) { warmerReadyProviders.Set(float64(n)) }

// WarmerSweep records the outcome of one warmer sweep.
func WarmerSweep(result string) { warmerSweeps.WithLabelValues(result).Inc() }

// WarmerProviderRefresh records one provider's refresh outcome within a sweep.
func WarmerProviderRefresh(result string) { warmerProviderRefresh.WithLabelValues(result).Inc() }

// WarmerSweepSucceeded stamps the last-completed-sweep gauge to now.
func WarmerSweepSucceeded() { warmerLastSuccess.SetToCurrentTime() }

// CollateralCacheLookup records a DCAP collateral cache lookup outcome.
func CollateralCacheLookup(hit bool) { collateralCache.WithLabelValues(hitMiss(hit)).Inc() }

// CollateralFetch records one upstream collateral fetch (cache miss) and its
// latency; ok distinguishes a successful fetch from a failed one.
func CollateralFetch(ok bool, dur time.Duration) {
	collateralFetch.WithLabelValues(result(ok)).Inc()
	collateralFetchDuration.Observe(dur.Seconds())
}

// CoreMetrics adapts this package to core.MetricsHook, so core can report
// redaction-safe counters without importing the Prometheus client itself
// (matching how core takes a *slog.Logger rather than a concrete sink).
type CoreMetrics struct{}

// ResponseOpenFailure implements core.MetricsHook.
func (CoreMetrics) ResponseOpenFailure() { ResponseOpenFailure() }

// ResponseVerificationFailure implements core.MetricsHook.
func (CoreMetrics) ResponseVerificationFailure(reason string) { ResponseVerificationFailure(reason) }

func result(ok bool) string {
	if ok {
		return "success"
	}
	return "error"
}

func hitMiss(hit bool) string {
	if hit {
		return "hit"
	}
	return "miss"
}
