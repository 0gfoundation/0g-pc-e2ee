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
	"strings"
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

// previewBuckets sizes the route-preview latency histogram: verifyBuckets with one
// bucket ABOVE that call's own ceiling — retry budget plus one attempt, ~2x
// controlPlaneHeaderTimeout — so a preview that runs all the way to the ceiling is
// measurable instead of collapsing into +Inf right at the boundary.
var previewBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// upstreamBuckets sizes the data-plane attempt histogram, which needs a far wider
// range than verifyBuckets: a completion can legitimately run for minutes and a
// stream is bounded only by the provider timeout (10m30s), so the top bucket sits
// past it — without one, every long-but-healthy stream would pile into +Inf and
// the p99 would be unreadable exactly when it matters. The stream first-frame
// histogram shares it for the same reason: that wait is bounded by the same idle
// watchdog, not by anything smaller.
var upstreamBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 900}

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

	// Route preview (route.preview) — the ONE outbound dependency on the request
	// path with no cache in front of it, deliberately, since the ranking must
	// reflect the live fleet. So its health is request health directly, and its
	// latency is request latency: everything else (quote, collateral, on-chain
	// signer) is normally served from a warm cache and shows up in the counters
	// above only on a miss.
	previewAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "preview_attempts_total",
		Help: "Route-preview HTTP attempts by result: ok; retryable (transport failure, a body that " +
			"dropped, or a 5xx — another attempt follows); rejected (the router ANSWERED definitively — " +
			"a 4xx/429, or a well-formed reply with no candidates — usually about the caller or the " +
			"fleet, not about the router); broken (it answered with a body that will not decode, which " +
			"IS the router misbehaving); canceled (the caller gave up mid-attempt); internal (a " +
			"request this gateway could not even build — our own configuration).",
	}, []string{"result"})
	previewCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "preview_calls_total",
		Help: "Route-preview CALLS (one per chat request, whatever its attempt count) by outcome: " +
			"ok, ok_retried, rejected, failed, canceled, internal. Watch ok_retried: it is where a degrading " +
			"router shows up while the error rate is still flat, because the retries are absorbing " +
			"it. Alert on failed, NOT on rejected: rejected is the router answering a caller (a bad " +
			"credential, an unknown model) or reporting an empty fleet, so folding it in lets one " +
			"misconfigured tenant pin an alert meant for the router. canceled is the caller leaving.",
	}, []string{"outcome"})
	previewRetrySuppressed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "preview_retries_suppressed_total",
		Help: "Route-preview retry ATTEMPTS not made because the router had stopped answering " +
			"altogether (see route.retryGate). Retrying an uncached dependency multiplies load " +
			"on it exactly when it can least take it, and holds a gateway concurrency slot for " +
			"the retry ceiling rather than one attempt, so a router outage would become " +
			"gateway-wide shedding. The first attempt of every request is still made, so this " +
			"rising means requests are still being served their real error, just without the " +
			"amplification — read it next to preview_calls_total{outcome=\"failed\"}.",
	})
	previewDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "preview_duration_seconds",
		Help: "End-to-end latency of one route-preview call, retries and their backoff included. " +
			"This sits in front of every sealed request, so it is a floor on request latency.",
		// previewBuckets, not verifyBuckets, whose top finite bucket is 60s — exactly
		// this call's own ceiling (retry budget + one attempt), so the worst case
		// would land in +Inf.
		Buckets: previewBuckets,
	})

	// Data plane (core) — the sealed POST to the router and what came back. This is
	// the expensive hop and the one that carries the long timeouts, the candidate
	// fallback and the streams, so it is metered on its own rather than left to be
	// inferred from the inbound http_* series: those measure the gateway's whole
	// handling, which is preview + materialization + this, and cannot say which
	// part moved.
	upstreamAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "upstream_attempts_total",
		Help: "Data-plane attempts against one provider, by kind (buffered|stream) and outcome: ok; " +
			"http_429/http_4xx/http_5xx/http_other (a status came back); transport (no response at " +
			"all — never reached it, or it never answered); body (the response dropped mid-read, or " +
			"a stream ended before its final frame); undecodable (a 2xx whose sealed body would not " +
			"decode or open); not_stream (a 200 that was not an event stream); unverified (the §8 " +
			"signature was retrieved and did not verify — an integrity claim about the provider); " +
			"unverifiable (the signature could not be retrieved at all, so nothing was proven either " +
			"way — operational, and deliberately apart from unverified so a broker's bad minute " +
			"cannot page anyone as a provider integrity failure); timeout (our own provider deadline " +
			"or stream idle watchdog — " +
			"the provider went quiet); canceled (the CALLER went away); internal (a fault in the " +
			"gateway itself). The last two are deliberately NOT failure buckets: a closed tab is not " +
			"a provider's fault, and our own bug should not be filed as one either.",
	}, []string{"kind", "outcome"})
	upstreamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "upstream_attempt_duration_seconds",
		Help: "Duration of one data-plane attempt, split by kind because the two distributions are " +
			"different questions: buffered is the completion's whole latency, stream is how long the " +
			"stream stayed open (see upstream_stream_ttff_seconds for the latency a streaming caller " +
			"actually feels). Split by result (ok|failed|canceled) as well, because a histogram over " +
			"ALL attempts is not a latency series: a 4xx rejected in 20ms and a caller that left " +
			"after 200ms both drag the completion p99 down, and that p99 is what the budget-cut " +
			"runbook says to read the ceiling against. Chart result=\"ok\" for latency. canceled is " +
			"kept out of failed for the same reason it is kept out of every failure bucket next " +
			"door, and because its duration is set by when the caller left rather than by anything " +
			"upstream. Coarsened to three values on purpose: the counter next door carries the full " +
			"outcome vocabulary, which here would multiply every bucket series by it.",
		Buckets: upstreamBuckets,
	}, []string{"kind", "result"})
	streamTTFF = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "upstream_stream_ttff_seconds",
		Help: "Time to first delivered frame of a stream — the latency a streaming caller feels, " +
			"which the attempt duration cannot show (a stream that runs for minutes may have " +
			"produced its first token instantly).",
		// upstreamBuckets, not verifyBuckets: the wait for a first frame is bounded
		// only by the stream idle watchdog (providerTimeout, 10m30s), so a 60s top
		// bucket would put every degraded stream in +Inf — unreadable exactly when
		// this panel matters.
		Buckets: upstreamBuckets,
	})
	walkBudgetExhausted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "walk_budget_exhausted_total",
		Help: "Requests where core.resolveBudget running out actually truncated the candidate walk " +
			"— it cut a materialization short, or denied a fallback the walk would otherwise have " +
			"made. Not counted when a failed attempt on the LAST candidate happens to exhaust it: a " +
			"running attempt is never cut by the budget, so there it only decides whether to move " +
			"on, and there was nothing to move on to. This is " +
			"the only signal that a request was ended by OUR ceiling rather than by " +
			"anything upstream, and therefore the only way to tell whether that ceiling is set " +
			"anywhere near right. Read it next to the buffered completion-latency p99: this rising " +
			"with the p99 pinned near the budget means requests are spending their whole allowance " +
			"walking a bad chain.",
	})
	candidateFallbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "candidate_fallbacks_total",
		Help: "Times the client moved on to the next provider candidate, by reason: upstream (an " +
			"attempt failed transiently and was re-sealed to the next) or materialize (the candidate " +
			"could not be prepared at all — its quote, key or on-chain grounding failed). Sustained " +
			"either way means the ranking the router hands us is putting bad providers first.",
	}, []string{"reason"})

	// §8 response-signature fetch (route.SignatureFetcher), which goes DIRECT to the
	// provider's broker — the router does not proxy it — once per response.
	signatureFetchCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "signature_fetch_calls_total",
		Help: "§8 signature fetches (one per verified response) by outcome: ok, ok_retried, failed " +
			"(the broker was asked and did not deliver), timeout (OUR deadline for the attempt " +
			"fired mid-fetch), canceled (the caller left), internal (we never asked it — no " +
			"endpoint to fetch from, or an endpoint/chatKey that would not form a URL). " +
			"ok_retried is expected traffic, not an incident: the broker writes the signature at " +
			"end-of-response, so a just-finished response can momentarily 404 — but a ratio that " +
			"climbs means every response is paying the backoff. timeout, canceled and internal are " +
			"split out of failed because none of them is the broker's; see route.endedBy for the " +
			"two cases that split imperfectly.",
	}, []string{"outcome"})
	signatureFetchDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Subsystem: subsystem, Name: "signature_fetch_duration_seconds",
		Help: "End-to-end latency of one §8 signature fetch, retries and backoff included. It is " +
			"serial with the response, so it is added to every verified completion.",
		Buckets: verifyBuckets,
	})

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
		Help: "Per-provider on-chain signer refreshes by the warmer, by result " +
			"(ok|failed|mismatch|unchecked). failed is our chain RPC; mismatch is the chain " +
			"declining to vouch for the quote-bound signer, which under enforce makes that " +
			"provider unusable and can hold back a blue/green cutover; unchecked is a reading " +
			"that acknowledged someone but had no quote-bound signer to compare against, " +
			"because the quote refresh failed first (see verify_failed).",
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
		previewAttempts, previewCalls, previewDuration, previewRetrySuppressed,
		upstreamAttempts, upstreamDuration, streamTTFF, candidateFallbacks, walkBudgetExhausted,
		signatureFetchCalls, signatureFetchDuration,
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
	}
	// The public evidence bundle, collapsed to ONE label rather than one per file:
	// it is a template, and the filenames are attacker-suppliable (a 404 for any
	// path under the prefix would otherwise mint a series). Worth separating from
	// "other" because it is the only unauthenticated, cacheable, browser-reachable
	// route the gateway serves — traffic to it says something different from traffic
	// bound for the router, and it must be visible when a verifier page hammers it.
	if path == "/evidences" || strings.HasPrefix(path, "/evidences/") {
		return "/evidences/"
	}
	return "other"
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

// PreviewAttempt counts one route-preview HTTP attempt. result is a fixed
// low-cardinality label, and route.previewResult is its single definition —
// re-listing the values here is what let this comment drift to naming one that is
// never emitted while omitting two that are. See the metric's Help for what falls
// in each.
func PreviewAttempt(result string) { previewAttempts.WithLabelValues(result).Inc() }

// PreviewRetrySuppressed counts n retry attempts the retry gate declined to make.
// n is the attempts remaining when the gate closed, so this measures amplification
// shed rather than calls affected — the budget might independently have declined
// some of them, which makes it the ceiling removed rather than an exact saving.
func PreviewRetrySuppressed(n int) { previewRetrySuppressed.Add(float64(n)) }

// PreviewCall records one route-preview call — one per chat request, whatever its
// attempt count — and its end-to-end latency including any retries. outcome is a
// fixed low-cardinality label derived from the attempt result that ended the call
// (route.previewResult.callOutcome), plus ok_retried for a success that needed a
// retry; that method is the single definition.
func PreviewCall(outcome string, dur time.Duration) {
	previewCalls.WithLabelValues(outcome).Inc()
	previewDuration.Observe(dur.Seconds())
}

// UpstreamAttempt records one completed data-plane attempt against a provider and
// how long the upstream call took. kind is "buffered" or "stream"; outcome is a
// fixed low-cardinality label (see the metric's Help).
func UpstreamAttempt(kind, outcome string, dur time.Duration) {
	upstreamAttempts.WithLabelValues(kind, outcome).Inc()
	upstreamDuration.WithLabelValues(kind, attemptResult(outcome)).Observe(dur.Seconds())
}

// attemptResult coarsens an attempt outcome to the duration histogram's result
// label. Three values rather than the counter's full vocabulary, which here would
// multiply every bucket series by it — and three rather than two, because
// "canceled" is not a failure (the same rule the counter's Help states) and its
// duration is set by when the caller left, so folding it into either neighbour
// distorts that neighbour.
//
// The two literals are core's outcome vocabulary (core.UpstreamOK,
// core.UpstreamCanceled). This package deliberately does not import core, so they
// are pinned to it by TestAttemptResultMatchesCoreVocabulary rather than by the
// compiler: renaming an outcome without it would silently relabel every attempt.
func attemptResult(outcome string) string {
	switch outcome {
	case "ok":
		return "ok"
	case "canceled":
		return "canceled"
	default:
		return "failed"
	}
}

// StreamFirstFrame records the time to a stream's first delivered frame.
func StreamFirstFrame(dur time.Duration) { streamTTFF.Observe(dur.Seconds()) }

// WalkBudgetExhausted counts one request cut short by the candidate-walk budget.
func WalkBudgetExhausted() { walkBudgetExhausted.Inc() }

// CandidateFallback counts one move to the next provider candidate. reason is
// "upstream" (an attempt failed and was re-sealed) or "materialize" (the candidate
// could not be prepared at all).
func CandidateFallback(reason string) { candidateFallbacks.WithLabelValues(reason).Inc() }

// SignatureFetch records one §8 signature fetch — one per verified response — and
// its end-to-end latency including retries. outcome is a fixed low-cardinality
// label; the metric's Help is the one place the set is described, because this
// comment restated it and drifted from it twice.
func SignatureFetch(outcome string, dur time.Duration) {
	signatureFetchCalls.WithLabelValues(outcome).Inc()
	signatureFetchDuration.Observe(dur.Seconds())
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
// warmer: ok, failed (our chain RPC could not be read), or mismatch (it was read
// and did not vouch for the quote-bound signer). The last is the one that marks a
// provider unprepared under enforce, so it is not a variant of failed.
func WarmerSignerRefresh(result string) { warmerSignerRefresh.WithLabelValues(result).Inc() }

// WarmerReadyProviders records how many providers the last sweep prepared end to
// end (endpoint resolved, quote verified, on-chain signer read — and, under
// -onchain-enforce, in agreement: a signer the registry does not vouch for, or one
// that could not be read, leaves that provider out).
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

// UpstreamAttempt implements core.MetricsHook.
func (CoreMetrics) UpstreamAttempt(kind, outcome string, dur time.Duration) {
	UpstreamAttempt(kind, outcome, dur)
}

// StreamFirstFrame implements core.MetricsHook.
func (CoreMetrics) StreamFirstFrame(dur time.Duration) { StreamFirstFrame(dur) }

// WalkBudgetExhausted implements core.MetricsHook.
func (CoreMetrics) WalkBudgetExhausted() { WalkBudgetExhausted() }

// CandidateFallback implements core.MetricsHook.
func (CoreMetrics) CandidateFallback(reason string) { CandidateFallback(reason) }

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
