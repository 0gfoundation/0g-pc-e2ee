// Command gateway is the cloud-TEE gateway form: the SAME client core wrapped
// as a server, but SERVER-RUN and 0G-operated — it runs inside an attested CVM
// and adds one attested trust party. It serves no-install / browser / thin
// clients that cannot run a sidecar: TLS terminates inside the enclave (in the
// deployed form, dstack-ingress in the same CVM — see deploy/phala/), the gateway
// seals each request to the routed provider and opens the sealed response, and
// plaintext streams back over that same TLS. See docs/design/cloud-gateway.md for
// the trust model.
//
// The gateway always routes: per request it asks the 0G router which provider to
// use (POST /v1/routing/preview), fetches that provider's enc key and signer
// address from the broker (GET /v1/e2ee/pubkey), then seals to it — so no
// provider key or signer is configured up front (design §12 open question 3;
// see client/route). A caller that wants a specific provider pins it with the
// X-0G-Provider-Address routing header, which the gateway forwards to the router
// so preview returns that provider.
//
// Startup wiring (flags, env-var defaults, route/seal plumbing) is shared with
// the sidecar via client/cmd/internal/proxycli; the gateway keeps only its own
// listen default (:8443), the ZG_GATEWAY_* env prefix, the browser-facing
// concerns (the CORS origin allowlist — see -allowed-origins / newHandler), and
// the operational routes below. Every parameter can be set via flag or a
// ZG_GATEWAY_* env var (flag > env > built-in default); env config is the
// primary path for the TEE/dstack deployment, where the compose file's
// `environment:` block is measured into the CVM attestation (see
// deploy/phala/docker-compose.yml).
//
// The gateway emits no attestation quote and signs no responses of its own.
// Endpoint/code identity comes from the in-CVM cert-binding attestation that
// dstack-ingress publishes at /evidences — its quote commits to app_id, which
// covers this gateway image too (see deploy/phala/ and
// docs/design/cloud-gateway.md §6). Inference authenticity rides the provider's
// own SPEC §8 response signature, which the gateway verifies
// (ZG_GATEWAY_VERIFY_RESPONSES). So the gateway exposes no /quote route. The
// sealed inference path carries a front-door credential gate
// (openaiproxy.RequireInferenceCredential in newHandler): a cheap presence/shape check
// that sheds missing-credential and mgmt-key traffic before the seal/route work,
// while the router stays the authoritative auth/billing point and re-validates
// every forwarded credential. That path also carries a process-wide concurrency
// ceiling (openaiproxy.LimitInFlight): paying per token bounds what a caller
// spends, not what they occupy, and this gateway is a shared CPU-bound process.
// The remaining multi-tenant concerns — per-user billing attribution, and
// per-account fairness rather than a global ceiling (issue #20) — are a later
// step; the router's per-account limiter is what bounds a single account's
// request rate today. Trusting the
// router's returned endpoint (vs resolving it on chain) is tracked in issue #18.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"runtime"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/cmd/internal/proxycli"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/dstack"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

func main() {
	f := proxycli.RegisterFlags(flag.CommandLine, "ZG_GATEWAY", ":8443")
	// Prometheus /metrics is a gateway-only concern (the sidecar shares the
	// instrumentation but never exposes it), so its listen address is registered
	// here rather than in the shared proxycli flags. Empty (the default) disables
	// the endpoint entirely; the TEE deployment sets it to an internal address
	// (e.g. 0.0.0.0:9464) that the compose neither publishes to the host nor fronts
	// with dstack-ingress, so /metrics is reachable only over the CVM-internal
	// compose network (the co-located Prometheus-agent scraper), never publicly.
	metricsListen := flag.String("metrics-listen", os.Getenv("ZG_GATEWAY_METRICS_LISTEN"),
		"address to serve Prometheus /metrics on; empty disables it. Bind an INTERNAL "+
			"address never published through the public ingress (env ZG_GATEWAY_METRICS_LISTEN)")
	// The browser origin allowlist for CORS — a gateway-only concern, like
	// -metrics-listen above: the gateway is the form that serves browsers
	// (no-install / thin clients), while the sidecar is a single-user localhost
	// process, so the shared proxycli flags stay unchanged. The default is the 0G
	// first-party app origins (openaiproxy.DefaultAllowedOriginsCSV — a deliberate
	// subset of what the router accepts), because a page allowed to call the router
	// directly is exactly the page expected to swap its base URL to this gateway; an
	// empty value allows no origin (browser access off) and is honored as set, not
	// treated as unset.
	allowedOrigins := flag.String("allowed-origins", proxycli.EnvOr("ZG_GATEWAY_ALLOWED_ORIGINS", openaiproxy.DefaultAllowedOriginsCSV),
		"comma-separated browser origin allowlist for CORS: exact origins (https://app.example.com), "+
			"\"*.\" wildcards (https://*.0g.ai — subdomains only, not the apex), or \"*\" for any; "+
			"empty allows no origin, disabling browser access (env ZG_GATEWAY_ALLOWED_ORIGINS)")
	// Where this CVM's own identity comes from. A gateway app can be backed by
	// several replicas sharing one app_id, so without it a merged log stream and a
	// shared metrics store cannot tell them apart.
	//
	// Two sources, and the file is preferred BECAUSE it is the weaker privilege:
	// cmd/cvmid opens the guest-agent socket once at boot and writes the file, so
	// the deployed gateway — the long-lived container that sees user prompts — never
	// touches a socket that also derives keys and issues quotes. The direct socket
	// path stays for local runs and for anyone deploying without that init step.
	identityFile := flag.String("identity-file", proxycli.EnvOr("ZG_GATEWAY_IDENTITY_FILE", ""),
		"path to the identity JSON written by cmd/cvmid, read ONCE at startup for this CVM's "+
			"instance_id/app_id (used as log fields and the X-0G-Gateway-Instance response header; "+
			"metrics are labelled by the scraper, not here); takes precedence over -dstack-socket, "+
			"which the deployed form leaves unset (env ZG_GATEWAY_IDENTITY_FILE)")
	dstackSocket := flag.String("dstack-socket", proxycli.EnvOr("ZG_GATEWAY_DSTACK_SOCKET", dstack.DefaultSocket),
		"path to the dstack guest-agent unix socket, read ONCE at startup for the same identity when "+
			"-identity-file is unset; empty disables the lookup (env ZG_GATEWAY_DSTACK_SOCKET)")
	// Ceiling on concurrent sealed inference requests (see
	// openaiproxy.LimitInFlight for why a paid-per-token service still needs
	// one). The default is deliberately generous rather than tuned: it is a
	// backstop against pile-up, not a capacity plan. A streamed completion is
	// held open for its whole token schedule, so healthy in-flight counts sit far
	// above the arrival rate — loadtest/README.md walks through why — and a cap
	// set near the measured knee would start refusing traffic the gateway is
	// still serving fine. Scaled by GOMAXPROCS so it tracks the CVM it is given
	// instead of a number that silently means something different on a resize.
	//
	// GOMAXPROCS is the right input for the deployed form — a CVM is a VM, so the
	// guest sees exactly its own vCPUs. Under a container CPU QUOTA (`cpus:`) it
	// is wrong, because this Go version reads the host's core count rather than
	// the quota — but the fix there is to pin GOMAXPROCS to the quota, not to
	// hand-tune this cap around a bad reading. Pinning repairs this default for
	// free AND fixes the scheduler problem the same misreading causes (dozens of
	// Ps against a two-CPU quota, throttled at every period boundary), which no
	// value of -max-inflight can. loadtest/docker-compose.yml pins it for exactly
	// that second reason; a quota-constrained deployment should do the same.
	//
	// Replace it with a measured value once L3 (in-CVM, behind dstack-ingress)
	// has a real knee to point at; until then, too high is the safer error, since
	// too high merely fails to help while too low turns a healthy gateway into a
	// 503 source.
	defaultMaxInFlight := 256 * runtime.GOMAXPROCS(0)
	maxInFlight := flag.Int("max-inflight", proxycli.EnvIntOr("ZG_GATEWAY_MAX_INFLIGHT", defaultMaxInFlight),
		"max concurrent sealed inference requests; excess is refused with 503 + Retry-After rather than queued. "+
			"0 disables the cap (load-test rigs measuring the unbounded knee) (env ZG_GATEWAY_MAX_INFLIGHT)")
	// Mount the Go runtime profiler on the metrics listener. OFF by default and
	// deliberately not a production knob: it is the fastest way to find where a
	// load test's throughput is going (`go tool pprof
	// http://<metrics-listen>/debug/pprof/profile?seconds=30`), and it rides the
	// internal metrics port precisely because that port is never published through
	// the ingress. Enabling it in an attested deployment would also change the
	// measured compose text (app_id), so keep it to load-test CVMs.
	pprofOn := flag.Bool("pprof", proxycli.EnvBool("ZG_GATEWAY_PPROF", false),
		"serve the Go runtime profiler at /debug/pprof/ on the -metrics-listen address (requires -metrics-listen). "+
			"For load testing and diagnosis only — it exposes process internals, so never enable it on a listener "+
			"reachable from outside the CVM (env ZG_GATEWAY_PPROF)")
	// -health turns the binary into its OWN container health probe: it makes one
	// GET /healthz to the -listen port, prints the result, and exits 0 (healthy)
	// or 1 — it starts no server. The image is distroless (no shell, no curl,
	// see cmd/gateway/Dockerfile), so the compose healthcheck runs THIS instead
	// of a shell one-liner (deploy/phala/docker-compose.yml). Reusing -listen /
	// $ZG_GATEWAY_LISTEN keeps the probe and the server on the same port.
	health := flag.Bool("health", false, "probe GET /healthz on the -listen port and exit 0 (healthy) or 1; starts no server, for container healthchecks")
	flag.Parse()

	if *health {
		os.Exit(runHealthCheck(*f.Listen))
	}

	// Build validates the flags and wires the route-and-seal client core (shared
	// with the sidecar). "gateway" only labels the attestation log line. The debug
	// logger it attaches records a redaction-safe summary of any response open
	// (AEAD) failure to the enclave's process log — operator-only diagnostics
	// (field names and byte lengths, no plaintext or key material), distinct from
	// the client-facing upstream-error detail the gateway still withholds.
	// One shared logger for startup, per-request, and the core's open-failure
	// diagnostics: text records to stdout, identical to the sidecar's, so the two
	// forms don't drift (see proxycli.NewLogger). dstack/Phala captures stdout as
	// line records; a later GCP move can swap the handler in one place.
	logger := proxycli.NewLogger()

	// Learn who this CVM is, before anything else logs. It is attached to the logger
	// (so EVERY line this process emits — startup, access log, the core's
	// open-failure diagnostics — carries it) and returned to callers in the
	// X-0G-Gateway-Instance header.
	//
	// Note it does NOT label this process's metrics. Which replica a series came
	// from is a TARGET label, applied by the scraper from the same file_sd document
	// cmd/cvmid writes — the only mechanism that also reaches up and the other
	// per-scrape series, which Prometheus builds from target labels alone (see
	// client/metrics).
	//
	// Best-effort on purpose: outside a CVM there is neither file nor socket, and
	// inside one a missing init container or a wedged agent must not keep the
	// gateway from serving. Telemetry loses a dimension; the data path is
	// unaffected. It is logged at Warn rather than Info so a deployment that MEANT
	// to wire this up (deploy/phala/) and didn't sees it.
	instanceID := ""
	if info, source, err := loadIdentity(*identityFile, *dstackSocket); err != nil {
		logger.Warn("dstack identity unavailable; logs and responses carry no instance dimension",
			"source", source, "err", err)
	} else if source != "" {
		instanceID = info.InstanceID
		logger = logger.With("instance_id", info.InstanceID)
		logger.Info("dstack identity", "source", source, "app_id", info.AppID,
			"app_name", info.AppName, "compose_hash", info.ComposeHash)
	}

	built := f.Build("gateway", logger)

	// Parse the router base URL once, up front, so a malformed -router-url fails
	// loud at startup (like Build's other validation) instead of surfacing as a
	// broken catch-all on the first non-chat request. The catch-all reverse-proxies
	// every otherwise-unmatched path to this router (see newRouterProxy).
	routerTarget, err := url.Parse(*f.RouterURL)
	if err != nil || routerTarget.Scheme == "" || routerTarget.Host == "" {
		logger.Error("invalid -router-url", "url", *f.RouterURL, "err", err)
		os.Exit(1)
	}

	// Validate the origin allowlist at startup, same fail-loud stance: a pattern a
	// browser Origin can never match (a trailing slash, a missing scheme) would
	// otherwise show up only as the app it was meant to allow being blocked, with
	// nothing in the log to explain it.
	origins := openaiproxy.ParseOrigins(*allowedOrigins)
	if err := openaiproxy.ValidateOrigins(origins); err != nil {
		logger.Error("invalid -allowed-origins", "err", err)
		os.Exit(1)
	}
	for _, o := range origins {
		if o == "*" {
			// Not fatal — an operator may genuinely want an open API — but it means any
			// web page can drive this gateway with a key its own visitor holds, so it
			// should never be the accidental result of a misrendered env var.
			logger.Warn("CORS allowlist contains \"*\": every browser origin is allowed", "allowed_origins", origins)
			break
		}
	}

	// Start the background quote-cache warmer (a no-op unless -warm is set) so
	// requests hit a warm cache instead of paying the DCAP verify inline; stop it
	// on shutdown before the process exits.
	stopWarmer := built.StartWarmer(logger)

	// Serve Prometheus /metrics on its own internal listener (a no-op unless
	// -metrics-listen is set). It is deliberately a separate server from the public
	// one: the metrics address is bound to a port the compose does not publish, so
	// it never rides the same ingress as the OpenAI API surface. stopMetrics shuts
	// it down alongside the main server on a signal.
	if *pprofOn && *metricsListen == "" {
		logger.Error("-pprof requires -metrics-listen (the profiler is served on that internal listener)")
		os.Exit(1)
	}
	stopMetrics := startMetrics(*metricsListen, *pprofOn, logger)

	// Publish the ceiling before any load arrives, so an alert on
	// in-flight-approaching-the-cap has a denominator on a gateway that has not
	// been busy yet. Set here rather than inside LimitInFlight: the process has
	// one ceiling, the constructor may be called more than once (tests).
	metrics.SetInFlightLimit(*maxInFlight)
	if *maxInFlight <= 0 {
		logger.Warn("sealed-inference concurrency cap disabled; nothing bounds concurrent requests, so overload degrades every in-flight request instead of shedding the excess",
			"max_inflight", *maxInFlight)
	}

	srv := &http.Server{
		Addr:              *f.Listen,
		Handler:           newHandler(built.Client, routerTarget, origins, instanceID, *maxInFlight, logger),
		ReadHeaderTimeout: 10 * time.Second,     // mitigate slow-header (Slowloris) clients
		IdleTimeout:       proxycli.IdleTimeout, // bound idle keep-alives; unset means unbounded
	}
	// TLS is terminated ahead of this listener, inside the same enclave
	// (dstack-ingress, over the CVM-internal network — see deploy/phala/), so the
	// gateway itself serves plaintext HTTP; the enclave boundary, not this
	// listener, is the TLS edge.
	// Serve until a shutdown signal, then drain in-flight requests gracefully
	// (shared with the sidecar so both forms handle SIGTERM identically — the
	// dstack/Phala deployment sends it on every redeploy). ListenAndServe's clean
	// shutdown is folded into a nil return; only a real listen failure is an error.
	logger.Info("gateway listening", "listen", *f.Listen, "router_url", *f.RouterURL,
		"cors_allowed_origins", origins)
	err = proxycli.Serve(srv, logger)
	stopWarmer()
	stopMetrics()
	if err != nil {
		logger.Error("gateway server exited", "err", err)
		os.Exit(1)
	}
}

// loadIdentity resolves this CVM's identity from the first configured source: the
// file cmd/cvmid wrote, else the guest-agent socket directly. It returns the
// identity, the source it came from (for the log line), and any error.
//
// The file wins when both are set because it is the lower-privilege path — see
// the -identity-file flag. With neither configured it returns an empty source and
// no error: that is a deliberate local-run configuration, not a failure, so it
// must not log a warning.
func loadIdentity(identityFile, socket string) (dstack.Info, string, error) {
	switch {
	case identityFile != "":
		info, err := dstack.ReadIdentityFile(identityFile)
		return info, "file:" + identityFile, err
	case socket != "":
		ctx, cancel := context.WithTimeout(context.Background(), dstack.DefaultTimeout)
		defer cancel()
		info, err := dstack.FetchInfo(ctx, socket)
		return info, "socket:" + socket, err
	default:
		return dstack.Info{}, "", nil
	}
}

// startMetrics serves the Prometheus /metrics endpoint on its own internal
// listener and returns a stop function the caller runs at shutdown. When listen
// is empty the endpoint is disabled and stop is a no-op, so main can wire it
// unconditionally. A listen failure is logged but never fatal: metrics are
// operational telemetry, so the gateway keeps serving requests even if its
// metrics port cannot bind, rather than the observability path taking down the
// data path.
//
// withPprof additionally mounts the Go runtime profiler on the same listener
// (see the -pprof flag). It shares this listener rather than getting one of its
// own because the property that makes it safe — never published through the
// ingress, reachable only on the CVM-internal network — is a property of THIS
// listener; a second one would have to re-establish it.
func startMetrics(listen string, withPprof bool, logger *slog.Logger) (stop func()) {
	if listen == "" {
		return func() {}
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	if withPprof {
		// Registered explicitly rather than by relying on net/http/pprof's init()
		// (which only populates http.DefaultServeMux — a mux this binary never
		// serves), so what the profiler exposes is visible here at the call site.
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
		logger.Warn("pprof profiler enabled on the metrics listener", "listen", listen, "path", "/debug/pprof/")
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,     // mitigate slow-header (Slowloris) clients
		IdleTimeout:       proxycli.IdleTimeout, // bound idle keep-alives; unset means unbounded
	}
	go func() {
		logger.Info("metrics listening", "listen", listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server exited", "err", err)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// healthURLFromListen turns a -listen value (":8443", "0.0.0.0:8443", …) into the
// loopback /healthz URL the -health probe hits. The server may bind all
// interfaces, but the probe runs INSIDE the same container, so it always dials
// 127.0.0.1 on the listen port: that keeps probe and server on one port via
// $ZG_GATEWAY_LISTEN, whatever interface the server bound.
func healthURLFromListen(listen string) (string, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("cannot derive port from listen %q: %w", listen, err)
	}
	if port == "" {
		return "", fmt.Errorf("no port in listen %q", listen)
	}
	return "http://127.0.0.1:" + port + "/healthz", nil
}

// probeHealth makes one GET to url and returns nil only on a 200 — the body of
// the -health container probe (see runHealthCheck). Split out so a test can drive
// it against an httptest server without spawning a process.
func probeHealth(url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s -> %s", url, resp.Status)
	}
	return nil
}

// runHealthCheck is the -health path: resolve the loopback /healthz URL from
// -listen, probe it, and return a process exit code (0 healthy, 1 not). Because
// the image is distroless, this IS the compose healthcheck (deploy/phala/).
func runHealthCheck(listen string) int {
	url, err := healthURLFromListen(listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "health: %v\n", err)
		return 1
	}
	if err := probeHealth(url, 3*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "health: %v\n", err)
		return 1
	}
	return 0
}

// newHandler mounts the shared OpenAI proxy, the gateway-only operational route
// (health), and a catch-all that reverse-proxies every other path to the router
// (routerTarget), all wrapped in the CORS and access-log middleware so browser
// callers on an allowed origin can reach it and every request emits one
// redaction-safe structured line. It is split out from main so tests can drive it
// with httptest.
//
// instanceID, when non-empty, is stamped on every response as the serving CVM's
// id (openaiproxy.StampInstance). It is empty only when the identity lookup found
// nothing — a local run, or a deployment that wired neither source — in which case
// no stamping middleware is wired at all.
//
// maxInFlight caps concurrent sealed inference requests (0 disables it); see the
// -max-inflight flag and openaiproxy.LimitInFlight.
func newHandler(c *core.Client, routerTarget *url.URL, allowedOrigins []string, instanceID string, maxInFlight int, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	// Mount the sealed inference path behind the gateway's front-door credential
	// gate. The gate is a cheap presence/shape check (reject missing credentials
	// and mgmt keys), NOT authentication — the router stays the authoritative
	// auth/billing point and re-validates every forwarded credential. It wraps
	// only this route: /healthz must stay unauthenticated for the container probe,
	// and the catch-all metadata passthrough below is discovery the router already
	// governs. The sidecar shares openaiproxy but is single-user, so it never
	// mounts this gate.
	//
	// The concurrency cap sits INSIDE the credential gate: a request with no
	// credential or a mgmt key is rejected on shape alone, and must not hold a
	// slot a real request could have used. It covers this route only — /healthz
	// is the container's own probe and a 503 there would kill the CVM rather than
	// protect it, and the catch-all below is cheap metadata the router already
	// governs. The expensive work (seal, route preview, DCAP on a cold cache,
	// streams held open for their whole schedule) is all on this path.
	mux.Handle("POST /v1/chat/completions",
		openaiproxy.RequireInferenceCredential(
			openaiproxy.LimitInFlight(maxInFlight, openaiproxy.Handler(c))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	// The gateway exposes no /quote route: it emits no attestation quote of its
	// own. Endpoint/code identity comes from dstack-ingress's in-CVM cert-binding
	// attestation (/evidences, which commits to app_id and so covers this image);
	// see docs/design/cloud-gateway.md §6.
	//
	// Everything else — the router's non-sealed OpenAI surface (model catalog,
	// discovery) a thin client needs — is reverse-proxied to the router as-is. The
	// sealed chat route and /healthz are more specific patterns, so Go's
	// ServeMux keeps serving them; only unmatched paths fall through here. This is a
	// cleartext passthrough — safe for metadata, never for sealed content (see
	// newRouterProxy).
	mux.Handle("/", newRouterProxy(routerTarget, logger))
	// CORS wraps the whole mux, INSIDE the access log: a preflight must be answered
	// here — before the mux would hand it to the credential gate (which 401s a
	// preflight, since a browser sends no credentials on one) or to the catch-all
	// (which would let the ROUTER's allowlist decide what may reach this gateway) —
	// while still emitting the one structured line per request, preflights included.
	// StampInstance sits OUTSIDE CORS so a preflight — answered by CORS without
	// ever reaching the mux — carries the header too, and inside the access log so
	// the middleware order stays "log everything that happens below it".
	return openaiproxy.LogRequests(logger, openaiproxy.StampInstance(instanceID, openaiproxy.CORS(allowedOrigins, mux)))
}
