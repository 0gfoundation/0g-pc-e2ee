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
// every forwarded credential. The remaining multi-tenant concerns (per-user
// billing attribution, rate limiting; issue #20) are a later step. Trusting the
// router's returned endpoint (vs resolving it on chain) is tracked in issue #18.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/cmd/internal/proxycli"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
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
	stopMetrics := startMetrics(*metricsListen, logger)

	srv := &http.Server{
		Addr:              *f.Listen,
		Handler:           newHandler(built.Client, routerTarget, origins, logger),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
	}
	// TLS is terminated ahead of this listener, inside the same enclave
	// (dstack-ingress, over the CVM-internal network — see deploy/phala/), so the
	// gateway itself serves plaintext HTTP; the enclave boundary, not this
	// listener, is the TLS edge.
	// Serve until a shutdown signal, then drain in-flight requests gracefully
	// (shared with the sidecar so both forms handle SIGTERM identically — the
	// dstack/Phala deployment sends it on every redeploy). ListenAndServe's clean
	// shutdown is folded into a nil return; only a real listen failure is an error.
	logger.Info("gateway listening", "listen", *f.Listen, "router_url", *f.RouterURL, "cors_allowed_origins", origins)
	err = proxycli.Serve(srv, logger)
	stopWarmer()
	stopMetrics()
	if err != nil {
		logger.Error("gateway server exited", "err", err)
		os.Exit(1)
	}
}

// startMetrics serves the Prometheus /metrics endpoint on its own internal
// listener and returns a stop function the caller runs at shutdown. When listen
// is empty the endpoint is disabled and stop is a no-op, so main can wire it
// unconditionally. A listen failure is logged but never fatal: metrics are
// operational telemetry, so the gateway keeps serving requests even if its
// metrics port cannot bind, rather than the observability path taking down the
// data path.
func startMetrics(listen string, logger *slog.Logger) (stop func()) {
	if listen == "" {
		return func() {}
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
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
func newHandler(c *core.Client, routerTarget *url.URL, allowedOrigins []string, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	// Mount the sealed inference path behind the gateway's front-door credential
	// gate. The gate is a cheap presence/shape check (reject missing credentials
	// and mgmt keys), NOT authentication — the router stays the authoritative
	// auth/billing point and re-validates every forwarded credential. It wraps
	// only this route: /healthz must stay unauthenticated for the container probe,
	// and the catch-all metadata passthrough below is discovery the router already
	// governs. The sidecar shares openaiproxy but is single-user, so it never
	// mounts this gate.
	mux.Handle("POST /v1/chat/completions", openaiproxy.RequireInferenceCredential(openaiproxy.Handler(c)))
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
	return openaiproxy.LogRequests(logger, openaiproxy.CORS(allowedOrigins, mux))
}
