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
// dstack-ingress produces and this process serves at /evidences (-evidence-dir; see
// evidenceRoute for why the serving side moved here) — its quote commits to app_id,
// which covers this gateway image too (see deploy/phala/ and
// docs/design/cloud-gateway.md §6). Inference authenticity rides the provider's
// own SPEC §8 response signature, which the gateway verifies
// (ZG_GATEWAY_VERIFY_RESPONSES). So the gateway exposes no /quote route. It does
// serve a self-DESCRIPTION at /v1/gateway/identity (app_id, compose hash, OS image,
// container list, matching release — see identity.go), which is display material for
// a browser panel and deliberately not evidence: it is parsed, not signed, and every
// value in it is what pcverify independently rederives.
//
// The provider half of that panel is /v1/providers/{address}/identity (see
// provideridentity.go): what this gateway VERIFIED about a provider before sealing to
// it — the DCAP verdict on that provider's quote, the on-chain signer comparison, the
// boot-chain verdict, its compose hash. Unlike the self-description it DOES report
// verdicts, because unlike the self-description those are verifications this process
// genuinely performed, on a third party. They are still relayed rather than the
// reader's own, it answers only for providers already used, and it never fetches
// anything.
//
// The sealed inference path carries a front-door credential gate
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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/cmd/internal/proxycli"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/dstack"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
)

// defaultRouterURL is what -router-url falls back to: the router's OWN name,
// NOT the public entry.
//
// This gateway serves the public entry, so pointing it at that name would make
// every passthrough request and every route-preview re-enter its own front door
// and recurse. It is a named constant rather than the call-site argument so a
// test can assert the binary's default without running it — see
// TestGatewayDefaultsToTheRouterCloudNameNotThePublicEntry.
const defaultRouterURL = route.DefaultRouterCloudURL

func main() {
	f := proxycli.RegisterFlags(flag.CommandLine, "ZG_GATEWAY", ":8443", defaultRouterURL)
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
	// Cookie credentials have NO FLAG: the router's HttpOnly `jwt` cookie is accepted
	// whenever the origin allowlist can vouch for a request, and the CORS answer is
	// credentialed to match. There was a `-allow-cookie-credential` here and it was
	// removed rather than re-defaulted; the reasoning is worth keeping because it is
	// the kind that looks prudent while costing something.
	//
	// The flag's "off" position protected nothing that was not already inert. The
	// router's session cookie is host-only (AUTH_COOKIE_DOMAIN is unset in
	// production, so the browser scopes it to the exact host that set it), so on any
	// deployment where this gateway serves some OTHER hostname no cookie can reach it
	// and there is nothing to admit. The CORS half was equally quiet: a caller that
	// sends no credentials ignores Access-Control-Allow-Credentials entirely, which is
	// what today's callers do.
	//
	// Its "on" requirement, meanwhile, was absolute and undetectable. Per the Fetch
	// spec's CORS check, a request whose credentials mode is "include" fails as a
	// NETWORK ERROR unless the response carries Access-Control-Allow-Credentials:
	// true — whether or not a cookie was actually sent. The first-party web app sets
	// `credentials: 'include'` on EVERY router call (0g-compute-new,
	// web-ui/src/shared/lib/routerClient.ts — both the JSON and the streaming helper),
	// so a gateway serving the router's hostname without it breaks the model catalog,
	// the provider list and the balance read along with chat. And this process cannot
	// tell whether it is in that topology: it only learns its public name from the
	// Host header, which the caller controls (see identity.go for why it refuses to
	// echo that back as its own). So the flag could not default correctly and could
	// not warn — it could only be forgotten, in the direction that breaks everything
	// with a CORS error rather than a 401. Removing it removes that failure mode; it
	// was the flag's existence, not its default, that created it.
	//
	// What remains is the guard below: an allowlist of "*" turns cookie admission and
	// the credentialed CORS answer back OFF. That combination is the one genuinely
	// unsafe shape (any page acting as a logged-in visitor), and refusing it by
	// degrading rather than by failing startup keeps the open-API deployment possible
	// — an API open to every origin is a keys-only API, which is the coherent reading
	// of "*" anyway.
	//
	// Which models this deployment seals — and so whether it seals at all. See
	// sealModels for why the dial is the model and deliberately not a percentage,
	// and parseSealModels for why "seal nothing" is a word rather than an empty value.
	sealModelsCSV := flag.String("seal-models", proxycli.EnvOr("ZG_GATEWAY_SEAL_MODELS", sealModelsAll),
		"which models to seal: \""+sealModelsAll+"\" (the default) seals every model; a comma-separated "+
			"list of model ids seals only those and proxies every other model to the router in the "+
			"clear, marked "+openaiproxy.HeaderE2EE+": "+openaiproxy.E2EEValueNone+"; \""+sealModelsOff+"\" "+
			"seals nothing, which makes this gateway behave as the plain router. An entry '<service "+
			"type>:*' (e.g. 'embedding:*') seals every model on that service type's surfaces. Empty "+
			"is refused rather than read as either end (env ZG_GATEWAY_SEAL_MODELS)")
	// Directory holding the public attestation evidence bundle to serve at
	// /evidences/ — in the TEE deployment, the `evidences` volume dstack-ingress
	// writes, mounted read-only. Empty (the default) mounts no such route, which is
	// right for a local run and for any deployment where the ingress still serves
	// the bundle itself. Why the gateway serves public attestation data at all, and
	// why that does not weaken the trust story: evidenceRoute.
	evidenceDir := flag.String("evidence-dir", proxycli.EnvOr("ZG_GATEWAY_EVIDENCE_DIR", ""),
		"directory to serve the public attestation evidence bundle from at /evidences/ (the read-only "+
			"dstack-ingress `evidences` volume); empty mounts no such route. Served with "+
			"Access-Control-Allow-Origin: * so browser verifiers can read it (env ZG_GATEWAY_EVIDENCE_DIR)")
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
	// Ceiling on concurrent sealed inference requests — see
	// openaiproxy.LimitInFlight for why a paid-per-token service still needs one,
	// and defaultMaxInFlight for how the built-in number is derived and why it is
	// bounded on two axes rather than one.
	maxInFlight := flag.Int("max-inflight", proxycli.EnvIntOr("ZG_GATEWAY_MAX_INFLIGHT", defaultMaxInFlight()),
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
	// Where /v1/gateway/identity's container list comes from: the manifest cmd/cvmid
	// wrote to the shared identity volume. It is the only source: it needs no network,
	// no third-party host and no DNS — and, like -identity-file, it keeps the gateway
	// off the guest-agent socket. The bytes are checked against the quote's
	// compose_hash before anything is read out of them, so an absent or stale file
	// costs the container list and nothing else.
	appComposeFile := flag.String("app-compose-file", proxycli.EnvOr("ZG_GATEWAY_APP_COMPOSE_FILE", ""),
		"path to the app-compose.json written by cmd/cvmid, read for "+identityPath+"'s container "+
			"list after checking it against the quote's compose_hash; empty reports no container "+
			"list (env ZG_GATEWAY_APP_COMPOSE_FILE)")
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
	instanceID, runtimeAppID := "", ""
	if info, source, err := loadIdentity(*identityFile, *dstackSocket); err != nil {
		logger.Warn("dstack identity unavailable; logs and responses carry no instance dimension",
			"source", source, "err", err)
	} else if source != "" {
		instanceID, runtimeAppID = info.InstanceID, info.AppID
		logger = logger.With("instance_id", info.InstanceID)
		logger.Info("dstack identity", "source", source, "app_id", info.AppID,
			"app_name", info.AppName, "compose_hash", info.ComposeHash)
	}

	built := f.Build("gateway", logger, proxycli.Serves(endpoint.All...))

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
	// An allowlist of "*" allows every browser origin. Not fatal — an operator may
	// genuinely want an open API — but it means any web page can drive this gateway
	// with a key its own visitor holds, so it should never be the accidental result of
	// a misrendered env var.
	//
	// It also turns ambient credentials OFF, and that is the load-bearing half. The
	// origin allowlist is the whole CSRF defense for a cookie (see
	// openaiproxy.AcceptCookieCredential): a cookie is attached by the browser without
	// the page asking, so "any origin may authenticate by cookie" means any page on the
	// internet can spend a logged-in visitor's balance and simply not read the reply.
	// "*" is precisely the configuration that makes the origin gate pass everything,
	// silently, while looking like a working deployment.
	//
	// So the two are mutually exclusive by construction rather than by a startup
	// refusal: with "*" this gateway is keys-only, which is the coherent reading of an
	// API open to every origin anyway. Degrading rather than exiting keeps that
	// deployment possible, and keeps the unsafe combination unreachable without
	// anybody having to remember a rule.
	openOrigins := false
	for _, o := range origins {
		if o == "*" {
			openOrigins = true
			logger.Warn("CORS allowlist contains \"*\": every browser origin is allowed, and cookie "+
				"credentials are therefore DISABLED (an ambient credential plus an unrestricted origin "+
				"allowlist would let any page act as a logged-in visitor). Callers must authenticate with "+
				"an Authorization header; name the origins explicitly to allow cookie authentication",
				"allowed_origins", origins)
			break
		}
	}

	// A -seal-models value this cannot read decides whether prompts are encrypted at
	// all, so it fails the deploy rather than guessing: falling back to sealing every
	// model would turn a deployment that meant to be transparent into a silent release
	// of default encryption, and falling back to sealing nothing would silently stop
	// encrypting for everyone already relying on it. The same goes for a
	// `<service type>:*` entry naming no surface, which would leave that surface in
	// the clear while reading as configured. See parseSealModels for what is refused.
	sealModelsList, err := parseSealModels(*sealModelsCSV)
	if err != nil {
		logger.Error("invalid -seal-models", "value", *sealModelsCSV, "err", err)
		os.Exit(1)
	}

	// Same stance for the evidence bundle's directory: a mount this process cannot
	// read would answer 404 to every verifier and look, from outside, exactly like
	// the CORS hole this route exists to close (#73) — silent, and with no signal
	// until someone tries to verify the deployment. See checkEvidenceDir for why the
	// check is narrow, and for the blast radius of exiting here.
	if *evidenceDir != "" {
		if err := checkEvidenceDir(*evidenceDir); err != nil {
			logger.Error("invalid -evidence-dir", "dir", *evidenceDir, "err", err)
			os.Exit(1)
		}
	}

	// Assemble this CVM's self-description in the background (see identity.go). It
	// deliberately does not gate startup: every input is optional, the first pass is
	// two file reads plus one GitHub call, and a slow or unreachable lookup must
	// delay serving by nothing at all. stopIdentity joins the builder at shutdown.
	//
	// A missing -evidence-dir leaves QuotePath empty, which turns off app_id,
	// compose_hash and os_image together — they all come out of the same quote — and
	// the endpoint then reports the instance id and nulls. That is the local-run
	// shape, and it is a legitimate one: the route stays honest about knowing
	// nothing rather than being absent.
	//
	// Always mounted: it publishes nothing that /evidences/ and the published
	// releases do not already make public, so there is no deployment it should be
	// hidden from, and a verification panel that silently shows nothing is worse than
	// one that shows nulls.
	//
	// The embedded allowlist. A failure here is a mistake in THIS repository (a
	// malformed osimages.json), not anything about the deployment — loud, but never
	// fatal: an operational display must not be able to take the inference path
	// down. The endpoint then reports os_image as null.
	osImages, err := evidence.BuiltinOSImages()
	if err != nil {
		logger.Error("embedded OS-image allowlist is malformed; identity will report no OS image", "err", err)
	}
	quotePath := ""
	if *evidenceDir != "" {
		quotePath = filepath.Join(*evidenceDir, evidenceQuoteFile)
	}
	identity, stopIdentity := startIdentity(identityConfig{
		InstanceID:     instanceID,
		AppID:          runtimeAppID,
		QuotePath:      quotePath,
		AppComposePath: *appComposeFile,
		Releases:       defaultIdentityReleases,
		Chain:          built.ChainRoot(),
		OSImages:       osImages,
		Timeout:        identityLookupTimeout,
	}, logger)

	// The provider-side records (GET /v1/providers/{address}/identity, see
	// provideridentity.go). Nil — so the route stays unmounted — whenever this build
	// can never produce one: direct-broker mode (no on-chain provider address to key a
	// record by) or -attest off (nothing verified).
	providerIdentities := built.ProviderIdentities()

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
		Addr: *f.Listen,
		Handler: newHandler(built.Clients, routerTarget, origins, instanceID, *evidenceDir, *maxInFlight,
			identity, providerIdentities, built.Readiness(), logger,
			withEntryPolicy(entryPolicy{
				openOrigins: openOrigins,
				sealModels:  sealModelsList,
			})),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
		// Backstop for every route: see serverReadTimeout. The sealed inference
		// routes are bounded tighter, from admission, by defaultBodyReadTimeout.
		ReadTimeout: serverReadTimeout,
		IdleTimeout: proxycli.IdleTimeout, // bound idle keep-alives; unset means unbounded
	}
	// TLS is terminated ahead of this listener, inside the same enclave
	// (dstack-ingress, over the CVM-internal network — see deploy/phala/), so the
	// gateway itself serves plaintext HTTP; the enclave boundary, not this
	// listener, is the TLS edge.
	// Serve until a shutdown signal, then drain in-flight requests gracefully
	// (shared with the sidecar so both forms handle SIGTERM identically — the
	// dstack/Phala deployment sends it on every redeploy). ListenAndServe's clean
	// shutdown is folded into a nil return; only a real listen failure is an error.
	// max_inflight is on this line because the deployed value is DERIVED (from
	// GOMEMLIMIT and the core count — see defaultMaxInFlight), so unlike a flag
	// that is simply echoed back, nobody can read the config and know what the
	// gateway settled on. The same value is published as zg_gateway_inflight_limit;
	// the log is what an operator reaches for first.
	//
	// go_memlimit_bytes and gomaxprocs come with it because they are its INPUTS,
	// and the failure worth catching is a GOMEMLIMIT set above the machine's actual
	// RAM — which is silent (Go never reaches a limit it cannot allocate up to, so
	// the OOM killer arrives first) and leaves the cap sized for memory that does
	// not exist. Logging all three puts the assumption next to what it produced, so
	// comparing it against the CVM's real shape is a glance rather than an
	// investigation. math.MaxInt64 means unset.
	//
	// evidence_dir is on this line because the route is invisible otherwise: it is
	// mounted or not depending on one env var, and an operator debugging "why does
	// /evidences 404" needs to see which side of that the process is on. Empty means
	// the route is not mounted at all.
	//
	// provider_identity_endpoint reports whether that route is MOUNTED: it needs
	// -attest (nothing to report without it), and "silently absent" is precisely the
	// diagnosis an operator would otherwise have to reconstruct from another flag.
	logger.Info("gateway listening", "listen", *f.Listen, "router_url", *f.RouterURL,
		"seal_models", *sealModelsCSV,
		"cors_allowed_origins", origins, "max_inflight", *maxInFlight,
		"evidence_dir", *evidenceDir,
		"provider_identity_endpoint", providerIdentities != nil,
		"go_memlimit_bytes", currentMemoryLimit(), "gomaxprocs", runtime.GOMAXPROCS(0))
	err = proxycli.Serve(srv, logger)
	stopWarmer()
	stopIdentity()
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

// entryPolicy holds what a deployment says about the shape it is serving.
//
// The zero value is the ORDINARY deployment: a named origin allowlist, so ambient
// credentials are on, and every model sealed. The fields therefore name the
// exception rather than the rule, which is deliberate — a caller that passes no
// option (every test that is about something else, and any future call site) gets
// the configuration a real gateway runs, not a stripped-down one. Getting that
// backwards is how a test ends up asserting against a shape nothing deploys.
type entryPolicy struct {
	// openOrigins reports that the allowlist contains "*", i.e. every browser origin
	// is allowed. It turns AMBIENT CREDENTIALS OFF — no cookie admission
	// (openaiproxy.AcceptCookieCredential) and no credentialed CORS answer — because
	// the origin allowlist is the entire CSRF defense for a cookie, and "*" makes that
	// defense pass everything. See the startup warning for the full reasoning; the
	// short version is that an API open to every origin is a keys-only API.
	openOrigins bool
	// sealModels decides WHICH models are sealed, and with sealModelsOff whether
	// anything is. Its zero value seals ALL — the same zero-value-is-the-ordinary-
	// deployment rule as the field above.
	sealModels sealModels
	// catalogCacheTTL is how long a public catalog read is reused (catalogcache.go).
	//
	// ZERO MEANS defaultCatalogCacheTTL, not "off". That reads backwards for a
	// duration, and it is the point: the ordinary deployment caches, so per this
	// type's contract the zero value has to be the one that does. A NEGATIVE value
	// turns it off. Not a flag: a deployment has no reason to change it, so only
	// tests set it.
	catalogCacheTTL time.Duration
	// bodyReadTimeout bounds a sealed-path body read (openaiproxy.BoundBodyRead).
	// Same convention as catalogCacheTTL: ZERO MEANS defaultBodyReadTimeout, and a
	// negative value turns it off.
	bodyReadTimeout time.Duration
}

// serverReadTimeout bounds reading any request, headers and body, on the public
// listener. It is the backstop for the routes defaultBodyReadTimeout does not
// cover — the catch-all, which streams bodies to the router unbuffered and holds no
// in-flight slot, so a slow body there costs a connection (dstack-ingress allows
// 4096 in all) rather than a slot. The router already ends such a body at its own
// ReadTimeout (60 s by default); this keeps the bound from depending on it, and
// sits above it so an upload the router accepts is never cut here first.
// net/http lifts it at the body's EOF, so it does not reach a streamed response.
const serverReadTimeout = 90 * time.Second

// defaultBodyReadTimeout is how long a sealed-path request's body may take to
// arrive once it holds an in-flight slot (openaiproxy.BoundBodyRead); past it the
// request is answered 408 and its slot freed. Without it a client that sends
// headers and trickles the body holds a slot indefinitely.
//
// It is long enough for the largest body these routes admit — maxPassthroughBytes
// (20 MiB), a chat turn carrying a video — on a ~2.8 Mbit/s uplink, and far
// shorter than the time a trickled body could otherwise hold a slot, which was
// unbounded.
const defaultBodyReadTimeout = 60 * time.Second

// bodyRead resolves bodyReadTimeout's zero value to the default; a negative one
// is returned as-is, which BoundBodyRead reads as disabled.
func (p entryPolicy) bodyRead() time.Duration {
	if p.bodyReadTimeout == 0 {
		return defaultBodyReadTimeout
	}
	return p.bodyReadTimeout
}

// newCatalogCache builds this deployment's catalog cache, resolving the zero
// value to the default TTL. One cache per handler: it holds no cross-handler
// state, and a package-level one would leak entries between the gateways a test
// binary stands up.
func (p entryPolicy) newCatalogCache() *catalogCache {
	ttl := p.catalogCacheTTL
	if ttl == 0 {
		ttl = defaultCatalogCacheTTL
	}
	return newCatalogCache(ttl) // nil when ttl < 0, i.e. explicitly disabled
}

// credentialsAllowed reports whether this deployment participates in ambient
// browser credentials. One predicate for the two places that must agree: the
// cookie middleware and the CORS answer. Splitting them would let a deployment
// read a cookie the browser will not send, or advertise credentials it then
// refuses — both of which fail as a CORS error rather than as an auth error, which
// is the hardest shape to diagnose.
func (p entryPolicy) credentialsAllowed() bool { return !p.openOrigins }

// sealingOn reports whether this deployment seals the inference surfaces at all.
// Only an explicit sealModelsOff turns it off; the zero value seals.
func (p entryPolicy) sealingOn() bool { return !p.sealModels.off }

// canonicalPath serves r through h with r.URL.Path replaced by path, for the one
// case where two spellings name one resource and only one of them is registered
// downstream (a sealed surface and its trailing-slash form).
//
// It copies the request and the URL rather than assigning to r.URL.Path: the
// middleware above still holds the original — the access log reads it after h
// returns — and a handler that edits its caller's request in place is the kind of
// action at a distance that is fine until something else reads the field.
//
// RawPath is cleared along with it. url.EscapedPath prefers RawPath when it is a
// valid encoding of Path, so leaving a stale one behind would have ServeMux match
// the ORIGINAL spelling while every later reader sees the rewritten one — which is
// the precise shape of the bug this exists to close.
func canonicalPath(path string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, withPath(r, path))
	})
}

func withPath(r *http.Request, path string) *http.Request {
	r2 := *r
	u := *r.URL
	u.Path = path
	u.RawPath = ""
	r2.URL = &u
	return &r2
}

// sealedNamespaceGuard makes a sealed surface's namespace claim hold for every
// SPELLING of a path, not just the canonical one, by folding the surface prefix to
// its registered form before the mux ever sees the request.
//
// ServeMux cannot express this claim on its own, and the two gaps both end the same
// way — at the catch-all, which is a cleartext reverse proxy to the untrusted
// router:
//
//   - It matches on the ESCAPED path, segment by segment. `%2F` is therefore an
//     ordinary character inside one segment rather than a separator, so
//     `/v1/chat/completions%2F` matches neither `POST /v1/chat/completions` nor the
//     `/v1/chat/completions/` subtree.
//   - It is case-SENSITIVE, so `/V1/chat/completions` matches nothing either.
//
// Both were confirmed against the real handler: 200, and the whole prompt in the
// router's log. Like the literal trailing slash before them, they are invisible to
// the caller — the router's gin answers the decoded path with a 307 onto the
// canonical one, the retry is served properly, and only the first request leaked.
// Claiming the exact path, the subtree and the `{$}` anchor closes three spellings;
// this closes the rest by construction, which is the only way to stop enumerating.
//
// FOLDING CASE IS A DELIBERATE WIDENING, and worth naming. The router is
// case-sensitive too, so `/V1/chat/completions` would 404 there; here it is served
// as the sealed surface. That is the trade being made: a path's capitalisation is
// not a security boundary anywhere sane, and treating it as one is exactly what
// produced the leak. Answering the request is also the friendlier half — the
// alternative, refusing it, would mean inventing an error for a spelling whose only
// real-world senders are probes and sloppy clients.
//
// It runs OUTSIDE the mux and inside CORS: a preflight must still be answered by
// the CORS layer, and the guard has nothing to say about a request that never
// reaches a handler.
func sealedNamespaceGuard(surfaces []string, mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path is the DECODED path, which is what makes the %2F case visible
		// here at all: net/http has already turned it back into a separator, while
		// ServeMux went on to match the escaped form.
		p := r.URL.Path
		for _, surface := range surfaces {
			switch {
			case strings.EqualFold(p, surface):
				r = withPath(r, surface)
			case len(p) > len(surface) && strings.EqualFold(p[:len(surface)+1], surface+"/"):
				// A sub-resource: fold only the surface prefix and leave the rest
				// verbatim, so the namespace handler decides it exactly as it decides
				// the canonical spelling.
				r = withPath(r, surface+p[len(surface):])
			default:
				continue
			}
			// Rewritten UNCONDITIONALLY on a match, with no "only if it differs" short
			// circuit. The escaping is half of what is being normalised and it does not
			// show up in this comparison: `/v1/chat/completions%2F` already has the
			// canonical Path — net/http decoded it — and differs only in RawPath, which
			// is the field ServeMux actually matches on. Skipping the rewrite because
			// the decoded strings agree is precisely how that spelling stayed leaking
			// after the case variants were fixed. withPath clears RawPath, so one
			// unconditional call normalises both axes.
			break
		}
		mux.ServeHTTP(w, r)
	})
}

// handlerOption configures newHandler's entryPolicy. It is variadic and last so
// the callers with no opinion — every test that is about something else — keep
// naming only what they care about.
type handlerOption func(*entryPolicy)

// withEntryPolicy sets the whole policy in one call, which is how main passes it:
// both fields come from the same startup validation and mean one thing together.
func withEntryPolicy(p entryPolicy) handlerOption {
	return func(dst *entryPolicy) { *dst = p }
}

// newHandler mounts the shared OpenAI proxy, the gateway-only operational routes
// (health and readiness), and a catch-all that reverse-proxies every other path to
// the router (routerTarget), all wrapped in the CORS and access-log middleware so
// browser callers on an allowed origin can reach it and every request emits one
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
//
// evidenceDir, when non-empty, mounts the public attestation bundle at /evidences/
// from that directory (see evidenceRoute). Empty leaves the route unmounted, so
// those paths fall through to the catch-all like any other unknown path.
//
// identity, when non-nil, mounts this CVM's self-description at
// /v1/gateway/identity. Nil leaves the route unmounted — the same fall-through as
// an unset evidenceDir — which is what every test that is not about the route
// gets. main always passes one.
//
// providerIdentities, when non-nil, mounts the provider-side counterpart at
// /v1/providers/{address}/identity: what this gateway verified about the providers
// it sealed to. Nil leaves it unmounted, which is what a build that verifies no
// quotes gets — see main's wiring and proxycli.Built.ProviderIdentities.
//
// ready backs GET /readyz: nil means there is nothing to assert (no warmer
// configured) and the route always answers ready. See proxycli.Built.Readiness and
// the /healthz vs /readyz split at the routes below.
//
// opts carries the entryPolicy. Passing NONE is the ordinary deployment — ambient
// credentials on, every model sealed — because the policy's fields name the
// exceptions rather than the rule (see entryPolicy). main always passes one, built
// from the allowlist and -seal-models; every test that is about
// something else passes none and gets the shape a real gateway runs.
func newHandler(clients map[string]*core.Client, routerTarget *url.URL, allowedOrigins []string, instanceID, evidenceDir string,
	maxInFlight int, identity *identityCache, providerIdentities route.ProviderIdentitySource,
	ready func() error, logger *slog.Logger, opts ...handlerOption) http.Handler {
	var policy entryPolicy
	for _, opt := range opts {
		opt(&policy)
	}
	// The cleartext passthrough to the router, built once: it is the catch-all, and
	// it is also what a sealed surface's namespace resolves to. Marked as unencrypted at the one place every cleartext response
	// leaves this process, so no route can forget to say so.
	//
	// Two wrappings of ONE proxy (one connection pool): the namespace handler gets
	// the plain one, the catch-all gets the catalog cache. The marker is the OUTER
	// layer in both, so it is applied per request rather than stored and replayed —
	// a cached response that carried its own marker would be a second place the
	// cleartext claim is made, and the one that could go stale.
	sealingOn := policy.sealingOn()
	routerProxy := newRouterProxy(routerTarget, logger)
	passthrough := openaiproxy.MarkE2EE(openaiproxy.E2EEValueNone, routerProxy)
	cachedPassthrough := openaiproxy.MarkE2EE(openaiproxy.E2EEValueNone,
		policy.newCatalogCache().wrap(routerProxy))
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
	// slot a real request could have used. It covers these routes only — /healthz
	// is the container's own probe and a 503 there would kill the CVM rather than
	// protect it, and the catch-all below is cheap metadata the router already
	// governs. The expensive work (seal, route preview, DCAP on a cold cache,
	// streams held open for their whole schedule) is all on this path.
	//
	// ONE gate object, mounted on both sealed routes, dispatching through an inner
	// mux. Every LimitInFlight call builds its OWN semaphore, so wrapping each
	// route separately would have made the process ceiling 2 × maxInFlight while
	// zg_gateway_inflight_limit still published one number — doubling the peak
	// memory that ceiling is derived from (see defaultMaxInFlight) and putting the
	// wrong denominator under every in-flight/limit alert.
	//
	// The E2EE marker is the OUTERMOST layer, so it is on the gate's own 401/403 and
	// the limiter's 503 too. Those are refusals rather than sealed exchanges, but
	// they are refusals FROM the sealed path, and a client that keys on the header
	// reads "sealed" as "this path would have sealed it" — which is the honest
	// answer, and better than an error whose header is absent and so
	// indistinguishable from a cleartext one.
	//
	// The cookie conversion sits outside the gate and inside the marker: it must run
	// BEFORE the gate, since its whole job is to turn a credential the gate does not
	// recognise into one it does. It is mounted for every deployment except one whose
	// allowlist is "*", where the origin gate it depends on would admit everything.
	sealed := http.NewServeMux()
	// Per-model routing goes INSIDE the credential gate and the in-flight cap, and
	// the ordering is the point rather than a detail.
	//
	// The dispatcher has to read the body to find the model. Mounted outside, that
	// read happens before either guard, so an unauthenticated caller could make
	// this process buffer a 9 MiB body and only then receive its 401 — which
	// contradicts LimitInFlight's own contract ("rejected on shape alone … must
	// not consume a slot") and invalidates computeMaxInFlight, whose ceiling is
	// derived from how many requests can be buffering at once. There is no global
	// MaxBytesHandler, and the only read bound outside the cap is the listener's
	// 90 s serverReadTimeout backstop, so a body fed in slowly could hold that
	// buffer for that long while holding no slot and carrying no credential.
	//
	// Both branches sit inside the cap, cleartext included: that branch buffers
	// exactly as much as the sealed one, so leaving it outside would put the same
	// memory beyond the ceiling by another door.
	//
	// Built ONCE here rather than per row — it does not depend on the endpoint —
	// and it returns the mux unchanged when no model list is configured, so the
	// ordinary deployment keeps the exact chain it had.
	//
	// A keyed async poll (SPEC §7.5.4) shares the gate: it carries a credential,
	// buffers up to a full sealed image result, and opens it, so it belongs under
	// the same credential check and the same in-flight ceiling. It is routed
	// AROUND the model dispatcher, not through it — a poll has no body and no
	// model, and the dispatcher's question ("is this model sealed?") has no
	// answer for it.
	gated := http.NewServeMux()
	gated.Handle("GET "+openaiproxy.AsyncJobsPrefix+"{id}",
		openaiproxy.AsyncJobPoll(routerTarget, &http.Client{Transport: core.NewPooledTransport()}))
	gated.Handle("/", policy.sealModels.dispatch(sealed, passthrough))
	// The body-read bound sits INSIDE the cap, so its clock starts when a slot is
	// held — the slot is what a trickled body would otherwise keep — and outside
	// everything that reads the body, the model dispatcher included.
	var sealedGate http.Handler = openaiproxy.RequireInferenceCredential(
		openaiproxy.LimitInFlight(maxInFlight, openaiproxy.BoundBodyRead(policy.bodyRead(), gated)))
	if policy.credentialsAllowed() {
		sealedGate = openaiproxy.AcceptCookieCredential(allowedOrigins, sealedGate)
	}
	sealedGate = openaiproxy.MarkE2EE(openaiproxy.E2EEValueSealed, sealedGate)
	// Every row of endpoint.All is mounted, as one of two things: the sealed
	// handler behind the shared gate when this build holds a client for it, or
	// an explicit refusal when it does not (direct-broker mode, whose single
	// configured broker URL is chat-shaped).
	//
	// The refusal is NOT optional. Leaving an unserved row unmounted is not inert:
	// the catch-all below is a reverse proxy to the router, and routerTarget is
	// parsed in every mode, so an unmounted sealed path forwards the caller's
	// PROMPT to the router in cleartext — the one thing this gateway exists to
	// prevent. Fail closed.
	//
	// Enumerating the table is what makes that hold by construction rather than
	// by someone remembering: a row added to endpoint.All is either served or
	// refused here, and cannot fall through. Before this loop the two ends — the
	// inner mux that serves and the outer mux that stands between a path and the
	// catch-all — each named the rows by hand, and a divergence between them was
	// exactly the leak described above.
	//
	// A row also claims its SUBTREE — the namespace, not a list of known
	// sub-resources, which would go stale the day the API grows another one. An
	// Anthropic SDK's messages.count_tokens() POSTs the whole conversation and system
	// prompt to /v1/messages/count_tokens, and Message Batches (/v1/messages/batches)
	// carries the same payload; neither is sealed by this gateway.
	//
	// The namespace is FORWARDED to the router, in the clear, and marked X-0G-E2EE:
	// none so the caller can see what it got. That is a deliberate trade, not an
	// oversight: this gateway IS the router's hostname (the global entry), so a client
	// has no other door to take those requests to, and refusing them would not point
	// it elsewhere — it would delete the feature. The leak is real and disclosed
	// rather than silent. (A `refuse` mode answering 501 existed for a deployment
	// beside a router callers could still reach directly; no deployment had that shape
	// any longer, and it was removed.)
	//
	// Claiming the namespace explicitly rather than leaving it to the catch-all still
	// matters: it routes these prompt-carrying requests through the PLAIN passthrough,
	// never the catalog cache, and it is what lets the trailing-slash form below be
	// pinned to the sealed POST instead of the namespace.
	//
	// Either way the sealed POST is untouched: it seals, or it is refused on a build
	// with no client for it. Nothing that WOULD have been sealed lands on the
	// cleartext path.
	// Collected for sealedNamespaceGuard, which has to fold every spelling of these
	// prefixes before the mux matches. Built from the same table the loop registers
	// from, so a row added later is guarded the day it lands.
	surfaces := make([]string, 0, len(endpoint.All)+1)
	for _, ep := range endpoint.All {
		surfaces = append(surfaces, ep.Path)
	}
	// The async poll namespace too, though it is not a row: a keyed poll's PATH
	// carries the job's private key, so a spelling that missed the poll route
	// (/V1/…, %2F) reached the cleartext catch-all and handed the key to the
	// router. Folded here, every spelling lands on the routes registered below.
	surfaces = append(surfaces, strings.TrimSuffix(openaiproxy.AsyncJobsPrefix, "/"))
	for _, ep := range endpoint.All {
		surface := ep.Path
		// The subtree, and the exact path on every method but the sealed POST, go to
		// the cleartext passthrough (see above). The method-less exact pattern is the
		// LESS specific of the two on that path, so `POST <path>` below still wins for
		// the sealed method; without it Go's ServeMux answers a slash-less request with
		// an implicit 307 into the subtree (a redirect nobody asked for).
		//
		// The PLAIN passthrough, never the cached one: these carry prompts. The cache
		// would refuse them anyway (allowlist, GET-only), and that is exactly why it
		// should not be in the way — the safety of this path must not rest on a list
		// somewhere else being right.
		mux.Handle(surface+"/", passthrough)
		mux.Handle(surface, passthrough)
		// Sealing off (-seal-models=off): this gateway is a transparent proxy for the
		// whole surface, POST included — it lands on the two patterns above because no
		// more specific `POST <path>` is registered. Nothing here is a leak the way an
		// unmounted row would be: cleartext to the router IS the configured behaviour,
		// and every response says so (X-0G-E2EE: none, applied by the marker around
		// `passthrough`).
		if !sealingOn {
			continue
		}
		if c := clients[ep.Path]; c != nil {
			// WithCleartext: an async submit asking for url format goes to the
			// router in the clear rather than being refused (see the option).
			openaiproxy.Register(sealed, ep, c, openaiproxy.WithCleartext(passthrough))
			mux.Handle("POST "+ep.Path, sealedGate)
			// ...and the surface's own TRAILING-SLASH form, which belongs to the sealed
			// POST and not to the subtree however much it looks like the latter.
			//
			// To Go's ServeMux, `POST /v1/chat/completions/` matches the subtree pattern
			// `/v1/chat/completions/` — `POST /v1/chat/completions` does not match a path
			// with a trailing slash, so it would land on the namespace's reverse proxy
			// and be answered 200 with the WHOLE PROMPT forwarded to
			// the router in the clear: exactly the leak the subtree claim exists to
			// prevent, reached by a single character, and invisible to the caller because
			// the router's gin then 307s the retry onto the real path and it works.
			//
			// `{$}` anchors the pattern to that one path (Go 1.22), so this claims the
			// surface's own slashed form and nothing beneath it. The path is rewritten to
			// the canonical form rather than redirected: the inner sealed mux registers
			// only `POST <path>`, a 308 would make every caller re-send its body, and a
			// caller that reached this surface through the router got the request SERVED
			// rather than refused — which is the behaviour the cutover has to preserve.
			mux.Handle("POST "+ep.Path+"/{$}", canonicalPath(ep.Path, sealedGate))
			continue
		}
		// The same envelope every other gateway-origin error uses (WriteError:
		// json-encoded, so the path cannot break the body, and attributed to
		// "gateway" in _0g.source so a thin client keys fault attribution off one
		// field). The old hand-rolled body was type "invalid_request_error" with no
		// attribution — the one gateway error a client could not attribute.
		//
		// Registered on the trailing-slash form too, for the reason above: an unserved
		// row must refuse BOTH spellings, or the namespace passthrough would forward
		// the prompt of a surface this build cannot seal.
		path := ep.Path
		unserved := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openaiproxy.WriteError(w, http.StatusNotImplemented, "gateway",
				fmt.Sprintf("sealed POST %s is not served by this gateway build", path))
		})
		mux.Handle("POST "+path, unserved)
		mux.Handle("POST "+path+"/{$}", unserved)
	}
	// The async poll (SPEC §7.5.4), registered whatever -seal-models says: a poll carries no model to decide on, and a job sealed by an
	// earlier configuration must stay readable. The job id decides. With a key
	// segment it is a job this gateway sealed — opened through the gate; without
	// one, the cleartext passthrough, which refuses to relay a sealed frame.
	keylessPoll := openaiproxy.MarkE2EE(openaiproxy.E2EEValueNone, newKeylessPollProxy(routerTarget, logger))
	// Everything else under the namespace — another method, a trailing slash, a
	// sub-path — is not the poll route, and the only other handler that would take
	// it is the cleartext catch-all. A path there that could carry a key segment
	// (any "." after the prefix) is refused rather than forwarded, without echoing
	// it; the rest is ordinary passthrough, as before. The trailing slash is the
	// quiet case: the router 307s it back to the canonical path and the retry
	// succeeds, so a client would never notice the first request gave the key away.
	mux.Handle(openaiproxy.AsyncJobsPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.TrimPrefix(r.URL.Path, openaiproxy.AsyncJobsPrefix), ".") {
			openaiproxy.WriteError(w, http.StatusBadRequest, "gateway",
				"a job id carrying a key is polled with GET "+openaiproxy.AsyncJobsPrefix+"{id} only; this request is refused rather than forwarded")
			return
		}
		passthrough.ServeHTTP(w, r)
	}))
	mux.Handle("GET "+openaiproxy.AsyncJobsPrefix+"{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if openaiproxy.HasJobKey(r) {
			sealedGate.ServeHTTP(w, r)
			return
		}
		keylessPoll.ServeHTTP(w, r)
	}))
	// /healthz answers "is this process serving?" and nothing more. It is the
	// container healthcheck, and compose gates dstack-ingress's STARTUP on it
	// (depends_on: service_healthy), so widening it to cover provider reachability
	// would be actively harmful: on a boot during an upstream outage the ingress
	// would never start, leaving the CVM dark and its certificate unissued rather
	// than up and reporting honest errors.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	// /readyz answers the other question — "could this side actually serve a sealed
	// request?" — and is what the blue/green cutover probes on the standby before
	// pointing traffic at it (switch.sh gate 2). Failing here is the useful
	// direction: the deploy stops and the live side keeps serving from its warm
	// cache, which is exactly what you want when the standby cannot verify anybody
	// (chain RPC unreadable under -onchain-enforce, provider quotes unreachable,
	// router catalog down). Unauthenticated and mounted explicitly for the same two
	// reasons as /healthz: an external probe must reach it, and an unmounted path
	// would fall through to the router passthrough below and answer with the
	// ROUTER's status instead of ours.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if ready != nil {
			if err := ready(); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = fmt.Fprintf(w, "not ready: %v\n", err)
				return
			}
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	// This CVM's self-description, for a browser panel that wants to show what it is
	// connected to (issue #78). Three deliberate placements:
	//
	// OUTSIDE the credential gate — it publishes only what /evidences/ and the
	// published releases already make public, so there is nothing here to authorize
	// and a verification panel must be able to load before anyone signs in.
	//
	// OUTSIDE the in-flight cap — it is a pre-assembled constant served from memory,
	// and letting it consume a slot would price a static read against the sealed
	// inference the cap exists to protect.
	//
	// INSIDE the CORS allowlist, unlike /evidences/. The bundle answers `*` because
	// any verifier must be able to fetch it; this endpoint is a convenience for the
	// first-party panel, and the values in it are always independently obtainable
	// from the bundle, so widening the origin policy for it would buy nothing.
	if identity != nil {
		mux.Handle("GET "+identityPath, identityHandler(identity))
	}
	// The provider side of the same panel, with the same three placements and the same
	// reasoning: outside the credential gate (it publishes only what the provider's own
	// public /v1/quote already does), outside the in-flight cap (a map lookup must not
	// price against sealed inference), inside the CORS allowlist.
	//
	// It shadows /v1/providers/{address}/identity from the router catch-all below,
	// which is the intent: the answer must come from the party that did the verifying,
	// not from the router — whose account of a provider's identity is, by design, not
	// something this system trusts. The catalog itself (/v1/providers) is a less
	// specific pattern and keeps falling through to the router untouched.
	if providerIdentities != nil {
		mux.Handle("GET "+providerIdentityPath, providerIdentityHandler(providerIdentities))
	}
	// The gateway exposes no /quote route: it emits no attestation quote of its
	// own. Endpoint/code identity comes from dstack-ingress's in-CVM cert-binding
	// attestation (/evidences, which commits to app_id and so covers this image);
	// see docs/design/cloud-gateway.md §6. The gateway does SERVE that bundle when
	// -evidence-dir is set — dstack-ingress produces it, this process publishes it
	// with an origin-independent CORS header (evidenceRoute, mounted below).
	//
	// Everything else — the router's non-sealed OpenAI surface (model catalog,
	// discovery) a thin client needs — is reverse-proxied to the router as-is. The
	// sealed chat route and /healthz are more specific patterns, so Go's
	// ServeMux keeps serving them; only unmatched paths fall through here. This is a
	// cleartext passthrough — safe for metadata, never for sealed content (see
	// newRouterProxy).
	//
	// The cached wrapping is mounted HERE and nowhere else. The namespace handler
	// carries prompts, so it gets the uncached
	// `passthrough`: keeping them separate means that path's safety rests on the
	// cache not being there at all, rather than on the allowlist being right.
	mux.Handle("/", cachedPassthrough)
	// CORS wraps the whole mux, INSIDE the access log: a preflight must be answered
	// here — before the mux would hand it to the credential gate (which 401s a
	// preflight, since a browser sends no credentials on one) or to the catch-all
	// (which would let the ROUTER's allowlist decide what may reach this gateway) —
	// while still emitting the one structured line per request, preflights included.
	// StampInstance sits OUTSIDE CORS so a preflight — answered by CORS without
	// ever reaching the mux — carries the header too, and inside the access log so
	// the middleware order stays "log everything that happens below it".
	//
	// evidenceRoute sits between StampInstance and CORS: the public evidence bundle
	// answers EVERY origin (`*`), which is a different policy from the sealed API's
	// allowlist and must not be filtered through it, while still being logged and
	// still carrying the serving replica's id. See evidenceRoute.
	return openaiproxy.LogRequests(logger,
		openaiproxy.StampInstance(instanceID,
			evidenceRoute(evidenceDir,
				openaiproxy.CORS(allowedOrigins, policy.credentialsAllowed(),
					sealedNamespaceGuard(surfaces, mux)))))
}
