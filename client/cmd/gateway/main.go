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
	// The self-description endpoint (GET /v1/gateway/identity, issue #78): what this
	// CVM is, assembled server-side from its own quote and manifest so a browser
	// panel does not have to reimplement pcverify in JavaScript — which it could not
	// do anyway, since JS cannot see its own connection's peer certificate. ON by
	// default: it publishes nothing that /evidences/ and the published releases do
	// not already make public, and a panel that silently shows nothing is worse than
	// one that shows nulls. The switch is here for a deployment that wants the
	// surface gone entirely.
	//
	// It is a DESCRIPTION, not a proof — see identity.go's header before extending
	// what it reports.
	identityOn := flag.Bool("identity-endpoint", proxycli.EnvBool("ZG_GATEWAY_IDENTITY_ENDPOINT", true),
		"serve this CVM's self-description at "+identityPath+" (app_id, compose_hash, OS image, "+
			"container list, matching release). Public, unauthenticated, and NOT evidence — every "+
			"value is independently rederivable with pcverify (env ZG_GATEWAY_IDENTITY_ENDPOINT)")
	// The provider-side counterpart (GET /v1/providers/{address}/identity, issue #80):
	// what this gateway VERIFIED about a provider — the DCAP verdict on that provider's
	// quote, the on-chain signer comparison, the boot-chain verdict, its compose hash.
	// The gateway already does all of it before sealing, and again on every warmer
	// sweep (see client/route); the endpoint exists because those results used to die
	// with the verification, leaving a verification panel with nothing to show for the
	// broker hop. With -warm on it answers for the whole catalog, so the panel is not
	// blank until the user's first prompt.
	//
	// ON by default, like the self-description, and for the same reason: every value is
	// obtainable by fetching that provider's own public /v1/quote, so there is nothing
	// here to authorize. It differs in one important way — see provideridentity.go —
	// in that it DOES report verdicts, because unlike the self-description they are
	// verifications this process genuinely performed on a third party.
	//
	// The route is mounted only when there is a source that can ever answer: router
	// mode with -attest on (see proxycli.Built.ProviderIdentities). Without quote
	// verification nothing is verified, and a route that could only ever 404 is worse
	// than an absent one.
	providerIdentityOn := flag.Bool("provider-identity-endpoint", proxycli.EnvBool("ZG_GATEWAY_PROVIDER_IDENTITY_ENDPOINT", true),
		"serve what this gateway verified about each provider at "+providerIdentityPath+
			" (DCAP verdict, on-chain signer check, boot-chain verdict, compose_hash). Public and "+
			"unauthenticated; answers only for providers this gateway has verified itself — those it "+
			"has sealed to, plus every provider the -warm sweep covers — and never fetches a quote "+
			"for an address on demand; requires -attest (env ZG_GATEWAY_PROVIDER_IDENTITY_ENDPOINT)")
	// Where the endpoint's container list comes from: the manifest cmd/cvmid wrote to
	// the shared identity volume. Preferred over the platform lookup below because it
	// needs no network, no third-party host and no DNS — and, like -identity-file, it
	// keeps the gateway off the guest-agent socket. The bytes are checked against the
	// quote's compose_hash before anything is read out of them, so an absent or stale
	// file costs the container list and nothing else.
	appComposeFile := flag.String("app-compose-file", proxycli.EnvOr("ZG_GATEWAY_APP_COMPOSE_FILE", ""),
		"path to the app-compose.json written by cmd/cvmid, read for "+identityPath+"'s container "+
			"list after checking it against the quote's compose_hash; empty falls back to "+
			"-platform-base-domain (env ZG_GATEWAY_APP_COMPOSE_FILE)")
	// The fallback: the platform's per-app guest-agent host,
	// `<app_id>-8090.<base_domain>`. For a replica whose init container predates
	// -out-app-compose — the shape a rolling blue/green upgrade has — and for nothing
	// else. Empty (the default) disables it, which is right for a local run and for
	// any deployment where the file is present.
	platformBaseDomain := flag.String("platform-base-domain", proxycli.EnvOr("ZG_GATEWAY_PLATFORM_BASE_DOMAIN", ""),
		"dstack platform base domain (e.g. in1.phala.network) to fetch this app's app-compose from "+
			"when -app-compose-file is unavailable; empty disables the fallback "+
			"(env ZG_GATEWAY_PLATFORM_BASE_DOMAIN)")
	// How many published releases the deployed compose text is compared against for
	// the endpoint's matched_release. The same lookup, and the same byte-for-byte
	// comparison, that `pcverify -releases N` performs — so the release the panel
	// names and the release pcverify confirms cannot disagree. 0 disables the GitHub
	// call, which is the setting for a CVM with no egress to it.
	identityReleases := flag.Int("identity-releases", proxycli.EnvIntOr("ZG_GATEWAY_IDENTITY_RELEASES", defaultIdentityReleases),
		"how many published releases to compare the deployed compose text against for "+
			identityPath+"'s matched_release; 0 disables the GitHub lookup "+
			"(env ZG_GATEWAY_IDENTITY_RELEASES)")
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

	built := f.Build("gateway", logger, proxycli.ServesImages())

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
	var identity *identityCache
	stopIdentity := func() {}
	if *identityOn {
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
		identity, stopIdentity = startIdentity(identityConfig{
			InstanceID:     instanceID,
			AppID:          runtimeAppID,
			QuotePath:      quotePath,
			AppComposePath: *appComposeFile,
			BaseDomain:     *platformBaseDomain,
			Releases:       *identityReleases,
			OSImages:       osImages,
			Timeout:        identityLookupTimeout,
		}, logger)
	}

	// The provider-side records the endpoint above publishes. Nil — so the route stays
	// unmounted — whenever this build can never produce one: direct-broker mode (no
	// on-chain provider address to key a record by) or -attest off (nothing verified).
	var providerIdentities route.ProviderIdentitySource
	if *providerIdentityOn {
		providerIdentities = built.ProviderIdentities()
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
		Addr: *f.Listen,
		Handler: newHandler(built.Client, built.ImageClient, routerTarget, origins, instanceID, *evidenceDir, *maxInFlight,
			identity, providerIdentities, built.Readiness(), logger),
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
	// identity_endpoint is here for the same reason, and it is the more confusing of
	// the two when it is off: the endpoint answers 200 with nulls when its SOURCES
	// are missing and 404s (via the router catch-all) when the route itself is off,
	// which are very different diagnoses for the same-looking symptom.
	//
	// provider_identity_endpoint reports whether the route is MOUNTED, not merely
	// whether it was asked for: it also needs -attest (nothing to report without it),
	// and "asked for but silently absent" is precisely the diagnosis an operator would
	// otherwise have to reconstruct from two other flags.
	logger.Info("gateway listening", "listen", *f.Listen, "router_url", *f.RouterURL,
		"cors_allowed_origins", origins, "max_inflight", *maxInFlight,
		"evidence_dir", *evidenceDir, "identity_endpoint", *identityOn,
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
// an unset evidenceDir — which is what -identity-endpoint=false and every test
// that is not about the route get.
//
// providerIdentities, when non-nil, mounts the provider-side counterpart at
// /v1/providers/{address}/identity: what this gateway verified about the providers
// it sealed to. Nil leaves it unmounted, which is what a build that verifies no
// quotes gets — see main's wiring and proxycli.Built.ProviderIdentities.
//
// ready backs GET /readyz: nil means there is nothing to assert (no warmer
// configured) and the route always answers ready. See proxycli.Built.Readiness and
// the /healthz vs /readyz split at the routes below.
func newHandler(c *core.Client, imageClient *core.Client, routerTarget *url.URL, allowedOrigins []string, instanceID, evidenceDir string,
	maxInFlight int, identity *identityCache, providerIdentities route.ProviderIdentitySource,
	ready func() error, logger *slog.Logger) http.Handler {
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
	sealed := http.NewServeMux()
	openaiproxy.Register(sealed, endpoint.Chat, c)
	if imageClient != nil {
		openaiproxy.Register(sealed, endpoint.Image, imageClient)
	}
	sealedGate := openaiproxy.RequireInferenceCredential(
		openaiproxy.LimitInFlight(maxInFlight, sealed))
	mux.Handle("POST "+endpoint.Chat.Path, sealedGate)
	// The sealed image endpoint shares that gate — it does the same expensive work
	// and must not have its own separate budget.
	//
	// When there is no image client (direct-broker mode, whose single configured
	// broker URL is chat-shaped), the route is mounted as an explicit refusal
	// rather than left unmounted. Leaving it off is NOT inert: the catch-all is a
	// reverse proxy to the router, and routerTarget is parsed in every mode, so an
	// unmounted sealed endpoint forwards the caller's PROMPT to the router in
	// cleartext — the one thing this gateway exists to prevent. Fail closed.
	//
	// Both mounts name endpoint.*.Path rather than repeating the literal the inner
	// mux already uses. A divergence between the two is not a 404: the outer mux is
	// what stands between a path and the cleartext catch-all below, so a route the
	// inner mux serves and the outer one does not is exactly the leak this comment
	// describes. Enumerating endpoint.All here is the next step; naming the rows is
	// what keeps the two ends together until then.
	if imageClient != nil {
		mux.Handle("POST "+endpoint.Image.Path, sealedGate)
	} else {
		mux.Handle("POST "+endpoint.Image.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte(`{"error":{"message":"sealed image generation is not available in direct-broker mode","type":"invalid_request_error"}}` + "\n"))
		}))
	}
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
	mux.Handle("/", newRouterProxy(routerTarget, logger))
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
			evidenceRoute(evidenceDir, openaiproxy.CORS(allowedOrigins, mux))))
}
