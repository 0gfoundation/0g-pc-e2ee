// Package proxycli holds the startup wiring shared by the two client-core
// binaries — the local sidecar (cmd/sidecar) and the cloud-TEE gateway
// (cmd/gateway). Both are the SAME client core wrapped as an OpenAI-compatible
// proxy; they differ only in how they listen (local vs enclave), whether they
// surface upstream error detail, and which operational routes they mount. The
// route-and-seal plumbing between those differences is identical, so it lives
// here once instead of being copied into each main.
//
// Each binary registers the shared flags with its own env prefix and default
// listen address, parses, then calls Build to get a wired *core.Client. Every
// parameter can be set two ways: an explicit command-line flag or a
// <PREFIX>_* environment variable used only as the flag's default, so
// precedence is: explicit flag > environment variable > built-in default. Env
// config is the primary path for the TEE/dstack deployment, where the compose
// file's `environment:` block is measured into the CVM attestation; flags stay
// convenient for local runs and one-off overrides.
package proxycli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/dcap"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/client/sig"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// ShutdownTimeout bounds how long Serve waits for in-flight requests to drain
// after a shutdown signal before it forces the listener closed. It is sized to a
// typical orchestrator stop grace (Docker defaults to 10s, Kubernetes to 30s; the
// dstack/Phala deployment sends SIGTERM on stop), so ordinary buffered
// completions finish cleanly while a long-lived SSE stream — which can otherwise
// run up to the core's providerTimeout (~10m) — is cut rather than stalling the
// redeploy. A cut stream is unavoidable on any bounded-grace shutdown; the
// alternative (waiting out the stream) would make every deploy hang for minutes.
const ShutdownTimeout = 30 * time.Second

// Serve runs srv until an interrupt or termination signal (SIGINT / SIGTERM)
// arrives, then shuts it down gracefully: it stops accepting new connections and
// waits up to ShutdownTimeout for in-flight requests to finish before forcing the
// listener closed. Both proxy binaries call it so their lifecycle — signal
// handling, drain window, and the ErrServerClosed vs real-error distinction —
// stays identical instead of being re-implemented in each main.
//
// It returns nil once a signal-triggered shutdown completes (whether the drain
// finished or timed out and was forced), and a non-nil error only when
// ListenAndServe fails for a reason other than the expected http.ErrServerClosed
// (e.g. the listen address is already bound). The caller logs it and sets the
// process exit code.
func Serve(srv *http.Server, logger *slog.Logger) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	return serve(srv, logger, sigCh)
}

// serve is the signal-source-independent core of Serve. It takes the trigger
// channel as a parameter so a test can drive the drain path deterministically
// without sending a real process signal (which would race every other test in
// the binary). Production always feeds it an os/signal-backed channel via Serve.
func serve(srv *http.Server, logger *slog.Logger, sigCh <-chan os.Signal) error {
	// ListenAndServe blocks until Shutdown/Close, so run it in a goroutine and
	// report its outcome here. A clean shutdown surfaces as ErrServerClosed, which
	// is normal (not an error); anything else is a genuine listen/serve failure
	// that the select below returns to the caller synchronously.
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		// The server exited before any signal — a bind/listen failure. Return it;
		// there is nothing to drain.
		return err
	case sig := <-sigCh:
		logger.Info("shutdown signal received, draining in-flight requests",
			"signal", sig.String(), "grace", ShutdownTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		// The grace window elapsed with requests still in flight (typically a
		// long-lived SSE stream). Force the listener and idle connections closed so
		// the process can exit promptly; the stream is cut, which is inherent to a
		// bounded-grace shutdown.
		logger.Warn("graceful shutdown timed out, forcing close", "err", err)
		_ = srv.Close()
	} else {
		logger.Info("graceful shutdown complete")
	}
	// Wait for ListenAndServe to return (it now yields ErrServerClosed → nil) so we
	// don't race the goroutine as the process exits.
	return <-errCh
}

// onchainCacheTTL bounds how long an on-chain teeSignerAddress lookup is reused.
// A provider's acknowledged signer changes only on re-registration, so a few
// minutes trades a stale-signer window for far fewer chain RPCs per request.
const onchainCacheTTL = 5 * time.Minute

// NewLogger builds the process logger both proxy binaries share: human-readable
// text records to stdout, at Info and above. Centralizing it here keeps the
// sidecar and gateway on one format, level, and sink so their logs don't drift.
// It is handed to Build (so the core's redaction-safe open-failure diagnostics
// use it too) and to each binary's access-log middleware, so every line a proxy
// emits — startup, per-request, and AEAD-failure — shares the same shape.
func NewLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// Flags holds the startup parameters common to both proxy binaries, populated
// by flag.Parse after RegisterFlags. Callers read Listen to bind their server
// and pass the rest to Build.
type Flags struct {
	Listen           *string
	RouterURL        *string
	providerURL      *string
	sealFieldsCSV    *string
	unboundFieldsCSV *string
	attestOn         *bool
	attestEnforce    *bool
	onchainOn        *bool
	onchainEnforce   *bool
	verifyResponses  *bool
	chainRPCURL      *string
	servingContract  *string
	warmOn           *bool
	warmInterval     *time.Duration
	pccsURL          *string
	collateralTTL    *time.Duration
}

// defaultWarmInterval is the refresh-ahead period the background quote-cache
// warmer uses when -warm is set without an explicit -warm-interval. It sits
// under the route package's quote-cache TTL (5m) so a cached entry is
// re-verified before it expires and requests keep hitting a warm cache (see
// route.RunWarmer).
const defaultWarmInterval = 4 * time.Minute

// defaultCollateralTTL is how long DCAP collateral (TCB Info / QE Identity /
// CRLs) is memoized by URL when -attest is on, so the verify path does not
// re-fetch the same collateral for every provider and every warmer sweep. It is
// deliberately bounded: a cached CRL delays observing a fresh revocation until it
// expires, so this is the accepted revocation-lag window — long enough to dedup
// across a warmer cycle and the ~dozens of providers, far under collateral's
// nextUpdate. Tunable via -collateral-ttl (0 disables the cache).
const defaultCollateralTTL = time.Hour

// RegisterFlags declares the shared startup flags on fs and returns a Flags
// whose pointers are filled by fs.Parse. envPrefix (e.g. "ZG_GATEWAY",
// "ZG_SIDECAR") selects the environment variables consulted for each flag's
// default: <envPrefix>_LISTEN, _ROUTER_URL, _PROVIDER_URL, _SEAL_FIELDS,
// _UNBOUND_FIELDS, _ATTEST, _ATTEST_ENFORCE, _ONCHAIN, _ONCHAIN_ENFORCE,
// _CHAIN_RPC_URL, _SERVING_CONTRACT, _WARM, _WARM_INTERVAL, _PCCS_URL,
// _COLLATERAL_TTL.
// defaultListen is the built-in listen address used when neither the flag nor
// <envPrefix>_LISTEN is set.
func RegisterFlags(fs *flag.FlagSet, envPrefix, defaultListen string) *Flags {
	env := func(name string) string { return envPrefix + "_" + name }
	return &Flags{
		Listen:    fs.String("listen", envOr(env("LISTEN"), defaultListen), fmt.Sprintf("address to listen on (env %s)", env("LISTEN"))),
		RouterURL: fs.String("router-url", envOr(env("ROUTER_URL"), route.DefaultRouterURL), fmt.Sprintf("0G router base URL/domain (the route-preview path is appended) (env %s)", env("ROUTER_URL"))),
		providerURL: fs.String("provider-url", envOr(env("PROVIDER_URL"), ""),
			fmt.Sprintf("direct-broker mode: seal each request straight to this provider endpoint, skipping the router's route-preview (for an environment with a broker but no centralized router, e.g. dev); the provider's enc key + signer are fetched from its broker's /v1/e2ee/pubkey. Empty keeps the default router mode (env %s)", env("PROVIDER_URL"))),
		sealFieldsCSV: fs.String("seal-fields", envOr(env("SEAL_FIELDS"), strings.Join(wire.DefaultSealedFields(), ",")),
			fmt.Sprintf("comma-separated request fields to seal (must include \"messages\") (env %s)", env("SEAL_FIELDS"))),
		unboundFieldsCSV: fs.String("unbound-fields", envOr(env("UNBOUND_FIELDS"), strings.Join(wire.DefaultUnboundFields(), ",")),
			fmt.Sprintf("comma-separated cleartext fields excluded from the AAD (intermediary-mutable, untrusted); empty binds everything (env %s)", env("UNBOUND_FIELDS"))),
		attestOn: fs.Bool("attest", envBool(env("ATTEST"), false),
			fmt.Sprintf("DCAP-verify each provider's TDX quote and seal only to the verified enc key (instead of trusting the router-supplied pubkey endpoint) (env %s)", env("ATTEST"))),
		attestEnforce: fs.Bool("attest-enforce", envBool(env("ATTEST_ENFORCE"), false),
			fmt.Sprintf("with -attest, reject a provider whose measurement is not in the allowlist instead of only warning; the audited-image allowlist is not wired yet (empty), so enforce currently rejects all providers (env %s)", env("ATTEST_ENFORCE"))),
		onchainOn: fs.Bool("onchain", envBool(env("ONCHAIN"), false),
			fmt.Sprintf("cross-check each provider's quote-bound TEE signer against its acknowledged on-chain teeSignerAddress in the InferenceServing registry (SPEC §4.4 step 3); requires -attest (env %s)", env("ONCHAIN"))),
		onchainEnforce: fs.Bool("onchain-enforce", envBool(env("ONCHAIN_ENFORCE"), false),
			fmt.Sprintf("with -onchain, skip a provider whose on-chain signer is missing/unacknowledged/mismatched instead of only warning (env %s)", env("ONCHAIN_ENFORCE"))),
		verifyResponses: fs.Bool("verify-responses", envBool(env("VERIFY_RESPONSES"), false),
			fmt.Sprintf("verify each response's §8 TEE signature (trust-chain hop 11), fetched directly from the provider's broker endpoint, fail-closed against the quote-bound signer; requires -attest, and -onchain additionally grounds that signer on-chain (env %s)", env("VERIFY_RESPONSES"))),
		chainRPCURL: fs.String("chain-rpc-url", envOr(env("CHAIN_RPC_URL"), chain.DefaultChainRPCURL),
			fmt.Sprintf("0G chain JSON-RPC endpoint for on-chain signer lookups; must be a source trusted independently of the router (defaults to 0G mainnet) (env %s)", env("CHAIN_RPC_URL"))),
		servingContract: fs.String("serving-contract", envOr(env("SERVING_CONTRACT"), chain.DefaultInferenceServingAddress),
			fmt.Sprintf("InferenceServing contract address for on-chain signer lookups (env %s)", env("SERVING_CONTRACT"))),
		warmOn: fs.Bool("warm", envBool(env("WARM"), false),
			fmt.Sprintf("run a background warmer that pre-verifies every provider's quote and refreshes it ahead of expiry, so requests hit a warm cache instead of paying the DCAP verify inline; requires -attest and -onchain (env %s)", env("WARM"))),
		warmInterval: fs.Duration("warm-interval", envDuration(env("WARM_INTERVAL"), defaultWarmInterval),
			fmt.Sprintf("with -warm, how often to re-verify each provider (should be under the ~5m quote-cache TTL for refresh-ahead) (env %s)", env("WARM_INTERVAL"))),
		pccsURL: fs.String("pccs-url", envOr(env("PCCS_URL"), ""),
			fmt.Sprintf("with -attest, fetch Intel PCS collateral (TCB Info, QE Identity, PCK CRL) from this PCCS base (e.g. https://pccs.phala.network) instead of api.trustedservices.intel.com; the root-CA CRL still comes from Intel (env %s)", env("PCCS_URL"))),
		collateralTTL: fs.Duration("collateral-ttl", envDuration(env("COLLATERAL_TTL"), defaultCollateralTTL),
			fmt.Sprintf("with -attest, how long to memoize DCAP collateral by URL so it is not re-fetched per provider/sweep; bounds revocation lag, 0 disables (env %s)", env("COLLATERAL_TTL"))),
	}
}

// Built is the wired client core plus the handles a caller needs to run the
// background quote-cache warmer. Client is the OpenAI-proxy core both binaries
// serve. The remaining fields are warmer wiring, populated only when -warm is
// set (nil/zero otherwise): router is the resolver whose cache is warmed, and
// resolver is the CONCRETE on-chain registry (not the caching SignerRegistry
// wrapper), because the warmer needs its ServiceInfo method to resolve each
// provider's endpoint from chain. Callers pass the whole struct to StartWarmer;
// only Client is needed to serve requests.
type Built struct {
	Client       *core.Client
	router       *route.Router
	resolver     route.EndpointResolver
	warmInterval time.Duration
}

// Build validates the parsed flags and constructs the wired client core: a
// per-request route resolver (optionally DCAP-verifying each provider's TDX
// quote) feeding a core.Client that seals the configured fields. label is used
// only for the verifier's log line ("<label>: TDX quote verification ...") so
// the two binaries identify themselves. A redaction-safe debug logger is always
// attached (field names and byte lengths only, never plaintext or key
// material); it writes to the process log and never reaches the end user.
//
// It returns a *Built: the client core to serve, plus (when -warm is set) the
// router and concrete on-chain resolver StartWarmer needs to run the background
// quote-cache warmer.
//
// It exits the process via os.Exit(1) (after logging through logger) on an
// invalid flag combination — the same fail-loud behavior both mains had inline —
// so a misconfigured proxy never starts with, say, an unsealed "messages" field
// or attestation silently off. logger is also attached as the core's debug
// logger, so open-failure diagnostics share the binary's format and sink.
func (f *Flags) Build(label string, logger *slog.Logger) *Built {
	sealFields := parseCSV(*f.sealFieldsCSV)
	if err := wire.ValidateSealedFields(sealFields); err != nil {
		logger.Error("invalid -seal-fields", "err", err)
		os.Exit(1)
	}
	unboundFields := parseCSV(*f.unboundFieldsCSV)
	if err := wire.ValidateUnboundFields(unboundFields, sealFields); err != nil {
		logger.Error("invalid -unbound-fields", "err", err)
		os.Exit(1)
	}
	// Direct-broker mode (-provider-url set) skips the router and seals straight to
	// one fixed provider — for an environment with a broker but no centralized
	// router (dev). It reuses the pubkey/quote fetch but not the router-only steps:
	// on-chain grounding needs the provider's on-chain address the router preview
	// would supply, and the warmer enumerates providers via the router — so both are
	// rejected. These checks come before the router-mode interdependency checks
	// below so a direct-mode operator gets the direct-mode message (not, say,
	// "-onchain requires -attest") for the same flag combination.
	directMode := strings.TrimSpace(*f.providerURL) != ""
	if directMode && *f.onchainOn {
		logger.Error("-onchain is not supported in direct-broker mode (-provider-url); run without -provider-url to route through the router")
		os.Exit(1)
	}
	if directMode && *f.warmOn {
		logger.Error("-warm is not supported in direct-broker mode (-provider-url); the warmer enumerates providers via the router")
		os.Exit(1)
	}
	// Fail loudly rather than silently give NO attestation when the operator asked
	// for the strictest mode: -attest-enforce is meaningless without -attest.
	if *f.attestEnforce && !*f.attestOn {
		logger.Error("-attest-enforce requires -attest")
		os.Exit(1)
	}
	// On-chain grounding needs a quote-bound signer to check (so -attest), a
	// stricter mode needs the check on (so -onchain), and the check needs an RPC.
	if *f.onchainEnforce && !*f.onchainOn {
		logger.Error("-onchain-enforce requires -onchain")
		os.Exit(1)
	}
	if *f.onchainOn && !*f.attestOn {
		logger.Error("-onchain requires -attest (the signer must come from a verified quote)")
		os.Exit(1)
	}
	if *f.onchainOn && strings.TrimSpace(*f.chainRPCURL) == "" {
		logger.Error("-onchain requires -chain-rpc-url")
		os.Exit(1)
	}
	// Response verification anchors on the provider's signer. In router mode that
	// signer is only trustworthy when it came from a verified quote (the router is
	// untrusted), so -verify-responses requires -attest. In direct-broker mode there
	// is no router in the path: the signer comes from the broker the operator pointed
	// at directly (-provider-url), so verifying responses against it is meaningful
	// without -attest.
	if *f.verifyResponses && !*f.attestOn && !directMode {
		logger.Error("-verify-responses requires -attest (the signer must come from a verified quote)")
		os.Exit(1)
	}
	// The warmer pre-verifies quotes (needs -attest) and resolves each provider's
	// endpoint from the on-chain registry (needs -onchain, which builds it). Fail
	// loud rather than start a warmer that would silently no-op.
	if *f.warmOn && (!*f.attestOn || !*f.onchainOn) {
		logger.Error("-warm requires -attest and -onchain")
		os.Exit(1)
	}
	if *f.warmOn && *f.warmInterval <= 0 {
		logger.Error("-warm requires a positive -warm-interval")
		os.Exit(1)
	}

	// Route per request: pick the provider via the router and derive its enc key +
	// signer from the broker, so no provider key is pinned up front. The router is
	// told to withhold exactly the sealed fields, so the prompt never reaches it in
	// cleartext even on the control-plane preview call. The service type is fixed
	// (route.New defaults to "chatbot"); it is not a startup choice.
	routeOpts := []route.Option{route.WithSensitiveFields(sealFields)}
	if *f.attestOn {
		routeOpts = append(routeOpts, route.WithQuoteVerification(
			newVerifier(label, *f.attestEnforce, *f.pccsURL, *f.collateralTTL, logger), logger))
	}
	// resolver is the CONCRETE on-chain registry the warmer uses to resolve each
	// provider's endpoint via ServiceInfo. The route's grounding uses the caching
	// wrapper (chain.Cached) instead — it only needs AcknowledgedSigner — so the
	// two are deliberately different values off the same underlying registry.
	var resolver route.EndpointResolver
	if *f.onchainOn {
		reg, err := chain.NewOnChainRegistry(chain.Config{RPCURL: *f.chainRPCURL, ContractAddress: *f.servingContract})
		if err != nil {
			logger.Error("on-chain registry", "err", err)
			os.Exit(1)
		}
		resolver = reg
		routeOpts = append(routeOpts, route.WithOnChainVerification(chain.Cached(reg, onchainCacheTTL), *f.onchainEnforce, logger))
		logger.Info("on-chain signer grounding enabled", "label", label, "enforce", *f.onchainEnforce, "contract", *f.servingContract)
	}
	coreOpts := []core.Option{
		core.WithSealFields(sealFields),
		core.WithUnboundFields(unboundFields),
		core.WithDebugLogger(logger),
	}
	if *f.verifyResponses {
		// Fetch the signature straight from the provider's broker endpoint (the
		// router does not proxy /v1/proxy/signature); verify fail-closed against the
		// resolver-grounded signer via the shared proof contract. The same fetcher
		// works in direct-broker mode — it already talks to Provider.Endpoint, which
		// the direct resolver sets to the provider URL.
		coreOpts = append(coreOpts, core.WithResponseVerification(route.NewSignatureFetcher(nil), sig.Recover))
		logger.Info("response signature verification enabled", "label", label, "direct", directMode, "onchain_grounded", *f.onchainOn)
	}

	// Direct-broker mode: seal straight to the one configured provider, no router
	// preview. The warmer stays off (no provider list to enumerate), so Built holds
	// only the client.
	if directMode {
		directRes, err := route.NewDirect(*f.providerURL, routeOpts...)
		if err != nil {
			logger.Error("invalid -provider-url", "url", *f.providerURL, "err", err)
			os.Exit(1)
		}
		logger.Info("direct-broker mode enabled (no router)", "label", label, "provider_url", *f.providerURL, "attest", *f.attestOn)
		return &Built{Client: core.NewWithResolver(directRes, coreOpts...)}
	}

	router := route.New(*f.RouterURL, routeOpts...)
	client := core.NewWithResolver(router, coreOpts...)
	b := &Built{Client: client, router: router}
	if *f.warmOn {
		b.resolver = resolver
		b.warmInterval = *f.warmInterval
	}
	return b
}

// StartWarmer launches the background quote-cache warmer in a goroutine and
// returns a stop function the caller defers (or calls before exit) to halt the
// loop and wait for it to drain on shutdown. When -warm was not configured it
// is a no-op that returns a no-op stop, so callers can wire it unconditionally.
// The warmer re-verifies every provider's quote on a refresh-ahead interval so
// requests hit a warm cache; a per-provider failure is logged and skipped, and
// shutdown (stop) cancels the loop without evicting still-good entries.
func (b *Built) StartWarmer(logger *slog.Logger) (stop func()) {
	if b.warmInterval <= 0 || b.resolver == nil || b.router == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.router.RunWarmer(ctx, b.warmInterval, b.resolver)
	}()
	logger.Info("quote-cache warmer started", "interval", b.warmInterval)
	return func() {
		cancel()
		// Wait for the loop to unwind, but only briefly: an in-flight refresh runs
		// on a detached context (route.quoteVerifyTimeout, ~60s) that cancel() does
		// not abort, and holding up process exit that long would blow the shutdown
		// grace. Its cache write is harmless — the process is exiting — so cap the
		// wait and let the goroutine finish on its own if it is mid-verify.
		select {
		case <-done:
		case <-time.After(warmerStopGrace):
			logger.Warn("quote-cache warmer still draining at shutdown; exiting anyway")
		}
	}
}

// warmerStopGrace bounds how long StartWarmer's stop waits for the warmer loop
// to unwind at shutdown before letting the process exit regardless. Kept small
// so a warmer mid-verify (on its own detached, ~60s-bounded context) never
// stretches shutdown past the orchestrator's stop grace.
const warmerStopGrace = 2 * time.Second

// newVerifier builds the per-request TDX quote verifier. Quote authenticity
// (genuine TDX + TCB UpToDate + report_data binding) is always enforced; only
// the measurement-allowlist decision is governed by enforce vs warn. The audited
// broker-image allowlist is not wired yet (empty), so warn is the usable interim
// (log an out-of-allowlist measurement but proceed) and enforce rejects all.
//
// pccsURL (when non-empty) points DCAP collateral fetches at a PCCS mirror
// instead of Intel PCS, and collateralTTL (when positive) memoizes that
// collateral by URL so it is not re-fetched for every provider and warmer sweep.
// Both are shared once across all verifications (the caching getter's memo lives
// for the process lifetime), so they dedup across the whole provider fleet.
func newVerifier(label string, enforce bool, pccsURL string, collateralTTL time.Duration, logger *slog.Logger) *attest.Verifier {
	mode := attest.ModeWarn
	if enforce {
		mode = attest.ModeEnforce
	}
	logger.Info("TDX quote verification enabled", "label", label, "enforce", enforce, "allowlist", "empty",
		"collateral_source", collateralSource(pccsURL), "collateral_ttl", collateralTTL)
	return attest.New(
		attest.Policy{}, // TODO: load the audited broker-image measurement allowlist
		attest.WithQuoteParser(dcap.NewQuoteParser(dcap.Config{
			PCCSBaseURL:   pccsURL,
			CollateralTTL: collateralTTL,
		})),
		attest.WithMeasurementMode(mode),
	)
}

// collateralSource names where DCAP collateral is fetched from, for the startup
// log line: the configured PCCS mirror, or Intel PCS when none is set.
func collateralSource(pccsURL string) string {
	if strings.TrimSpace(pccsURL) != "" {
		return pccsURL
	}
	return "intel-pcs"
}

// envOr returns the value of environment variable key, or def if it is unset.
// An explicitly-set-but-empty variable (e.g. ZG_GATEWAY_UNBOUND_FIELDS=) is
// honored as empty, which for CSV fields is a meaningful value (bind everything),
// so we branch on presence via LookupEnv rather than treating "" as unset.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// envBool parses a boolean environment variable (accepting the same forms as
// the -flag=bool syntax: 1/t/T/TRUE/true, 0/f/F/FALSE/false, etc.). An unset
// variable falls back to def; a set-but-unparseable value is fatal rather than
// silently defaulting, so a typo like ZG_GATEWAY_ATTEST=yes cannot quietly leave
// attestation off.
func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Fatalf("invalid %s=%q: must be a boolean (true/false)", key, v)
	}
	return b
}

// envDuration parses a duration environment variable (Go duration syntax, e.g.
// "4m", "90s"). An unset variable falls back to def; a set-but-unparseable value
// is fatal rather than silently defaulting, so a typo like ZG_GATEWAY_WARM_INTERVAL=4
// (missing unit) cannot quietly change the refresh cadence.
func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid %s=%q: must be a Go duration (e.g. 4m, 90s)", key, v)
	}
	return d
}

// parseCSV splits a comma-separated flag value into trimmed, non-empty parts.
func parseCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
