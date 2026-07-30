// Command gateway is the cloud-TEE gateway form: the SAME client core wrapped
// as a server, but SERVER-RUN and 0G-operated — it runs inside an attested CVM
// and adds one attested trust party. It serves no-install / browser / thin
// clients that cannot run a sidecar: TLS terminates inside the enclave (dstack
// ZT-HTTPS), the gateway seals each request to the routed provider and opens the
// sealed response, and plaintext streams back over that same TLS. See
// docs/design/cloud-gateway.md for the trust model.
//
// The gateway always routes: per request it asks the 0G router which provider to
// use (POST /v1/routing/preview), fetches that provider's enc key and signer
// address from the broker (GET /v1/e2ee/pubkey), then seals to it — so no
// provider key or signer is configured up front (design §12 open question 3;
// see client/route). A caller that wants a specific provider pins it with the
// X-0G-Provider-Address routing header, which the gateway forwards to the router
// so preview returns that provider.
//
// Attestation (the /quote body and per-response signature; issue #19, on
// protocol/attest / issue #7) and multi-tenant concerns (auth, billing, rate
// limiting; issue #20) are later steps; /quote is a stub until then. Trusting
// the router's returned endpoint (vs resolving it on chain) is tracked in
// issue #18.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/dcap"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// onchainCacheTTL bounds how long an on-chain teeSignerAddress lookup is reused.
// A provider's acknowledged signer changes only on re-registration, so a few
// minutes trades a stale-signer window for far fewer chain RPCs per request.
const onchainCacheTTL = 5 * time.Minute

// Every startup parameter can be set two ways: an explicit command-line flag or
// a ZG_GATEWAY_* environment variable. The env value is used only as the flag's
// default, so precedence is: explicit flag > environment variable > built-in
// default. Env config is the primary path for the TEE/dstack deployment, where
// the compose file's `environment:` block is measured into the CVM attestation
// (see deploy/phala/docker-compose.yml), while flags stay convenient for local
// runs and one-off overrides.
func main() {
	listen := flag.String("listen", envOr("ZG_GATEWAY_LISTEN", ":8443"), "address to listen on (env ZG_GATEWAY_LISTEN)")
	routerURL := flag.String("router-url", envOr("ZG_GATEWAY_ROUTER_URL", route.DefaultRouterURL), "0G router base URL/domain (the route-preview path is appended) (env ZG_GATEWAY_ROUTER_URL)")
	sealFieldsCSV := flag.String("seal-fields", envOr("ZG_GATEWAY_SEAL_FIELDS", strings.Join(wire.DefaultSealedFields(), ",")), "comma-separated request fields to seal (must include \"messages\") (env ZG_GATEWAY_SEAL_FIELDS)")
	unboundFieldsCSV := flag.String("unbound-fields", envOr("ZG_GATEWAY_UNBOUND_FIELDS", strings.Join(wire.DefaultUnboundFields(), ",")), "comma-separated cleartext fields excluded from the AAD (intermediary-mutable, untrusted); empty binds everything (env ZG_GATEWAY_UNBOUND_FIELDS)")
	attestOn := flag.Bool("attest", envBool("ZG_GATEWAY_ATTEST", false), "DCAP-verify each provider's TDX quote and seal only to the verified enc key (instead of trusting the router-supplied pubkey endpoint) (env ZG_GATEWAY_ATTEST)")
	attestEnforce := flag.Bool("attest-enforce", envBool("ZG_GATEWAY_ATTEST_ENFORCE", false), "with -attest, reject a provider whose measurement is not in the allowlist instead of only warning; the audited-image allowlist is not wired yet (empty), so enforce currently rejects all providers (env ZG_GATEWAY_ATTEST_ENFORCE)")
	onchainOn := flag.Bool("onchain", envBool("ZG_GATEWAY_ONCHAIN", false), "cross-check each provider's quote-bound TEE signer against its acknowledged on-chain teeSignerAddress in the InferenceServing registry (SPEC §4.4 step 3); requires -attest (env ZG_GATEWAY_ONCHAIN)")
	onchainEnforce := flag.Bool("onchain-enforce", envBool("ZG_GATEWAY_ONCHAIN_ENFORCE", false), "with -onchain, skip a provider whose on-chain signer is missing/unacknowledged/mismatched instead of only warning (env ZG_GATEWAY_ONCHAIN_ENFORCE)")
	chainRPCURL := flag.String("chain-rpc-url", envOr("ZG_GATEWAY_CHAIN_RPC_URL", ""), "0G chain JSON-RPC endpoint for on-chain signer lookups; must be a source trusted independently of the router (required with -onchain) (env ZG_GATEWAY_CHAIN_RPC_URL)")
	servingContract := flag.String("serving-contract", envOr("ZG_GATEWAY_SERVING_CONTRACT", chain.DefaultInferenceServingAddress), "InferenceServing contract address for on-chain signer lookups (env ZG_GATEWAY_SERVING_CONTRACT)")
	flag.Parse()

	sealFields := parseCSV(*sealFieldsCSV)
	if err := wire.ValidateSealedFields(sealFields); err != nil {
		log.Fatalf("invalid -seal-fields: %v", err)
	}
	unboundFields := parseCSV(*unboundFieldsCSV)
	if err := wire.ValidateUnboundFields(unboundFields, sealFields); err != nil {
		log.Fatalf("invalid -unbound-fields: %v", err)
	}
	// Fail loudly rather than silently give NO attestation when the operator asked
	// for the strictest mode: -attest-enforce is meaningless without -attest.
	if *attestEnforce && !*attestOn {
		log.Fatalf("-attest-enforce requires -attest")
	}
	// On-chain grounding needs a quote-bound signer to check (so -attest), a
	// stricter mode needs the check on (so -onchain), and the check needs an RPC.
	if *onchainEnforce && !*onchainOn {
		log.Fatalf("-onchain-enforce requires -onchain")
	}
	if *onchainOn && !*attestOn {
		log.Fatalf("-onchain requires -attest (the signer must come from a verified quote)")
	}
	if *onchainOn && strings.TrimSpace(*chainRPCURL) == "" {
		log.Fatalf("-onchain requires -chain-rpc-url")
	}

	// The gateway holds no pinned provider: it routes per request and derives the
	// provider's enc key + signer from the broker. The router is told to withhold
	// exactly the sealed fields, so the prompt never reaches it in cleartext even
	// on the control-plane preview call.
	// The gateway serves only chat completions, so the route service type is fixed
	// (route.New defaults to "chatbot"); it is not a startup choice.
	routeOpts := []route.Option{route.WithSensitiveFields(sealFields)}
	if *attestOn {
		routeOpts = append(routeOpts, route.WithQuoteVerification(newVerifier(*attestEnforce), nil))
	}
	if *onchainOn {
		reg, err := chain.NewOnChainRegistry(chain.Config{RPCURL: *chainRPCURL, ContractAddress: *servingContract})
		if err != nil {
			log.Fatalf("on-chain registry: %v", err)
		}
		routeOpts = append(routeOpts, route.WithOnChainVerification(chain.Cached(reg, onchainCacheTTL), *onchainEnforce, nil))
		log.Printf("gateway: on-chain signer grounding enabled (enforce=%v, contract=%s)", *onchainEnforce, *servingContract)
	}
	router := route.New(*routerURL, routeOpts...)
	// Log a redaction-safe summary of any response open (AEAD) failure to the
	// enclave's process log. This is operator-only diagnostics (field names and
	// byte lengths, no plaintext or key material; see core.WithDebugLogger) and is
	// distinct from the client-facing upstream-error detail the gateway still
	// withholds — it never echoes anything to the end user.
	client := core.NewWithResolver(router,
		core.WithSealFields(sealFields),
		core.WithUnboundFields(unboundFields),
		core.WithDebugLogger(log.Default()),
	)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(client),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
	}
	// TLS is terminated by the dstack ZT-HTTPS front end inside the enclave, so
	// the gateway itself serves plaintext HTTP on the socket dstack forwards to;
	// the enclave boundary, not this listener, is the TLS edge.
	log.Printf("gateway listening on %s -> route via %s", *listen, *routerURL)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// newVerifier builds the per-request TDX quote verifier. Quote authenticity
// (genuine TDX + TCB UpToDate + report_data binding) is always enforced; only
// the measurement-allowlist decision is governed by enforce vs warn. The audited
// broker-image allowlist is not wired yet (empty), so warn is the usable interim
// (log an out-of-allowlist measurement but proceed) and enforce rejects all.
func newVerifier(enforce bool) *attest.Verifier {
	mode := attest.ModeWarn
	if enforce {
		mode = attest.ModeEnforce
	}
	log.Printf("gateway: TDX quote verification enabled (measurement enforce=%v, allowlist empty)", enforce)
	return attest.New(
		attest.Policy{}, // TODO: load the audited broker-image measurement allowlist
		attest.WithQuoteParser(dcap.NewQuoteParser(dcap.Config{})),
		attest.WithMeasurementMode(mode),
	)
}

// newHandler mounts the shared OpenAI proxy plus the gateway-only operational
// routes (health, attestation quote). It is split out from main so tests can
// drive it with httptest.
func newHandler(c *core.Client) http.Handler {
	mux := http.NewServeMux()
	openaiproxy.Register(mux, c)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	// /quote will expose the enclave's attestation quote (with the TLS cert key
	// bound into report_data) once the gateway attestation work lands (issue #19,
	// on protocol/attest / issue #7); until then it advertises the endpoint but is
	// Not Implemented, so a validator gets a clear signal rather than a 404.
	mux.HandleFunc("GET /quote", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "attestation quote not yet implemented", http.StatusNotImplemented)
	})
	return mux
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
