// Command sidecar is the local sidecar form: the client core wrapped as a
// localhost OpenAI-compatible proxy. Run it and point any OpenAI SDK at it via
// base_url; it routes each request through the 0G router, seals the sensitive
// request fields to the chosen provider, and opens the sealed response, so your
// app keeps talking plain OpenAI.
//
// Like the gateway, the sidecar is route-oriented: per request it asks the
// router which provider to use (POST /v1/routing/preview) and fetches that
// provider's enc key + signer from the broker (GET /v1/e2ee/pubkey), so no
// provider key is configured up front. Unlike the gateway it runs on the user's
// own machine (no new trust party) and surfaces upstream error detail for local
// debugging.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/dcap"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func main() {
	listen := flag.String("listen", "localhost:8787", "address to listen on")
	routerURL := flag.String("router-url", route.DefaultRouterURL, "0G router base URL/domain (the route-preview path is appended)")
	sealFieldsCSV := flag.String("seal-fields", strings.Join(wire.DefaultSealedFields(), ","), "comma-separated request fields to seal (must include \"messages\")")
	unboundFieldsCSV := flag.String("unbound-fields", strings.Join(wire.DefaultUnboundFields(), ","), "comma-separated cleartext fields excluded from the AAD (intermediary-mutable, untrusted); empty binds everything")
	attestOn := flag.Bool("attest", false, "DCAP-verify each provider's TDX quote and seal only to the verified enc key (instead of trusting the router-supplied pubkey endpoint)")
	attestEnforce := flag.Bool("attest-enforce", false, "with -attest, reject a provider whose measurement is not in the allowlist instead of only warning; the audited-image allowlist is not wired yet (empty), so enforce currently rejects all providers")
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

	// Route per request: pick the provider via the router and derive its enc key
	// from the broker. The router is told to withhold exactly the sealed fields,
	// so the prompt never reaches it in cleartext on the preview call.
	// The sidecar serves only chat completions, so the route service type is fixed
	// (route.New defaults to "chatbot"); it is not a startup choice.
	routeOpts := []route.Option{route.WithSensitiveFields(sealFields)}
	if *attestOn {
		routeOpts = append(routeOpts, route.WithQuoteVerification(newVerifier(*attestEnforce), nil))
	}
	router := route.New(*routerURL, routeOpts...)
	// Log a redaction-safe summary of any response open (AEAD) failure to the
	// process log — the operator-only counterpart to the opaque
	// "message authentication failed" the caller sees (field names/lengths only,
	// no plaintext or key material; see core.WithDebugLogger).
	client := core.NewWithResolver(router,
		core.WithSealFields(sealFields),
		core.WithUnboundFields(unboundFields),
		core.WithDebugLogger(log.Default()),
	)

	srv := &http.Server{
		Addr: *listen,
		// Single-user and local, so surfacing the raw upstream body in errors aids
		// debugging and never leaves the user's machine (localhost); the gateway
		// deliberately does not do this.
		Handler:           openaiproxy.Handler(client, openaiproxy.WithVerboseUpstreamErrors()),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
	}
	log.Printf("sidecar listening on %s -> route via %s", *listen, *routerURL)
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
	log.Printf("sidecar: TDX quote verification enabled (measurement enforce=%v, allowlist empty)", enforce)
	return attest.New(
		attest.Policy{}, // TODO: load the audited broker-image measurement allowlist
		attest.WithQuoteParser(dcap.NewQuoteParser(dcap.Config{})),
		attest.WithMeasurementMode(mode),
	)
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
