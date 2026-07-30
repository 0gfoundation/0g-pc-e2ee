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
// Startup wiring (flags, env-var defaults, route/seal plumbing) is shared with
// the sidecar via client/cmd/internal/proxycli; the gateway keeps only its own
// listen default (:8443), the ZG_GATEWAY_* env prefix, and the operational
// routes below. Every parameter can be set via flag or a ZG_GATEWAY_* env var
// (flag > env > built-in default); env config is the primary path for the
// TEE/dstack deployment, where the compose file's `environment:` block is
// measured into the CVM attestation (see deploy/phala/docker-compose.yml).
//
// Attestation (the /quote body and per-response signature; issue #19, on
// protocol/attest / issue #7) and multi-tenant concerns (auth, billing, rate
// limiting; issue #20) are later steps; /quote is a stub until then. Trusting
// the router's returned endpoint (vs resolving it on chain) is tracked in
// issue #18.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/cmd/internal/proxycli"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

func main() {
	f := proxycli.RegisterFlags(flag.CommandLine, "ZG_GATEWAY", ":8443")
	flag.Parse()

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
	client := f.Build("gateway", logger)

	srv := &http.Server{
		Addr:              *f.Listen,
		Handler:           newHandler(client, logger),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
	}
	// TLS is terminated by the dstack ZT-HTTPS front end inside the enclave, so
	// the gateway itself serves plaintext HTTP on the socket dstack forwards to;
	// the enclave boundary, not this listener, is the TLS edge.
	// Serve until a shutdown signal, then drain in-flight requests gracefully
	// (shared with the sidecar so both forms handle SIGTERM identically — the
	// dstack/Phala deployment sends it on every redeploy). ListenAndServe's clean
	// shutdown is folded into a nil return; only a real listen failure is an error.
	logger.Info("gateway listening", "listen", *f.Listen, "router_url", *f.RouterURL)
	if err := proxycli.Serve(srv, logger); err != nil {
		logger.Error("gateway server exited", "err", err)
		os.Exit(1)
	}
}

// newHandler mounts the shared OpenAI proxy plus the gateway-only operational
// routes (health, attestation quote), wrapped in the access-log middleware so
// every request emits one redaction-safe structured line. It is split out from
// main so tests can drive it with httptest.
func newHandler(c *core.Client, logger *slog.Logger) http.Handler {
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
	return openaiproxy.LogRequests(logger, mux)
}
