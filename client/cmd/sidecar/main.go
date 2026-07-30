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
//
// Startup wiring (flags, env-var defaults, route/seal plumbing) is shared with
// the gateway via client/cmd/internal/proxycli; the sidecar keeps only its own
// listen default (localhost:8787), the ZG_SIDECAR_* env prefix, and the verbose
// upstream errors. Every parameter can be set via flag or a ZG_SIDECAR_* env var
// (flag > env > built-in default).
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/cmd/internal/proxycli"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

func main() {
	f := proxycli.RegisterFlags(flag.CommandLine, "ZG_SIDECAR", "localhost:8787")
	flag.Parse()

	// Build validates the flags and wires the route-and-seal client core (shared
	// with the gateway). "sidecar" only labels the attestation log line. The debug
	// logger it attaches records a redaction-safe summary of any response open
	// (AEAD) failure to the process log — the operator-only counterpart to the
	// opaque "message authentication failed" the caller sees (field names/lengths
	// only, no plaintext or key material).
	client := f.Build("sidecar")

	srv := &http.Server{
		Addr: *f.Listen,
		// Single-user and local, so surfacing the raw upstream body in errors aids
		// debugging and never leaves the user's machine (localhost); the gateway
		// deliberately does not do this.
		Handler:           openaiproxy.Handler(client, openaiproxy.WithVerboseUpstreamErrors()),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
	}
	log.Printf("sidecar listening on %s -> route via %s", *f.Listen, *f.RouterURL)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
