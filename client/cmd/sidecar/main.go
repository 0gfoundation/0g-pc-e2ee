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
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func main() {
	listen := flag.String("listen", "localhost:8787", "address to listen on")
	routerURL := flag.String("router-url", route.DefaultRouterURL, "0G router base URL/domain (the route-preview path is appended)")
	sealFieldsCSV := flag.String("seal-fields", strings.Join(wire.DefaultSealedFields(), ","), "comma-separated request fields to seal (must include \"messages\")")
	unboundFieldsCSV := flag.String("unbound-fields", strings.Join(wire.DefaultUnboundFields(), ","), "comma-separated cleartext fields excluded from the AAD (intermediary-mutable, untrusted); empty binds everything")
	flag.Parse()

	sealFields := parseCSV(*sealFieldsCSV)
	if err := wire.ValidateSealedFields(sealFields); err != nil {
		log.Fatalf("invalid -seal-fields: %v", err)
	}
	unboundFields := parseCSV(*unboundFieldsCSV)
	if err := wire.ValidateUnboundFields(unboundFields, sealFields); err != nil {
		log.Fatalf("invalid -unbound-fields: %v", err)
	}

	// Route per request: pick the provider via the router and derive its enc key
	// from the broker. The router is told to withhold exactly the sealed fields,
	// so the prompt never reaches it in cleartext on the preview call.
	// The sidecar serves only chat completions, so the route service type is fixed
	// (route.New defaults to "chatbot"); it is not a startup choice.
	router := route.New(*routerURL,
		route.WithSensitiveFields(sealFields),
	)
	client := core.NewWithResolver(router, core.WithSealFields(sealFields), core.WithUnboundFields(unboundFields))

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
