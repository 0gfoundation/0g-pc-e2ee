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
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func main() {
	listen := flag.String("listen", ":8443", "address to listen on")
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

	// The gateway holds no pinned provider: it routes per request and derives the
	// provider's enc key + signer from the broker. The router is told to withhold
	// exactly the sealed fields, so the prompt never reaches it in cleartext even
	// on the control-plane preview call.
	// The gateway serves only chat completions, so the route service type is fixed
	// (route.New defaults to "chatbot"); it is not a startup choice.
	router := route.New(*routerURL,
		route.WithSensitiveFields(sealFields),
	)
	client := core.NewWithResolver(router, core.WithSealFields(sealFields), core.WithUnboundFields(unboundFields))

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
