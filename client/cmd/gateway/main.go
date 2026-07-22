// Command gateway is the cloud-TEE gateway form: the SAME client core wrapped
// as a server, but SERVER-RUN and 0G-operated — it runs inside an attested CVM
// and adds one attested trust party. It serves no-install / browser / thin
// clients that cannot run a sidecar: TLS terminates inside the enclave (dstack
// ZT-HTTPS), the gateway seals each request to the pinned provider and opens the
// sealed response, and plaintext streams back over that same TLS. See
// docs/design/cloud-gateway.md for the trust model.
//
// This is the pin-only phase (design §10 step 1): the gateway serves the shared
// openaiproxy handler against a single flag-pinned provider. Attestation (the
// /quote body and per-response signature, protocol/attest / issue #7) and route
// support are later steps; /quote is a stub until then.
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func main() {
	listen := flag.String("listen", ":8443", "address to listen on")
	providerURL := flag.String("provider-url", core.DefaultProviderURL, "provider (router/broker) OpenAI chat-completions endpoint")
	encPubB64 := flag.String("provider-enc-key", "", "provider HPKE public key, base64url (attestation stub)")
	signer := flag.String("provider-signer", "", "provider on-chain signer address (0x...)")
	sealFieldsCSV := flag.String("seal-fields", strings.Join(wire.DefaultSealedFields(), ","), "comma-separated request fields to seal (must include \"messages\")")
	flag.Parse()

	if *encPubB64 == "" || *signer == "" {
		log.Fatal("provider-enc-key and provider-signer are required")
	}
	encPub, err := base64.RawURLEncoding.DecodeString(*encPubB64)
	if err != nil {
		log.Fatalf("bad provider-enc-key: %v", err)
	}
	sealFields := parseCSV(*sealFieldsCSV)
	if err := wire.ValidateSealedFields(sealFields); err != nil {
		log.Fatalf("invalid -seal-fields: %v", err)
	}

	client := core.New(core.Provider{
		URL:        *providerURL,
		EncPubKey:  crypto.PublicKey(encPub),
		SignerAddr: *signer,
	}, core.WithSealFields(sealFields))

	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(client),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
	}
	// TLS is terminated by the dstack ZT-HTTPS front end inside the enclave, so
	// the gateway itself serves plaintext HTTP on the socket dstack forwards to;
	// the enclave boundary, not this listener, is the TLS edge.
	log.Printf("gateway listening on %s -> %s", *listen, *providerURL)
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
	// bound into report_data) once protocol/attest lands (issue #7); until then
	// it advertises the endpoint but is Not Implemented, so a validator gets a
	// clear signal rather than a 404.
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
