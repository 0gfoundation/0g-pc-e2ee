// Command sidecar is the local sidecar form: the client core wrapped as a
// localhost OpenAI-compatible proxy. Run it and point any OpenAI SDK at it via
// base_url; it seals the sensitive request fields to the provider and opens the
// sealed response, so your app keeps talking plain OpenAI.
//
// The provider's encryption key and signer address are passed in as flags for
// now (attestation — verifying them out of a TEE quote — is a later step).
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
	listen := flag.String("listen", "localhost:8787", "address to listen on")
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
		Handler:           openaiproxy.Handler(client),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
	}
	log.Printf("sidecar listening on %s -> %s", *listen, *providerURL)
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
