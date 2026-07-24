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
// The gateway also exposes its own attestation quote at GET /quote (design §6,
// phase 2) so an out-of-band validator can confirm the endpoint is a genuine
// enclave. Per-response signatures (issue #19) and multi-tenant concerns (auth,
// billing, rate limiting; issue #20) are later steps. Trusting the router's
// returned endpoint (vs resolving it on chain) is tracked in issue #18.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/client/tee"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func main() {
	listen := flag.String("listen", ":8443", "address to listen on")
	routerURL := flag.String("router-url", route.DefaultRouterURL, "0G router base URL/domain (the route-preview path is appended)")
	routeType := flag.String("route-type", route.DefaultType, "inference kind sent to the route-preview API")
	sealFieldsCSV := flag.String("seal-fields", strings.Join(wire.DefaultSealedFields(), ","), "comma-separated request fields to seal (must include \"messages\")")
	teeMode := flag.String("tee", "", `attestor for GET /quote (required): "dstack" (in-enclave tappd socket) or "mock" (dev only, INSECURE fake quotes)`)
	dstackSocket := flag.String("dstack-socket", tee.DefaultDstackSocket, "dstack tappd unix socket (tee=dstack)")
	tlsCertPath := flag.String("tls-cert", "", "PEM file of the enclave TLS certificate to bind into the quote's report_data (design §6.1.2)")
	flag.Parse()

	sealFields := parseCSV(*sealFieldsCSV)
	if err := wire.ValidateSealedFields(sealFields); err != nil {
		log.Fatalf("invalid -seal-fields: %v", err)
	}

	// The gateway holds no pinned provider: it routes per request and derives the
	// provider's enc key + signer from the broker. The router is told to withhold
	// exactly the sealed fields, so the prompt never reaches it in cleartext even
	// on the control-plane preview call.
	router := route.New(*routerURL,
		route.WithType(*routeType),
		route.WithSensitiveFields(sealFields),
	)
	client := core.NewWithResolver(router, core.WithSealFields(sealFields))

	quote, err := newQuoteHandler(*teeMode, *dstackSocket, *tlsCertPath)
	if err != nil {
		log.Fatalf("attestation: %v", err)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(client, quote),
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
func newHandler(c *core.Client, quote http.Handler) http.Handler {
	mux := http.NewServeMux()
	openaiproxy.Register(mux, c)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	// /quote serves the enclave's attestation quote for download, so an
	// out-of-band validator (or a tier-3 client) can verify the endpoint is a
	// genuine enclave running the expected measurement (design §6).
	mux.Handle("GET /quote", quote)
	return mux
}

// newQuoteHandler selects the attestor for the chosen mode and binds the
// report_data (the TLS cert public key, from -tls-cert), returning the ready
// /quote handler. It fails closed: an unset/unknown -tee, or -tee=dstack without
// a cert to bind, is an error rather than a silently-insecure or empty quote.
func newQuoteHandler(mode, socket, tlsCertPath string) (*tee.Handler, error) {
	var attestor tee.Attestor
	switch mode {
	case "dstack":
		attestor = &tee.Dstack{Socket: socket}
	case "mock":
		attestor = tee.Mock{}
		log.Print("attestation: tee=mock — quotes are INSECURE fakes, for development only")
	default:
		// No default: an unset/unknown -tee fails closed rather than silently
		// selecting an insecure attestor.
		return nil, &badFlag{"tee", mode + ` (want "dstack" or "mock")`}
	}

	var reportData []byte
	if tlsCertPath != "" {
		cert, err := loadCert(tlsCertPath)
		if err != nil {
			return nil, err
		}
		reportData = tee.ReportDataForCert(cert)
	} else if mode == "dstack" {
		// A dstack quote with no cert binding attests the measurement but binds
		// nothing to the TLS endpoint (design §6.1.2) — a genuine but meaningless
		// quote. Refuse to serve one: fail closed rather than warn.
		return nil, &badFlag{"tls-cert", `required with -tee=dstack (bind the enclave TLS cert into the quote)`}
	}

	return tee.NewHandler(attestor, reportData), nil
}

// loadCert reads the first CERTIFICATE block from a PEM file.
func loadCert(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, &badFlag{"tls-cert", path + " (no CERTIFICATE PEM block)"}
	}
	return x509.ParseCertificate(block.Bytes)
}

type badFlag struct{ name, value string }

func (e *badFlag) Error() string { return "invalid -" + e.name + ": " + e.value }

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
