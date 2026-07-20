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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc/client/core"
	"github.com/0gfoundation/0g-pc/protocol/crypto"
	"github.com/0gfoundation/0g-pc/protocol/wire"
)

// maxRequestBytes caps the request body the sidecar will read.
const maxRequestBytes = 10 << 20 // 10 MiB

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
		Handler:           newHandler(client),
		ReadHeaderTimeout: 10 * time.Second, // mitigate slow-header (Slowloris) clients
	}
	log.Printf("sidecar listening on %s -> %s", *listen, *providerURL)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// newHandler is the OpenAI-compatible proxy over the client core. It is split
// out from main so tests can drive it with httptest.
func newHandler(c *core.Client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeError(w, http.StatusBadRequest, "read request body")
			return
		}
		var req wire.Request
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "request body is not a JSON object")
			return
		}
		stream, err := streamRequested(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if stream {
			// Fail loud: a streaming client must not receive a non-SSE body.
			writeError(w, http.StatusNotImplemented, "streaming (stream: true) is not yet supported")
			return
		}
		resp, err := c.Complete(r.Context(), req)
		if err != nil {
			writeError(w, statusFor(err), err.Error())
			return
		}
		out, err := json.Marshal(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode response")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
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

// streamRequested reports whether the request asked for a streamed (SSE)
// response. A present-but-non-boolean "stream" is an error, so a malformed value
// is rejected rather than silently treated as non-streaming.
func streamRequested(req wire.Request) (bool, error) {
	raw, ok := req["stream"]
	if !ok {
		return false, nil
	}
	var stream bool
	if err := json.Unmarshal(raw, &stream); err != nil {
		return false, fmt.Errorf(`field "stream" must be a boolean`)
	}
	return stream, nil
}

// statusFor maps a Complete failure to an HTTP status. A non-2xx provider status
// is surfaced verbatim (so OpenAI clients keep their retry/backoff on 429/5xx vs
// 4xx); otherwise a bad client request is 400, a client-side internal error is
// 500, and anything upstream (transport failure, bad sealed response) is 502.
func statusFor(err error) int {
	var e *core.Error
	if errors.As(err, &e) {
		if e.Status != 0 {
			return e.Status
		}
		switch e.Stage {
		case core.StageRequest:
			return http.StatusBadRequest
		case core.StageInternal:
			return http.StatusInternalServerError
		}
	}
	return http.StatusBadGateway
}

// writeError emits an OpenAI-shaped error object.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": msg},
	})
}
