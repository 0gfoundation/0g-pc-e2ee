package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/freshquote"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// freshEvidencePath is GET /evidence?nonce=<64 hex>: a quote minted for this request,
// with report_data committing to the nonce and the served certificate's public key
// (client/freshquote). Not to be confused with /evidences/, the static bundle.
const freshEvidencePath = "/evidence"

// freshEvidenceTimeout bounds the hop to the quoter, which bounds its own GetQuote.
const freshEvidenceTimeout = 20 * time.Second

// freshEvidenceMaxBody caps the quoter's reply; a quote is a few KiB.
const freshEvidenceMaxBody = 1 << 20

// freshEvidenceRoute relays GET /evidence to the quoter (cmd/quoter) and delegates
// every other path to next. With quoter nil it returns next unchanged.
//
// The gateway only relays: the quote is minted by the quoter, which holds the
// guest-agent socket and fixes the report_data, so this process cannot obtain a
// quote over anything else. A relay that altered the bytes would only fail
// verification. CORS is `*` for the same reason as evidenceRoute: public data,
// no credentials.
func freshEvidenceRoute(quoter *url.URL, next http.Handler) http.Handler {
	if quoter == nil {
		return next
	}
	client := &http.Client{Timeout: freshEvidenceTimeout}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != freshEvidencePath {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Expose-Headers", openaiproxy.HeaderGatewayInstance)
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method {
		case http.MethodGet:
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", evidenceMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			w.Header().Set("Allow", "GET, OPTIONS")
			openaiproxy.WriteError(w, http.StatusMethodNotAllowed, "gateway", "GET only")
			return
		}
		nonce, err := freshquote.ParseNonce(r.URL.Query().Get("nonce"))
		if err != nil {
			openaiproxy.WriteError(w, http.StatusBadRequest, "gateway", err.Error())
			return
		}

		target := quoter.JoinPath("quote")
		target.RawQuery = url.Values{"nonce": {nonce}}.Encode()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
		if err != nil {
			openaiproxy.WriteError(w, http.StatusInternalServerError, "gateway", "build quoter request")
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			openaiproxy.WriteError(w, http.StatusBadGateway, "gateway", "quoter unreachable")
			return
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusTooManyRequests:
			w.Header().Set("Retry-After", "1")
			openaiproxy.WriteError(w, http.StatusTooManyRequests, "gateway", "too many concurrent quote requests")
			return
		case http.StatusServiceUnavailable:
			openaiproxy.WriteError(w, http.StatusServiceUnavailable, "gateway", "certificate not issued yet")
			return
		default:
			openaiproxy.WriteError(w, http.StatusBadGateway, "gateway", fmt.Sprintf("quoter returned %d", resp.StatusCode))
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, freshEvidenceMaxBody+1))
		if err != nil || len(body) > freshEvidenceMaxBody {
			openaiproxy.WriteError(w, http.StatusBadGateway, "gateway", "quoter reply unreadable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}
