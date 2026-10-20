package openaiproxy

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
)

// BoundBodyRead gives a request's body d to arrive in full, counted from when h is
// entered.
//
// WHY. Once a request's headers are in, the only other bound on its body is the
// server's ReadTimeout, which on the gateway's public listener is a loose 90 s
// backstop (before this change there was none) — and the body is read INSIDE the
// in-flight cap (LimitInFlight), on purpose: buffering it outside would put that
// memory beyond the ceiling the cap is derived from. So a client that sends
// headers and then trickles its body holds a slot for as long as that allows, and
// the credential gate in front only checks a credential's shape, so it costs no
// account. A few hundred such connections hold every slot. dstack-ingress in front
// is a TCP proxy with a 24 h idle timeout, so it does not bound this either.
//
// WHY NOT ONLY http.Server.ReadTimeout. It bounds every route, and the catch-all
// reverse-proxies uploads to the router (POST /v1/files: up to 5 files of 50 MB by
// the router's defaults) that nothing here caps, so the server-wide value has to
// be loose enough for those — the gateway's is 90 s, above the router's own 60 s.
// The inference routes cap their bodies (MaxRequestBytes sealed; the gateway's
// cleartext branch at 20 MiB), so they can be held to far less; this bounds only
// what it wraps, and starts the clock when a slot is held, which is the resource
// it protects.
//
// The deadline is set on the connection through the response's controller.
// net/http lifts it itself when the body hits EOF (startBackgroundRead clears the
// read deadline before it watches for the client going away), so a response
// streamed for minutes after a body read in one second is untouched — pinned by
// TestBoundBodyReadLiftsAtEOF. A request with no body is passed through. A body
// that misses the deadline fails its next Read with an error wrapping
// os.ErrDeadlineExceeded, which readBodyError answers 408. d <= 0 disables it.
func BoundBodyRead(d time.Duration, h http.Handler) http.Handler {
	if d <= 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(d)); err != nil {
				// The writer chain cannot reach the connection (a wrapper without
				// Unwrap). Serving unbounded is what happened before this existed;
				// refusing every request over it would be an outage. Counted, so it
				// cannot stay invisible, and pinned by the gateway's handler test.
				metrics.BodyReadUnbounded()
			}
		}
		h.ServeHTTP(w, r)
	})
}

// readBodyError answers a failed request-body read: 413 past MaxRequestBytes, 408
// when BoundBodyRead's deadline passed first, 400 for anything else.
func readBodyError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeGatewayError(w, http.StatusRequestEntityTooLarge, "request body too large")
	case errors.Is(err, os.ErrDeadlineExceeded):
		metrics.BodyReadTimeout()
		writeGatewayError(w, http.StatusRequestTimeout, "request body not received in time")
	default:
		writeGatewayError(w, http.StatusBadRequest, "read request body")
	}
}
