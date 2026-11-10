package main

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// recoverWithoutAddress turns a handler panic into one log line that carries no
// client address, then aborts the connection exactly as net/http would have.
//
// Why it exists. net/http's own recovery logs `http: panic serving <RemoteAddr>: …`
// to the server's ErrorLog (stderr by default). With -proxy-protocol, RemoteAddr is
// the CLIENT's address taken from the PROXY header, and this CVM's logs are public
// (`public_logs`), so that line would publish a caller's IP — against the promise in
// deploy/phala/README.md "Client address" that the gateway never logs one. It is the
// only server log line that names the peer and can fire here (the other, the TLS
// handshake error, needs TLS, which this listener does not do).
//
// Re-panicking with http.ErrAbortHandler keeps the observable behaviour: net/http
// still closes the connection (or resets the HTTP/2 stream) without writing a
// response it has not already sent, and it logs nothing for that sentinel. A handler
// that panics with ErrAbortHandler itself — httputil.ReverseProxy does, when the
// client goes away mid-copy — is passed through untouched and unlogged, as before.
//
// It catches only panics on the handler's own goroutine; a goroutine a handler
// starts that panics still takes the process down, and net/http logs nothing then.
func recoverWithoutAddress(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(v)
			}
			// What goes on this line, and why, given that it lands in PUBLIC logs:
			//   - no RemoteAddr: the reason this function exists;
			//   - the path REDACTED, the same way the access log and the router
			//     passthrough's ErrorHandler print it: an async poll path is
			//     /v1/async/jobs/{id}.{key}, and the key is the ephemeral private
			//     key that opens that job's result (a full job id is a credential,
			//     SPEC §7.5.3). r.URL.Path excludes the query string;
			//   - the panic value and stack VERBATIM. This is the one place in the
			//     gateway that prints an arbitrary panic value into public logs. A
			//     runtime panic (nil map, index out of range) carries no request
			//     data, and a stack prints arguments as machine words, not the
			//     strings they point to; but a panic built from request content —
			//     panic(fmt.Sprintf("bad body %s", b)), a wrapped error quoting a
			//     path or a header — would be published as written. Do not panic
			//     with request data anywhere under this handler.
			logger.Error("handler panic",
				"method", r.Method, "path", openaiproxy.RedactJobPath(r.URL.Path),
				"panic", v, "stack", string(debug.Stack()))
			panic(http.ErrAbortHandler)
		}()
		next.ServeHTTP(w, r)
	})
}
