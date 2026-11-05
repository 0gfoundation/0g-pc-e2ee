package openaiproxy

import "net/http"

// Response headers the gateway's "0g/auto" layer (cmd/gateway/autoroute.go)
// sets: the task the conversation was classified as, the model it was sent as,
// and — once the conversation's opening has been classified — whether that
// classification was sealed (HeaderAutoClassifierE2EE: sealed or none).
// Exposed to browsers with the rest (corsExposeHeaders).
const (
	HeaderAutoTask           = "X-0G-Auto-Task"
	HeaderAutoModel          = "X-0G-Auto-Model"
	HeaderAutoClassifierE2EE = "X-0G-Auto-Classifier-E2EE"
)

// Credential is the caller's credential as an Authorization value, the one
// the sealed path forwards (see credential).
func Credential(r *http.Request) string { return credential(r) }

// RoutingHeaders is the subset of h the sealed path forwards to the router
// (see routingHeaders).
func RoutingHeaders(h http.Header) http.Header { return routingHeaders(h) }

// CopyPassthroughHeaders adds to w the router response headers the sealed path
// surfaces (see passthroughResponseHeaders), for a caller that relays a router
// answer itself.
func CopyPassthroughHeaders(w http.ResponseWriter, src http.Header) { setPassthrough(w, src) }
