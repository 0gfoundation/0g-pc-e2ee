package openaiproxy

import (
	"net/http"
)

// HeaderE2EE declares whether an exchange was end-to-end encrypted to a provider
// enclave.
//
// It is stamped on every response from the two paths that carry, or could carry,
// inference content: the sealed path and the cleartext passthrough. Operational
// and evidence routes (/healthz, /readyz, /evidences/, the identity endpoints) are
// NOT marked, and a CORS preflight is answered before the mux and so is not
// either. Those responses have no content to make a claim about, and marking them
// would dilute a header whose whole use is "what happened to my prompt".
//
// Within that set it is stamped on BOTH branches on purpose. A marker that
// appeared only on cleartext responses would tell a client nothing it can act on —
// absence would be ambiguous between "sealed" and "an older gateway that does not
// say" — so a client could never assert sealing, only hope for it. Present on both,
// with one of the two values below, it becomes a check: a caller that requires
// privacy can refuse anything that is not E2EEValueSealed, and refuse it on the
// response it actually got rather than on configuration it cannot see.
//
// That matters most for what it is not doing yet. The seal policy this design
// calls for (docs in 0g-router, e2ee-global-entry-design.zh.md §2) has an `auto`
// mode — seal when a provider can, pass through in cleartext when none can — and
// the objection to `auto` is that silent downgrade turns a privacy guarantee into
// a coin flip. This header is what makes the downgrade audible.
//
// It is a statement about the CHANNEL, not a verdict on the provider: sealed means
// this request was HPKE-sealed to an attested enclave and the response opened from
// it, which is a different and weaker claim than the §8 response signature having
// verified (see setProvider for the same distinction on X-Provider). Nothing here
// is evidence; it is the gateway reporting which of its two paths served you.
const HeaderE2EE = "X-0G-E2EE"

const (
	// E2EEValueSealed: the request was sealed to a provider enclave and the response
	// was opened from it — the sealed inference path.
	E2EEValueSealed = "sealed"
	// E2EEValueNone: this response came through the cleartext passthrough to the
	// router. Correct and expected for the metadata and discovery surface (the model
	// catalog, provider lists), and the honest answer for a content-bearing surface
	// the passthrough is configured to carry (see -unsealed-subtree): the router saw
	// whatever transited it.
	E2EEValueNone = "none"
)

// MarkE2EE stamps HeaderE2EE with value on every response h produces.
//
// Set before h runs, so it is on the wire for a streamed response too — the
// header block of an SSE response is flushed with the first frame, long before the
// handler returns, and a header set afterwards would be silently dropped.
//
// A handler that sets the header itself overwrites this, which is the right
// precedence: the specific path knows better than the wrapper. The reverse proxy is
// the case that needs care rather than precedence — it copies upstream headers with
// Add, so a router that ever emitted this name would APPEND to ours and put two
// values on one response. newRouterProxy strips it upstream-side for that reason,
// the same way it strips the upstream's CORS headers.
func MarkE2EE(value string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderE2EE, value)
		h.ServeHTTP(w, r)
	})
}
