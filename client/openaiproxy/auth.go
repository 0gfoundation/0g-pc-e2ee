package openaiproxy

import (
	"net/http"
	"strings"
)

// Credential prefixes mirror the router's (service.InferenceKeyPrefix /
// service.MgmtKeyPrefix). The gateway front door only needs the prefixes to
// classify a credential's shape; it deliberately does NOT reimplement the
// router's validation.
const (
	inferenceKeyPrefix = "sk-" // inference API key — passes on prefix alone
	mgmtKeyPrefix      = "mk-" // management key — rejected on the inference path
)

// RequireCredential is the gateway's front-door auth gate for the sealed
// inference path. It is a cheap presence/shape check, NOT authentication: the
// router remains the authoritative auth/billing point (docs/design/cloud-gateway.md
// §12) and re-validates every credential the gateway forwards. This gate's only
// job is to shed traffic the router would reject anyway, before the gateway pays
// for sealing and the route-preview round trip:
//
//   - no credential          -> 401 (missing key)
//   - management key (mk-…)   -> 403 (mgmt keys cannot do inference; mirrors the
//                               router's RejectMgmtKey)
//   - everything else         -> forwarded to the wrapped handler
//
// Inference keys (sk-…) pass on their prefix alone: the key body's length has
// changed over time, so only the prefix is stable enough to gate on, and the
// router's DB lookup is what actually authenticates it. JWT and Privy tokens
// carry no stable prefix and so are opaque to this gate — they pass through and
// are verified authoritatively upstream. The gate therefore never accepts a
// credential the router would not; it only rejects the two shapes (absent, mgmt)
// that are certain to fail there.
//
// It is mounted only by the gateway. The sidecar shares this package but is
// single-user and needs no auth, so it never wraps its handler with this.
func RequireCredential(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			WriteError(w, http.StatusUnauthorized, "gateway", "missing API key")
			return
		}
		if strings.HasPrefix(tok, mgmtKeyPrefix) {
			WriteError(w, http.StatusForbidden, "gateway",
				"management keys cannot be used for inference; use an inference API key (sk-…)")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// bearerToken returns the raw caller token from the Authorization bearer header
// or, failing that, the Anthropic-convention x-api-key header — or "" when
// neither carries one. It mirrors credential()'s source precedence
// (Authorization wins over x-api-key) but strips the "Bearer " scheme so the
// key prefix can be inspected. A present-but-non-bearer Authorization header is
// treated as absent (""): the router likewise only accepts the bearer scheme,
// so such a request would be rejected upstream regardless.
func bearerToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
		return ""
	}
	if apiKey := r.Header.Get("x-api-key"); apiKey != "" {
		return strings.TrimSpace(apiKey)
	}
	return ""
}
