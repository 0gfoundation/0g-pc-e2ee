package openaiproxy

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// DefaultAllowedOriginsCSV is the built-in browser origin allowlist: the 0G
// first-party app origins (0g.ai and its subdomains) plus the two local dev-server
// ports.
//
// Why these at all: a browser reaching the gateway is the same first-party app
// that reaches the router directly (the gateway is a drop-in origin swap for the
// router's chat endpoint, and its catch-all reverse-proxies the router's metadata
// surface), so a page allowed to call the router has to be allowed to call the
// gateway or the E2EE path is unusable from exactly the clients it exists for.
//
// This is deliberately a SUBSET of what the router accepts, not a mirror of it:
// the router's list also carries several third-party-hosted preview/deploy
// origins, which are not extended the ability to drive sealed inference through an
// enclave by default. A deployment that needs one adds it via
// ZG_GATEWAY_ALLOWED_ORIGINS — the default is a starting point, not a binding, and
// erring narrow is the right direction for a list whose entries each widen who can
// reach the enclave.
//
// The localhost entries are development conveniences: they let a page served from
// a developer's machine seal through whatever enclave this gateway runs in. Drop
// them via the env override (no code change) on a deployment that does not need
// that.
const DefaultAllowedOriginsCSV = "https://0g.ai,https://*.0g.ai,http://localhost:3000,http://localhost:5173"

// corsAllowMethods is the preflight's Access-Control-Allow-Methods. It mirrors
// the router's list because the gateway's catch-all fronts the router's whole
// non-sealed surface, including the PATCH/DELETE key-management routes a browser
// app uses; a method missing here fails the preflight and the browser never sends
// the real request. Only GET/HEAD/POST are "simple" methods that need no preflight,
// so every other verb has to be named.
const corsAllowMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"

// corsAllowHeaders is the preflight's Access-Control-Allow-Headers: the router's
// own list plus the two headers only the gateway sees.
//
//   - x-api-key — the Anthropic-convention credential this proxy accepts
//     alongside Authorization (see credential()). The router does not list it;
//     the gateway must, or an Anthropic-SDK-shaped browser call fails preflight.
//   - X-Request-Id — honored inbound for cross-hop correlation (see accesslog.go).
//
// The X-0G-* routing directives are listed individually rather than by prefix
// because Access-Control-Allow-Headers has no wildcard-per-prefix form; a new
// forwarded directive (routingHeaders forwards the whole X-0G-* namespace) needs
// its name added here before a browser can send it.
const corsAllowHeaders = "Origin, Content-Type, Authorization, x-api-key, X-Request-Id, " +
	"X-0G-Source-Id, HTTP-Referer, X-Title, " +
	"X-0G-Provider-Address, X-0G-Provider-Sort, X-0G-Provider-Trust-Mode, X-0G-Provider-Allow-Fallbacks"

// corsMaxAge lets a browser cache one preflight for 12h (the router's value), so
// a chatting page pays the extra round trip once rather than per request.
const corsMaxAge = "43200"

// corsExposeHeaders is derived from the SAME list the proxy actually re-emits
// (passthroughResponseHeaders) plus ZG-Res-Key, which setResKey surfaces
// separately. Deriving it instead of restating it is what keeps the two from
// drifting: a header added to the passthrough set becomes readable by browser JS
// automatically, and one removed stops being advertised. Without this, fetch()
// sees only the CORS-safelisted response headers — Retry-After, the rate-limit
// counters, ZG-Failure-Source and X-Request-ID would all read as absent from a
// browser even though they are on the wire.
var corsExposeHeaders = strings.Join(append([]string{headerResKey}, passthroughResponseHeaders...), ", ")

// ParseOrigins splits a comma-separated origin allowlist into trimmed, non-empty
// patterns. An empty (or all-blank) value yields nil — no origin matches, i.e.
// browser access is off — which is a meaningful configuration, not a mistake.
func ParseOrigins(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ValidateOrigins rejects patterns that can never match a real browser Origin, so
// a typo fails at startup instead of silently blocking the app it was meant to
// allow. It is a shape check only — no DNS, no reachability.
func ValidateOrigins(origins []string) error {
	for _, o := range origins {
		if err := validateOrigin(o); err != nil {
			return fmt.Errorf("origin %q: %w", o, err)
		}
	}
	return nil
}

func validateOrigin(o string) error {
	if o == "*" {
		return nil
	}
	var host string
	switch {
	case strings.HasPrefix(o, "http://"):
		host = strings.TrimPrefix(o, "http://")
	case strings.HasPrefix(o, "https://"):
		host = strings.TrimPrefix(o, "https://")
	default:
		return errors.New("must start with http:// or https:// (a browser Origin is scheme://host[:port])")
	}
	if host == "" {
		return errors.New("no host")
	}
	if strings.ContainsAny(o, " \t") {
		return errors.New("contains whitespace")
	}
	// A browser's Origin header is scheme://host[:port] and never carries a path,
	// so "https://app.example.com/" (the common copy-paste from a URL bar) would
	// match nothing at all.
	if strings.ContainsAny(host, "/?#") {
		return errors.New("must have no path, query, or trailing slash — a browser's Origin header never carries one, so such a pattern can never match")
	}
	if strings.Contains(host, "*") {
		// The parent domain after "*." must be non-empty: "https://*." would compile to
		// the suffix "." and match no real origin, which is the same never-matches class
		// as a trailing slash above. Note this deliberately still accepts a
		// single-label parent ("https://*.localhost" is a legitimate dev pattern);
		// rejecting a public-suffix parent like "https://*.com" would need the public
		// suffix list, so that stays an operator judgment rather than a shape check.
		rest, ok := strings.CutPrefix(host, "*.")
		if !ok || rest == "" || strings.Contains(rest, "*") {
			return errors.New(`the only supported wildcard is a leading "*." label followed by a domain (e.g. https://*.0g.ai)`)
		}
	}
	return nil
}

// originAllowed reports whether origin matches any pattern, with the SAME
// semantics as the router's own origin matching: "*" allows anything, a plain
// pattern matches case-insensitively, and a "*." pattern matches by prefix+suffix
// — so "https://*.0g.ai" covers "https://chat.0g.ai" but NOT the bare apex
// "https://0g.ai", which must be listed separately (as the default above does).
// Matching identically is deliberate even though the two allowlists differ: an
// origin this gateway allows must be read the same way the router reads it, so a
// page that clears the gateway is not then rejected by the router on the request
// the gateway forwards — a failure that would surface deep in the call, not as a
// CORS error the page can act on.
func originAllowed(origin string, patterns []string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		if strings.EqualFold(origin, p) {
			return true
		}
		if i := strings.Index(p, "*."); i >= 0 {
			prefix, suffix := p[:i], p[i+1:] // "https://" and ".0g.ai"
			if strings.HasPrefix(strings.ToLower(origin), strings.ToLower(prefix)) &&
				strings.HasSuffix(strings.ToLower(origin), strings.ToLower(suffix)) {
				return true
			}
		}
	}
	return false
}

// CORS wraps h with cross-origin access control for browser callers, gated on the
// allowlist in origins (see DefaultAllowedOriginsCSV / ParseOrigins). It answers
// preflights itself and adds the response headers a browser needs on the real
// request; a nil/empty allowlist allows no origin, so browser access is off.
//
// It must wrap the WHOLE mux, not a route: a preflight is an OPTIONS to the target
// path, so mounted below the mux it would fall through the gateway's catch-all to
// the router (whose reply is governed by the router's allowlist, not this one) and
// through the credential gate, which would 401 it — a browser never sends
// credentials on a preflight. Answering it here makes this allowlist the single
// authority and keeps the gate on the real request only.
//
// Deliberate choices:
//
//   - The allowed origin is echoed back (never a literal "*"), with Vary: Origin,
//     so a shared cache cannot serve one origin's response to another.
//   - Access-Control-Allow-Credentials is NOT set. The proxy authenticates from an
//     Authorization / x-api-key header the app sets explicitly, which is not a CORS
//     "credential" (cookies, TLS certs, HTTP auth are), and no cookie is ever read.
//     Leaving it off keeps ambient browser credentials out of the auth path and
//     avoids the "*"-plus-credentials trap.
//   - A DISALLOWED origin fails differently by request kind: a preflight is
//     rejected 403 (only a browser sends one, so refusing it is safe and shows up
//     in the access log as a real signal), while a non-preflight request is served
//     normally WITHOUT CORS headers — the browser then blocks the response, and a
//     non-browser client that happens to send an Origin header (some SDKs and
//     proxies do) keeps working. Turning CORS into server-side origin blocking
//     would break those callers for no security gain: CORS is enforced by the
//     browser, and any non-browser client can send whatever Origin it likes.
func CORS(origins []string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// A preflight is an OPTIONS carrying Access-Control-Request-Method. A bare
		// OPTIONS is not one and is left to the mux (the catch-all forwards it to the
		// router), so this middleware never swallows a plain OPTIONS request.
		preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
		if origin == "" {
			h.ServeHTTP(w, r)
			return
		}
		// Set on every origin-bearing response, allowed or not: the response DOES vary
		// by Origin, and a cache that missed that would poison one origin with
		// another's headers.
		w.Header().Add("Vary", "Origin")
		if !originAllowed(origin, origins) {
			if preflight {
				WriteError(w, http.StatusForbidden, "gateway", "origin not allowed")
				return
			}
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		if preflight {
			// The preflight answer depends on the requested method/headers too, so a
			// cache keyed on Origin alone would still be wrong.
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
			w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
			w.Header().Set("Access-Control-Max-Age", corsMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)
		h.ServeHTTP(w, r)
	})
}

// StripCORSHeaders removes every Access-Control-* header from an upstream
// response block, so the gateway's own CORS middleware is the single authority.
// The catch-all reverse proxy copies upstream headers verbatim, and the router
// sets its own Access-Control-Allow-Origin — two values on one response is a hard
// browser failure ("contains multiple values"), and the router's allowlist is not
// necessarily this gateway's. Called from the proxy's ModifyResponse.
func StripCORSHeaders(h http.Header) {
	for name := range h {
		// Canonicalize only to CLASSIFY the key, then delete the literal map entry:
		// http.Header.Del canonicalizes its argument, so on a non-canonical key it
		// would delete a different (likely absent) entry and leave this one in place —
		// exactly the upstream Allow-Origin this function exists to remove. Go's
		// transport canonicalizes response headers, so that only bites a hand-built
		// http.Header or a custom RoundTripper, but the check above already assumes
		// non-canonical keys are possible, so the delete must handle them too.
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") {
			delete(h, name)
		}
	}
}
