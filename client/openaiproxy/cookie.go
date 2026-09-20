package openaiproxy

import (
	"net/http"
)

// cookieCredentialName is the HttpOnly cookie the ROUTER issues and accepts as an
// inference credential (its extractBearerToken falls back to `c.Cookie("jwt")`
// after Authorization and x-api-key). The name is a contract with the router, not
// an operator choice, so it is a constant rather than a flag: a gateway reading
// some other cookie would authenticate nobody.
const cookieCredentialName = "jwt"

// AcceptCookieCredential converts the router's HttpOnly `jwt` cookie into an
// Authorization bearer header, so a browser that authenticates by cookie reaches
// the sealed path instead of being rejected at the front door.
//
// It exists for the global-entry topology: the gateway fronting the router at the
// router's own hostname.
// Until then a cookie-authenticated caller had a working alternative: call the
// router directly. Once the gateway IS the router's hostname there is no
// "directly", and the first-party web app's chat requests — which carry no
// Authorization header at all — would every one of them 401 here, because
// RequireInferenceCredential reads only Authorization and x-api-key and
// routingHeaders never forwards a Cookie.
//
// Order mirrors the router's exactly: an explicit credential wins, so a request
// carrying Authorization or x-api-key passes through untouched and a cookie is
// looked at only in their absence. That way a page holding both is authenticated
// as the same principal here and upstream, rather than as one thing at the gateway
// and another at the router.
//
// # Why this is gated on the origin allowlist, and why that gate is not optional
//
// A cookie is an AMBIENT credential: the browser attaches it to a cross-origin
// request without the page asking. CORS does not prevent the request from being
// sent — it only hides the response — and a POST with `Content-Type: text/plain`
// is a "simple" request that is sent with no preflight at all, while still
// carrying a body this proxy will happily parse as JSON. So a page on any origin
// could otherwise spend a logged-in visitor's balance and simply not read the
// reply. That is CSRF, and the response being invisible does not undo the charge.
//
// The defense is the router's own: a cookie credential is honored only for a
// request whose Origin is present AND on the allowlist. Both halves matter — a
// missing Origin is rejected rather than trusted, because "no Origin" is what a
// same-origin form post looks like too. A cross-origin attacker's request carries
// its own true Origin (the browser sets it and a page cannot forge it), so the
// allowlist is what turns it away. Same rule, same matcher (originAllowed) as the
// preflight answer, so a page that clears CORS here is not then rejected by this.
//
// # INVARIANT: this allowlist must stay a SUBSET of the router's own
//
// The gateway's origin gate is not a second opinion alongside the router's — it is
// the ONLY one, and the conversion is what makes it so. The router runs
// checkCookieCSRF only when it read the credential out of a cookie itself
// (`isCookie`); a request arriving as `Authorization: Bearer …` never reaches that
// check, however the bearer was obtained. So every request converted here bypasses
// the router's CSRF gate by construction, and this allowlist is what stands in for
// it.
//
// Which means: an origin allowed HERE but not in the router's `auth.allowed_origins`
// is an origin the gateway grants a capability the router would have refused, with
// nothing anywhere to report it. The two lists live in two repositories and two
// deployments and are deliberately not identical (deploy/phala/README.md), so
// nothing mechanical enforces the direction — the containment is a rule a human
// keeps. It is safe today: the deployed gateway list is the first-party origins and
// the router's is a strict superset of those.
//
// The reverse direction is fine. An origin the router allows and this gateway does
// not is simply a page that cannot use the gateway, which is a narrowing.
//
// One place this design is STRICTER than the router, worth knowing when comparing
// them: an allowlist of "*" disables ambient credentials here, whereas the router's
// checkCookieCSRF returns true for "*" and skips the CSRF check entirely.
//
// # Why allowHeadersFor's reflect-what-was-asked-for policy is still sound
//
// That policy's stated precondition was "no ambient credentials: ACAC unset and no
// cookie is read", and enabling cookies changes the first half. It stays safe
// because header reflection only ever happens on a preflight, and a preflight is
// answered only for an allowlisted origin — the same set this middleware honors a
// cookie for. What would break the policy is a cookie honored WITHOUT the origin
// check, which is exactly what this refuses to do.
//
// The Cookie header itself is deliberately left on the request rather than
// stripped: what does and does not travel to the untrusted router is decided in
// one place (routingHeaders, which forwards the X-0G-* namespace and the
// attribution headers and nothing else), and a second, quieter enforcement point
// here would only make that one look optional.
//
// Mounted by the gateway OUTSIDE RequireInferenceCredential — it has to run before
// the gate, or the gate 401s the request this exists to admit. There is no flag: it
// is mounted whenever the origin allowlist can vouch for a request, i.e. for every
// allowlist except one containing "*", where the gateway leaves it off because a
// gate that admits every origin is not a CSRF defense at all. The sidecar is a
// single-user localhost process with no browser and no cookies, so it never mounts
// this.
func AcceptCookieCredential(origins []string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if credential(r) != "" {
			// An explicit credential is present, so the cookie is not consulted.
			//
			// The test is credential() — the same function that decides what actually
			// travels upstream — and NOT bearerToken(), which the front-door gate uses.
			// They disagree on two inputs, and on both of them bearerToken would have let
			// the cookie win over a credential the caller supplied:
			//
			//   - `Authorization` in a non-bearer scheme: bearerToken returns "" and
			//     stops there, so this header would be OVERWRITTEN with the cookie's
			//     bearer. The caller's credential does not just lose, it disappears.
			//   - `x-api-key` alongside such an `Authorization`: bearerToken's early
			//     return never reaches its x-api-key branch, so an explicit API key would
			//     lose to the cookie — while the router, whose own extractBearerToken
			//     falls THROUGH a non-bearer Authorization to x-api-key, would have
			//     honored the key. Same request, two principals, two billing accounts.
			//
			// credential() has neither gap: it returns the Authorization header verbatim
			// whatever its scheme, and otherwise wraps x-api-key. So "would this request
			// already carry a credential upstream?" is exactly the question, and it is
			// asked of the thing that answers it.
			h.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(cookieCredentialName)
		if err != nil || cookie.Value == "" {
			// No cookie either. Leave the request exactly as it arrived so the gate
			// below gives its own "missing API key" answer — this middleware has no
			// opinion about a request that carries no credential at all.
			h.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin == "" || !originAllowed(origin, origins) {
			WriteError(w, http.StatusForbidden, "gateway",
				"origin not allowed for cookie authentication; send the credential as an "+
					"Authorization bearer header instead")
			return
		}
		// Shallow-copy the request and clone the header rather than mutating the one
		// we were handed: the middleware above us (the access log) still holds the
		// original, and a handler that rewrites its caller's header block is the kind
		// of action at a distance that is fine until something else reads it.
		r2 := *r
		r2.Header = r.Header.Clone()
		r2.Header.Set("Authorization", "Bearer "+cookie.Value)
		h.ServeHTTP(w, &r2)
	})
}
