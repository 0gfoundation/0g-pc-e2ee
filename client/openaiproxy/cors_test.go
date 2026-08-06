package openaiproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// corsHandler wraps a sentinel handler in CORS and reports whether the inner
// handler ran, so a test can tell "answered by the middleware" from "passed
// through" — the distinction that matters for every preflight case.
func corsHandler(origins []string) (h http.Handler, reached *bool) {
	var ran bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.Header().Set(headerResKey, "res-key-123")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("inner"))
	})
	return CORS(origins, inner), &ran
}

// preflight builds the OPTIONS request a browser sends before a non-simple call:
// Origin plus Access-Control-Request-Method, and deliberately NO credential — a
// browser never sends one on a preflight, which is why CORS has to answer it
// ahead of the gateway's credential gate.
func preflight(origin string) *http.Request {
	r := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	return r
}

func TestCORSPreflightAllowed(t *testing.T) {
	h, reached := corsHandler(ParseOrigins(DefaultAllowedOriginsCSV))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, preflight("https://chat.0g.ai"))

	if rec.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", rec.Code)
	}
	if *reached {
		t.Error("preflight reached the inner handler; it must be answered by the middleware (the credential gate would 401 it)")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://chat.0g.ai" {
		t.Errorf("Allow-Origin: got %q, want the request's origin echoed back", got)
	}
	// A literal "*" would break any future credentialed mode and is less precise
	// for caches; the origin must be echoed instead.
	if rec.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Error("Allow-Origin must echo the origin, never a literal *")
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials: got %q, want unset (the proxy authenticates from an explicit header, not ambient cookies)", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != corsMaxAge {
		t.Errorf("Max-Age: got %q, want %q", got, corsMaxAge)
	}
	// PATCH/DELETE reach the router through the catch-all (key management), so a
	// browser must be told they are allowed or the preflight blocks them.
	methods := rec.Header().Get("Access-Control-Allow-Methods")
	for _, m := range []string{"POST", "GET", "PATCH", "DELETE", "OPTIONS"} {
		if !strings.Contains(methods, m) {
			t.Errorf("Allow-Methods %q missing %s", methods, m)
		}
	}
	// Both credential spellings and the routing directives must be preflight-able,
	// or the corresponding browser call never leaves the page.
	headers := strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers"))
	for _, name := range []string{"authorization", "x-api-key", "content-type", "http-referer"} {
		if !strings.Contains(headers, name) {
			t.Errorf("Allow-Headers %q missing %s", headers, name)
		}
	}
	// Every routing directive the router consumes must be preflight-able. The
	// Max-Price-Usd caps are header-only upstream (no body equivalent), so leaving
	// one out does not just make a header awkward to send — it puts price ceilings
	// out of reach of browser clients entirely.
	for _, name := range []string{
		"x-0g-source-id",
		"x-0g-provider-address",
		"x-0g-provider-sort",
		"x-0g-provider-trust-mode",
		"x-0g-provider-allow-fallbacks",
		"x-0g-provider-require-parameters",
		"x-0g-provider-max-price-usd-prompt",
		"x-0g-provider-max-price-usd-completion",
		"x-0g-provider-max-price-usd-image",
	} {
		if !strings.Contains(headers, name) {
			t.Errorf("Allow-Headers %q missing routing directive %s", headers, name)
		}
	}
	vary := rec.Header().Values("Vary")
	for _, want := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !containsValue(vary, want) {
			t.Errorf("Vary %v missing %s", vary, want)
		}
	}
}

// The preflight answer must follow the same rule as the forwarding it authorizes:
// routingHeaders forwards on the x-0g- PREFIX, so a directive the router adds later
// — one this test cannot know the name of — must be preflight-able without a code
// change here, while a header outside the namespace stays unadvertised.
func TestCORSPreflightEchoesRoutingNamespace(t *testing.T) {
	h, _ := corsHandler(ParseOrigins(DefaultAllowedOriginsCSV))
	r := preflight("https://chat.0g.ai")
	r.Header.Set("Access-Control-Request-Headers",
		"authorization, X-0G-Provider-Future-Directive, x-not-forwarded, X-0G-Provider-Address")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	allow := rec.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(allow, "X-0G-Provider-Future-Directive") {
		t.Errorf("Allow-Headers %q: an unknown X-0G-* directive must be echoed — the gateway "+
			"forwards the whole namespace, so a browser must be allowed to send it", allow)
	}
	if strings.Contains(strings.ToLower(allow), "x-not-forwarded") {
		t.Errorf("Allow-Headers %q: a header outside the X-0G-* namespace must not be echoed "+
			"(the gateway would not forward it anyway)", allow)
	}
	// A name already in the fixed list must not be repeated.
	if n := strings.Count(strings.ToLower(allow), "x-0g-provider-address"); n != 1 {
		t.Errorf("Allow-Headers %q: x-0g-provider-address appears %d times, want 1", allow, n)
	}
}

// Reflected names are caller-controlled, so anything that is not a valid HTTP token
// is dropped rather than echoed into the response.
func TestCORSPreflightRejectsNonTokenHeaderNames(t *testing.T) {
	h, _ := corsHandler(ParseOrigins(DefaultAllowedOriginsCSV))
	r := preflight("https://chat.0g.ai")
	r.Header.Set("Access-Control-Request-Headers", "x-0g-bad\r\nInjected: yes, x-0g-also bad, x-0g-good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	allow := rec.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(allow, "x-0g-good") {
		t.Errorf("Allow-Headers %q dropped the valid token", allow)
	}
	for _, bad := range []string{"Injected", "also bad"} {
		if strings.Contains(allow, bad) {
			t.Errorf("Allow-Headers %q echoed a non-token name (%q)", allow, bad)
		}
	}
}

func TestCORSPreflightDisallowedOrigin(t *testing.T) {
	h, reached := corsHandler(ParseOrigins(DefaultAllowedOriginsCSV))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, preflight("https://evil.example.com"))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rec.Code)
	}
	if *reached {
		t.Error("disallowed preflight reached the inner handler")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin: got %q, want unset for a disallowed origin", got)
	}
	// The rejection uses the proxy's canonical envelope, so a thin client parses
	// it the same way it parses every other gateway error.
	if body := rec.Body.String(); !strings.Contains(body, `"gateway_error"`) {
		t.Errorf("body: got %q, want the proxy's JSON error envelope", body)
	}
	if !containsValue(rec.Header().Values("Vary"), "Origin") {
		t.Error("Vary: Origin must be set even when the origin is rejected (the response varies by origin)")
	}
}

// An empty allowlist is a valid configuration meaning "no browser access": every
// preflight is refused, and nothing is advertised as allowed.
func TestCORSEmptyAllowlistRefusesPreflight(t *testing.T) {
	h, reached := corsHandler(ParseOrigins("  ,, "))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, preflight("https://chat.0g.ai"))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rec.Code)
	}
	if *reached {
		t.Error("preflight reached the inner handler under an empty allowlist")
	}
}

// A plain OPTIONS (no Access-Control-Request-Method) is not a preflight and must
// keep flowing to the mux — otherwise the middleware would swallow an OPTIONS the
// catch-all is supposed to forward to the router.
func TestCORSPlainOptionsPassesThrough(t *testing.T) {
	h, reached := corsHandler(ParseOrigins(DefaultAllowedOriginsCSV))
	r := httptest.NewRequest(http.MethodOptions, "/v1/models", nil)
	r.Header.Set("Origin", "https://chat.0g.ai")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if !*reached {
		t.Error("plain OPTIONS was swallowed by the CORS middleware")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want the inner handler's 200", rec.Code)
	}
}

func TestCORSActualRequestAllowed(t *testing.T) {
	h, reached := corsHandler(ParseOrigins(DefaultAllowedOriginsCSV))
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	r.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if !*reached {
		t.Fatal("allowed request did not reach the inner handler")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("Allow-Origin: got %q, want the request's origin", got)
	}
	// Expose-Headers is what makes these readable from fetch(); without it a
	// browser sees only the CORS-safelisted response headers.
	expose := rec.Header().Get("Access-Control-Expose-Headers")
	for _, name := range append([]string{headerResKey}, passthroughResponseHeaders...) {
		if !strings.Contains(expose, name) {
			t.Errorf("Expose-Headers %q missing %s", expose, name)
		}
	}
}

// TestCORSExposeHeadersTracksPassthrough is the anti-drift check: Expose-Headers
// must be DERIVED from the passthrough set, so adding a header the proxy re-emits
// automatically makes it readable by browser JS instead of silently invisible.
func TestCORSExposeHeadersTracksPassthrough(t *testing.T) {
	got := strings.Split(corsExposeHeaders, ", ")
	want := append([]string{headerResKey}, passthroughResponseHeaders...)
	if len(got) != len(want) {
		t.Fatalf("Expose-Headers has %d entries, want %d (ZG-Res-Key + every passthrough header)", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Expose-Headers[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// A disallowed origin on a REAL request is served normally, without CORS headers:
// the browser blocks the response on its own, while a non-browser client that
// happens to send an Origin header keeps working. Turning this into a server-side
// 403 would break those callers and buy nothing (any client can forge Origin).
func TestCORSActualRequestDisallowedStillServed(t *testing.T) {
	h, reached := corsHandler(ParseOrigins(DefaultAllowedOriginsCSV))
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if !*reached {
		t.Error("a non-preflight request was blocked server-side; CORS is browser-enforced")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin: got %q, want unset so the browser blocks the response", got)
	}
}

// A request with no Origin at all (every SDK / curl call) must be untouched: no
// CORS headers, no Vary, so nothing about the non-browser path changes.
func TestCORSNoOriginUntouched(t *testing.T) {
	h, reached := corsHandler(ParseOrigins(DefaultAllowedOriginsCSV))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`)))

	if !*reached {
		t.Fatal("origin-less request did not reach the inner handler")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin: got %q, want unset", got)
	}
	if got := rec.Header().Get("Vary"); got != "" {
		t.Errorf("Vary: got %q, want unset for a non-CORS request", got)
	}
}

// Matching must behave exactly like the router's own origin matching: the gateway
// forwards every allowed request to the router, so an origin read differently by
// the two would clear CORS here and then be rejected deeper in the call.
func TestOriginAllowedSemantics(t *testing.T) {
	patterns := ParseOrigins(DefaultAllowedOriginsCSV)
	cases := []struct {
		origin string
		want   bool
		why    string
	}{
		{"https://0g.ai", true, "exact apex"},
		{"HTTPS://0G.AI", true, "origin comparison is case-insensitive"},
		{"https://chat.0g.ai", true, "*. wildcard covers a subdomain"},
		{"https://a.b.0g.ai", true, "*. wildcard covers nested subdomains"},
		{"http://localhost:3000", true, "port is part of the origin"},
		{"http://localhost:3001", false, "a different port is a different origin"},
		{"http://0g.ai", false, "scheme is part of the origin"},
		{"https://evil-0g.ai", false, "suffix must start at a label boundary"},
		{"https://0g.ai.evil.com", false, "the allowed name as a prefix of another domain"},
		{"https://chat.0g.ai:8443", false, "the wildcard pattern carries no port, so a ported origin is not covered"},
		{"null", false, `sandboxed / file: origins send the literal "null"`},
		{"", false, "empty origin"},
	}
	for _, c := range cases {
		if got := originAllowed(c.origin, patterns); got != c.want {
			t.Errorf("originAllowed(%q) = %v, want %v (%s)", c.origin, got, c.want, c.why)
		}
	}

	if !originAllowed("https://anything.example.com", []string{"*"}) {
		t.Error(`"*" must allow any origin`)
	}
	if originAllowed("https://0g.ai", nil) {
		t.Error("an empty allowlist must allow nothing")
	}
}

func TestParseOrigins(t *testing.T) {
	got := ParseOrigins(" https://a.example ,, https://b.example,  ")
	want := []string{"https://a.example", "https://b.example"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if ParseOrigins("") != nil {
		t.Error("an empty value must parse to nil (browser access off), not a one-entry list")
	}
}

func TestValidateOrigins(t *testing.T) {
	if err := ValidateOrigins(ParseOrigins(DefaultAllowedOriginsCSV)); err != nil {
		t.Fatalf("the built-in default must validate: %v", err)
	}
	if err := ValidateOrigins([]string{"*"}); err != nil {
		t.Errorf(`"*" must validate: %v`, err)
	}
	// A single-label parent is legitimate (dev hostnames), so the wildcard check must
	// not tighten into "the parent needs a dot".
	if err := ValidateOrigins([]string{"https://*.localhost"}); err != nil {
		t.Errorf("a single-label wildcard parent must validate: %v", err)
	}

	bad := map[string]string{
		"https://app.example.com/":     "trailing slash — a browser Origin never has one, so it would match nothing",
		"https://app.example.com/path": "path",
		"app.example.com":              "no scheme",
		"ftp://app.example.com":        "non-HTTP scheme",
		"https://":                     "no host",
		"https://*app.example.com":     "wildcard not on a label boundary",
		"https://a.*.example.com":      "wildcard in the middle",
		"https://*.":                   `"*." with no parent domain — compiles to the suffix "." and matches nothing`,
		"https://*.*.example.com":      "two wildcards",
		"https://a b.example.com":      "whitespace inside the host",
	}
	for pattern, why := range bad {
		if err := ValidateOrigins([]string{pattern}); err == nil {
			t.Errorf("ValidateOrigins(%q) = nil, want an error (%s)", pattern, why)
		}
	}
}

func TestStripCORSHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "https://router.example")
	h.Add("Access-Control-Expose-Headers", "X-Whatever")
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Content-Type", "application/json")
	h.Set("X-Request-ID", "abc")

	StripCORSHeaders(h)

	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") {
			t.Errorf("%s survived; the upstream's CORS headers must not reach the browser alongside ours", name)
		}
	}
	if h.Get("Content-Type") != "application/json" || h.Get("X-Request-ID") != "abc" {
		t.Error("non-CORS headers must be left alone")
	}
}

// A NON-CANONICAL map key must be stripped too. This has to be built by assigning
// into the map directly: Header.Set canonicalizes, so it cannot produce the case —
// and neither can Header.Del remove it, since Del canonicalizes its argument and
// would delete a different entry, leaving the upstream Allow-Origin on the
// response. Go's transport canonicalizes what it parses off the wire, so this
// guards the hand-built / custom-RoundTripper path the classify-then-delete logic
// already assumes is possible.
func TestStripCORSHeadersNonCanonicalKey(t *testing.T) {
	h := http.Header{}
	h["access-control-allow-origin"] = []string{"https://router.example"}
	h["ACCESS-CONTROL-ALLOW-CREDENTIALS"] = []string{"true"}
	h["content-type"] = []string{"application/json"}

	StripCORSHeaders(h)

	if len(h) != 1 || h["content-type"][0] != "application/json" {
		t.Errorf("got %v, want only the non-CORS header left (a surviving Access-Control-* "+
			"would reach the browser next to the gateway's own → \"contains multiple values\")", h)
	}
}

// containsValue reports whether a header's values contain want, treating a
// comma-joined value ("Origin, Accept") the same as repeated headers, since both
// spellings are equivalent on the wire.
func containsValue(values []string, want string) bool {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), want) {
				return true
			}
		}
	}
	return false
}
