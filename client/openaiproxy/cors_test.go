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
	for _, name := range []string{"authorization", "x-api-key", "content-type", "x-0g-provider-address", "http-referer"} {
		if !strings.Contains(headers, name) {
			t.Errorf("Allow-Headers %q missing %s", headers, name)
		}
	}
	vary := rec.Header().Values("Vary")
	for _, want := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !containsValue(vary, want) {
			t.Errorf("Vary %v missing %s", vary, want)
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

	bad := map[string]string{
		"https://app.example.com/":     "trailing slash — a browser Origin never has one, so it would match nothing",
		"https://app.example.com/path": "path",
		"app.example.com":              "no scheme",
		"ftp://app.example.com":        "non-HTTP scheme",
		"https://":                     "no host",
		"https://*app.example.com":     "wildcard not on a label boundary",
		"https://a.*.example.com":      "wildcard in the middle",
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
		if strings.HasPrefix(name, "Access-Control-") {
			t.Errorf("%s survived; the upstream's CORS headers must not reach the browser alongside ours", name)
		}
	}
	if h.Get("Content-Type") != "application/json" || h.Get("X-Request-ID") != "abc" {
		t.Error("non-CORS headers must be left alone")
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
