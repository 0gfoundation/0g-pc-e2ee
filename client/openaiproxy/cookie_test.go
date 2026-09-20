package openaiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// cookieOrigins is the allowlist the cookie cases run against: one exact origin
// and one wildcard, so a case can pick a match of either kind and a non-match
// that is not merely a typo.
func cookieOrigins() []string {
	return []string{"https://pc.0g.ai", "https://*.example.com"}
}

// cookieHandler wraps a sentinel in AcceptCookieCredential and reports what the
// inner handler saw, so a case can assert BOTH halves of the conversion: that the
// request got through, and what credential it carried when it did.
func cookieHandler(origins []string) (h http.Handler, gotAuth *string, reached *bool) {
	var (
		auth string
		ran  bool
	)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	return AcceptCookieCredential(origins, inner), &auth, &ran
}

func cookieRequest(origin, cookie string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: cookieCredentialName, Value: cookie})
	}
	return r
}

// The case the middleware exists for: a browser on an allowlisted origin sends
// the router's HttpOnly cookie and no Authorization header, and the sealed path
// downstream sees an ordinary bearer credential.
//
// Both origin forms are covered, because the matcher is shared with the preflight
// answer and a page that clears CORS must not then be rejected here.
func TestCookieCredentialConvertedForAllowedOrigin(t *testing.T) {
	for _, origin := range []string{"https://pc.0g.ai", "https://app.example.com"} {
		t.Run(origin, func(t *testing.T) {
			h, auth, reached := cookieHandler(cookieOrigins())
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, cookieRequest(origin, "jwt-value"))

			if !*reached {
				t.Fatalf("status %d: the request never reached the sealed path", rec.Code)
			}
			if *auth != "Bearer jwt-value" {
				t.Errorf("Authorization: got %q, want the cookie wrapped as a bearer", *auth)
			}
		})
	}
}

// A cookie from an origin that is NOT on the allowlist is refused, not honored.
//
// This is the CSRF case, and it is the whole reason the middleware takes an
// allowlist: a cookie is ambient, so without this check any page could spend a
// logged-in visitor's balance by firing a request it never reads the answer to.
// The browser sets Origin on a cross-origin request and a page cannot forge it,
// so the origin is what turns the attacker away.
func TestCookieCredentialRefusedForDisallowedOrigin(t *testing.T) {
	h, _, reached := cookieHandler(cookieOrigins())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, cookieRequest("https://evil.example.net", "jwt-value"))

	if *reached {
		t.Fatal("a cookie from a disallowed origin reached the sealed path")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rec.Code)
	}
	// The same error envelope every other gateway-origin error uses, attributed to
	// the gateway — a client should not have to special-case this one.
	var env struct {
		Error struct{ Message string } `json:"error"`
		ZG    struct{ Source string }  `json:"_0g"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("refusal is not the standard error envelope: %v (%s)", err, rec.Body)
	}
	if env.ZG.Source != "gateway" {
		t.Errorf("_0g.source: got %q, want %q", env.ZG.Source, "gateway")
	}
	if env.Error.Message == "" {
		t.Error("refusal carries no message")
	}
}

// A cookie with NO Origin header is refused too, and this is the half that is
// easy to get wrong: "no Origin" is not "no cross-origin risk". A same-origin
// form post carries no Origin either, so treating absence as trustworthy would
// reopen exactly the CSRF the allowlist closes. The router's own cookie path
// rejects it for the same reason.
func TestCookieCredentialRefusedWithoutOrigin(t *testing.T) {
	h, _, reached := cookieHandler(cookieOrigins())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, cookieRequest("", "jwt-value"))

	if *reached {
		t.Fatal("a cookie with no Origin reached the sealed path")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rec.Code)
	}
}

// An explicit credential wins, and the cookie is not consulted — the router's own
// precedence. Getting this backwards would authenticate a page holding both as
// one principal here and another upstream.
//
// The x-api-key row is the one that pins the subtle half: the middleware must
// leave it ALONE rather than "helpfully" also synthesizing an Authorization
// header, because credential() already knows how to wrap x-api-key and a second
// opinion here could disagree with it.
func TestCookieCredentialYieldsToExplicitCredential(t *testing.T) {
	tests := []struct {
		name, header, value, wantAuth string
	}{
		{"authorization wins", "Authorization", "Bearer sk-explicit", "Bearer sk-explicit"},
		{"x-api-key is left untouched", "x-api-key", "sk-explicit", ""},
		// A non-bearer Authorization is still the caller's credential, and the cookie
		// must not overwrite it. The gate rejects this request a moment later, which is
		// the right answer — but "rejected" and "silently re-authenticated as somebody
		// else" are very different wrong answers, and only one of them bills a stranger.
		{"a non-bearer scheme is still explicit", "Authorization", "Basic dXNlcjpwdw==", "Basic dXNlcjpwdw=="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, auth, reached := cookieHandler(cookieOrigins())
			req := cookieRequest("https://pc.0g.ai", "jwt-value")
			req.Header.Set(tt.header, tt.value)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if !*reached {
				t.Fatalf("status %d: the request never reached the sealed path", rec.Code)
			}
			if *auth != tt.wantAuth {
				t.Errorf("Authorization: got %q, want %q", *auth, tt.wantAuth)
			}
		})
	}
}

// With no cookie — and with an empty one, which is a cookie that authenticates
// nobody — the request passes through EXACTLY as it arrived, so the credential
// gate below gives its own "missing API key" answer. The middleware has no
// opinion about a request carrying no credential at all, and a 403 here would
// mislabel the 401 case.
//
// The no-Origin row matters: it must not trip the CSRF refusal, because there is
// no cookie to refuse.
func TestCookieCredentialAbsentPassesThrough(t *testing.T) {
	tests := []struct{ name, origin, cookie string }{
		{"no cookie, allowed origin", "https://pc.0g.ai", ""},
		{"no cookie, no origin", "", ""},
		{"no cookie, disallowed origin", "https://evil.example.net", ""},
		{"empty cookie", "https://pc.0g.ai", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, auth, reached := cookieHandler(cookieOrigins())
			req := cookieRequest(tt.origin, tt.cookie)
			if tt.name == "empty cookie" {
				// AddCookie skips an empty value, so set the header directly: the point
				// is a present-but-worthless cookie, which is the shape a logged-out
				// browser can genuinely send.
				req.Header.Set("Cookie", cookieCredentialName+"=")
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if !*reached {
				t.Fatalf("status %d: a credential-less request must reach the gate, not be refused here", rec.Code)
			}
			if *auth != "" {
				t.Errorf("Authorization: got %q, want it left empty", *auth)
			}
		})
	}
}

// The middleware must not mutate the request its caller still holds: the access
// log wraps it from outside, and a handler that rewrites its caller's header
// block is action at a distance that is fine right up until something reads it.
func TestCookieCredentialDoesNotMutateCallersRequest(t *testing.T) {
	h, _, _ := cookieHandler(cookieOrigins())
	req := cookieRequest("https://pc.0g.ai", "jwt-value")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("the caller's request was mutated: Authorization = %q", got)
	}
}

// Composed with the gate it exists to get past — the wiring the gateway uses.
//
// The mgmt-key row is the one worth having: a cookie is converted before the gate
// runs, so a cookie carrying an `mk-` value must still be rejected as a mgmt key.
// Converting a credential must not launder what it is.
func TestCookieCredentialThroughTheGate(t *testing.T) {
	tests := []struct {
		name, cookie string
		wantStatus   int
	}{
		{"jwt passes the gate", "eyJhbGciOiJ", http.StatusOK},
		{"mgmt key in a cookie is still a mgmt key", "mk-management-key", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reached bool
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			h := AcceptCookieCredential(cookieOrigins(), RequireInferenceCredential(inner))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, cookieRequest("https://pc.0g.ai", tt.cookie))

			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if reached != (tt.wantStatus == http.StatusOK) {
				t.Errorf("reached inner = %v, want %v", reached, tt.wantStatus == http.StatusOK)
			}
		})
	}
}

// The divergence that made bearerToken the wrong test: an explicit x-api-key
// alongside a non-bearer Authorization.
//
// bearerToken returns "" for a present-but-non-bearer Authorization and stops
// there, never reaching its x-api-key branch — so gating on it let the cookie
// overwrite an API key the caller supplied. The router's own extractBearerToken
// falls THROUGH that Authorization to x-api-key and would have honored the key, so
// the two sides would have billed two different accounts for one request.
func TestCookieCredentialDoesNotOverrideAPIKeyBehindANonBearerHeader(t *testing.T) {
	h, auth, reached := cookieHandler(cookieOrigins())
	req := cookieRequest("https://pc.0g.ai", "jwt-value")
	req.Header.Set("Authorization", "Basic dXNlcjpwdw==")
	req.Header.Set("x-api-key", "sk-caller-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !*reached {
		t.Fatalf("status %d: the request never reached the sealed path", rec.Code)
	}
	if *auth == "Bearer jwt-value" {
		t.Fatal("the cookie replaced the caller's own credential: this request would be " +
			"billed to the cookie's account while the router would have billed the API key's")
	}
	if *auth != "Basic dXNlcjpwdw==" {
		t.Errorf("Authorization: got %q, want the caller's header untouched", *auth)
	}
}
