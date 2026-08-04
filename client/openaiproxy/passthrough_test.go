package openaiproxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
)

// TestRoutingHeaders_ForwardsRouterConsumedOnly checks the request-forward
// allowlist: the X-0G-* routing namespace and the two app-attribution headers
// (HTTP-Referer, X-Title) pass through, while arbitrary client headers do not.
func TestRoutingHeaders_ForwardsRouterConsumedOnly(t *testing.T) {
	// Build via Set so keys are canonicalized exactly as an inbound *http.Request
	// carries them (e.g. "X-0G-…" → "X-0g-…", "HTTP-Referer" → "Http-Referer").
	in := http.Header{}
	for k, v := range map[string]string{
		"X-0G-Provider-Address": "0xabc",
		"X-0G-Source-Id":        "partner-slug",
		"HTTP-Referer":          "https://app.example",
		"X-Title":               "My App",
		"Authorization":         "Bearer sk-secret",
		"Cookie":                "session=abc",
		"X-App-Internal":        "leak-me",
	} {
		in.Set(k, v)
	}
	out := routingHeaders(in)

	forwarded := []string{"X-0G-Provider-Address", "X-0G-Source-Id", "HTTP-Referer", "X-Title"}
	for _, k := range forwarded {
		if out.Get(k) == "" {
			t.Errorf("expected %q to be forwarded, but it was dropped", k)
		}
	}
	dropped := []string{"Authorization", "Cookie", "X-App-Internal"}
	for _, k := range dropped {
		if out.Get(k) != "" {
			t.Errorf("expected %q to be dropped, but it was forwarded as %q", k, out.Get(k))
		}
	}
}

func TestCredential(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"authorization verbatim", map[string]string{"Authorization": "Bearer sk-abc"}, "Bearer sk-abc"},
		{"x-api-key wrapped as bearer", map[string]string{"x-api-key": "sk-abc"}, "Bearer sk-abc"},
		{"authorization wins over x-api-key", map[string]string{"Authorization": "Bearer sk-auth", "x-api-key": "sk-key"}, "Bearer sk-auth"},
		{"neither present", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := credential(r); got != tc.want {
				t.Errorf("credential() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSetPassthrough checks that only the curated upstream response headers are
// re-emitted, absent ones are skipped, non-allowlisted ones stay inside the
// gateway, and multi-valued headers survive.
func TestSetPassthrough(t *testing.T) {
	src := http.Header{
		"X-Provider":                {"0xprovider"},
		"Zg-Failure-Source":         {"upstream"},
		"Retry-After":               {"30"},
		"X-Ratelimit-Remaining-Day": {"5", "5"},
		"Content-Type":              {"application/json"}, // not allowlisted
		"X-Router-Internal":         {"do-not-surface"},   // not allowlisted
	}
	rec := httptest.NewRecorder()
	setPassthrough(rec, src)
	got := rec.Header()

	if got.Get("X-Provider") != "0xprovider" {
		t.Errorf("X-Provider not surfaced: %q", got.Get("X-Provider"))
	}
	if got.Get("Zg-Failure-Source") != "upstream" {
		t.Errorf("ZG-Failure-Source not surfaced: %q", got.Get("Zg-Failure-Source"))
	}
	if got.Get("Retry-After") != "30" {
		t.Errorf("Retry-After not surfaced: %q", got.Get("Retry-After"))
	}
	if vals := got.Values("X-Ratelimit-Remaining-Day"); len(vals) != 2 {
		t.Errorf("multi-valued rate-limit header not preserved: %v", vals)
	}
	for _, k := range []string{"Content-Type", "X-Router-Internal"} {
		if got.Get(k) != "" {
			t.Errorf("non-allowlisted header %q leaked as %q", k, got.Get(k))
		}
	}
}

// TestSetPassthrough_NilSafe guards the no-response case: a nil source header
// must be a no-op, not a panic.
func TestSetPassthrough_NilSafe(t *testing.T) {
	setPassthrough(httptest.NewRecorder(), nil)
	setPassthrough(httptest.NewRecorder(), http.Header{})
}

// TestUpstreamHeader checks the error-path source: a core.Error carries its
// upstream header block, while a transport failure or non-core error yields nil
// (nothing to surface).
func TestUpstreamHeader(t *testing.T) {
	h := http.Header{"Retry-After": {"30"}}
	if got := upstreamHeader(&core.Error{Header: h}); got.Get("Retry-After") != "30" {
		t.Errorf("upstreamHeader(core.Error) did not return the carried header: %v", got)
	}
	if got := upstreamHeader(&core.Error{}); got != nil {
		t.Errorf("upstreamHeader with no header should be nil, got %v", got)
	}
	if got := upstreamHeader(errors.New("plain")); got != nil {
		t.Errorf("upstreamHeader(non-core err) should be nil, got %v", got)
	}
}
