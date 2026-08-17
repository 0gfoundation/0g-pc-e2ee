package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// Once the gateway knows its identity, every response carries it — including the
// ones that never reach the sealed route, since those are exactly the responses
// someone is trying to attribute to a replica when one CVM misbehaves. There is
// no toggle: a header that had to be switched on would be off during the incident
// that wanted it.
func TestInstanceHeaderStampedOnEveryResponse(t *testing.T) {
	const id = "aa11bb22cc33dd44"
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), testOrigins(), id, "", noInFlightCap, nil, discardLogger()))
	defer gw.Close()

	t.Run("healthz", func(t *testing.T) {
		resp, err := http.Get(gw.URL + "/healthz")
		if err != nil {
			t.Fatalf("get /healthz: %v", err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get(openaiproxy.HeaderGatewayInstance); got != id {
			t.Errorf("%s = %q, want %q", openaiproxy.HeaderGatewayInstance, got, id)
		}
	})

	// An error response is the case that matters most: "which replica 401'd me".
	t.Run("credential gate rejection", func(t *testing.T) {
		resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("expected the credential gate to reject, got %d", resp.StatusCode)
		}
		if got := resp.Header.Get(openaiproxy.HeaderGatewayInstance); got != id {
			t.Errorf("%s = %q, want %q", openaiproxy.HeaderGatewayInstance, got, id)
		}
	})

	// StampInstance sits outside CORS, so a preflight — which CORS answers without
	// ever reaching the mux — is stamped too.
	t.Run("cors preflight", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodOptions, gw.URL+"/v1/chat/completions", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Origin", "https://0g.ai")
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get(openaiproxy.HeaderGatewayInstance); got != id {
			t.Errorf("%s = %q, want %q", openaiproxy.HeaderGatewayInstance, got, id)
		}
	})
}

// The one case that stamps nothing: the process never learned its own id (a local
// run, or a deployment that wired neither identity source). It must serve
// normally, without a header naming an empty replica.
func TestInstanceHeaderAbsentWithoutIdentity(t *testing.T) {
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), testOrigins(), "", "", noInFlightCap, nil, discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/healthz")
	if err != nil {
		t.Fatalf("get /healthz: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get(openaiproxy.HeaderGatewayInstance); got != "" {
		t.Errorf("%s = %q, want absent", openaiproxy.HeaderGatewayInstance, got)
	}
}

// A browser can only read a response header the CORS layer advertises, so the
// header being on the wire is not enough — it must appear in
// Access-Control-Expose-Headers. It is advertised unconditionally (see
// corsExposeHeaders), so this holds even on a gateway that stamps nothing.
func TestInstanceHeaderExposedToBrowsers(t *testing.T) {
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), testOrigins(), "", "", noInFlightCap, nil, discardLogger()))
	defer gw.Close()

	req, err := http.NewRequest(http.MethodGet, gw.URL+"/healthz", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Origin", "https://0g.ai")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	exposed := resp.Header.Get("Access-Control-Expose-Headers")
	if !strings.Contains(strings.ToLower(exposed), strings.ToLower(openaiproxy.HeaderGatewayInstance)) {
		t.Errorf("Access-Control-Expose-Headers = %q, missing %s", exposed, openaiproxy.HeaderGatewayInstance)
	}
}
