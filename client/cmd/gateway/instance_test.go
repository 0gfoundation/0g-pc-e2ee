package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// With an instance id wired in (-instance-header on, and the dstack lookup having
// succeeded), every response carries it — including the ones that never reach the
// sealed route, since those are exactly the responses an operator is trying to
// attribute to a replica when one CVM misbehaves.
func TestInstanceHeaderStampedOnEveryResponse(t *testing.T) {
	const id = "aa11bb22cc33dd44"
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), testOrigins(), id, discardLogger()))
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

// The default: no id (either -instance-header is off or the dstack lookup
// failed), so nothing is stamped and the fleet shape stays unadvertised.
func TestInstanceHeaderAbsentByDefault(t *testing.T) {
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), testOrigins(), "", discardLogger()))
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
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), testOrigins(), "", discardLogger()))
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
