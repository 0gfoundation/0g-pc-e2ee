package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// The browser allowlist these tests drive newHandler with, kept independent of the
// shipped default so a change to that list cannot quietly change what is asserted.
var corsTestOrigins = openaiproxy.ParseOrigins("https://app.example.com,https://*.wild.example.com")

// TestGatewayPreflightAnsweredLocally pins the middleware ORDER, which is the
// whole reason CORS wraps the mux rather than a route. A preflight carries no
// credential and no body, so:
//   - if it reached the sealed route's credential gate it would 401, and the
//     browser would report a CORS failure with no way to see why;
//   - if it fell through the catch-all it would be answered by the ROUTER's
//     allowlist instead of this gateway's.
//
// The router URL here is a spy: any request that reaches it is a failure.
func TestGatewayPreflightAnsweredLocally(t *testing.T) {
	var routerHits int
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routerHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer router.Close()

	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), corsTestOrigins, "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	// One preflight per path class: the sealed route (behind the credential gate)
	// and a catch-all path (proxied to the router on the real request).
	for _, path := range []string{"/v1/chat/completions", "/v1/models"} {
		req, err := http.NewRequest(http.MethodOptions, gw.URL+path, nil)
		if err != nil {
			t.Fatalf("build preflight: %v", err)
		}
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("preflight %s: %v", path, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("preflight %s: got %d, want 204 (401 = the credential gate ran first)", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
			t.Errorf("preflight %s: Allow-Origin = %q, want the origin echoed", path, got)
		}
	}
	if routerHits != 0 {
		t.Errorf("router saw %d preflight(s); the gateway must answer them from its own allowlist", routerHits)
	}
}

// TestGatewayCatchAllStripsUpstreamCORS covers the duplicate-header trap: the
// router runs its own CORS middleware, and the catch-all copies upstream headers
// verbatim, so without the strip in newRouterProxy a browser would receive two
// Access-Control-Allow-Origin values — which browsers reject outright — or the
// router's verdict where the two allowlists disagree.
func TestGatewayCatchAllStripsUpstreamCORS(t *testing.T) {
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// What the router's own gin-cors middleware would emit.
		w.Header().Set("Access-Control-Allow-Origin", "https://router-allowlist.example")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "X-Router-Only")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list"}`))
	}))
	defer router.Close()

	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), corsTestOrigins, "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	req, err := http.NewRequest(http.MethodGet, gw.URL+"/v1/models", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Origin", "https://sub.wild.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get /v1/models: %v", err)
	}
	defer resp.Body.Close()

	got := resp.Header.Values("Access-Control-Allow-Origin")
	if len(got) != 1 {
		t.Fatalf("Allow-Origin values = %v, want exactly one (a browser rejects multiple)", got)
	}
	if got[0] != "https://sub.wild.example.com" {
		t.Errorf("Allow-Origin = %q, want the gateway's own verdict, not the router's", got[0])
	}
	// Credentials stay off on this path too: the router's value must not leak
	// through and turn on ambient-cookie CORS the gateway never opted into.
	if v := resp.Header.Get("Access-Control-Allow-Credentials"); v != "" {
		t.Errorf("Allow-Credentials = %q, want unset (the upstream's must be stripped)", v)
	}
	if v := resp.Header.Get("Access-Control-Expose-Headers"); v == "X-Router-Only" {
		t.Error("the router's Expose-Headers survived; the gateway's own list must govern")
	}
}

// composePath is the deployed compose manifest, relative to this package. It sits
// outside the client module, which is fine for a test that only reads it.
const composePath = "../../../deploy/phala/docker-compose.yml"

// composeAllowedOrigins matches the fallback of the compose's
// ZG_GATEWAY_ALLOWED_ORIGINS entry — the value that applies when the encrypted
// environment supplies no override.
var composeAllowedOrigins = regexp.MustCompile(
	`ZG_GATEWAY_ALLOWED_ORIGINS=\$\{ZG_GATEWAY_ALLOWED_ORIGINS:-([^}]*)\}`)

// TestComposeAllowedOriginsMatchesDefault enforces the "keep in sync" note in
// deploy/phala/docker-compose.yml. The compose spells the allowlist out instead of
// inheriting it, because that block is measured into compose_hash and app_id should
// commit to which web origins may drive sealed inference through the enclave. That
// is only sound while the two agree: a change to DefaultAllowedOriginsCSV alone
// would leave the deployed enclave on the old list with nothing to say so, and the
// note asking a human to remember is not a mechanism.
//
// Deliberately compared against the shipped constant, not corsTestOrigins — this is
// the one test whose subject IS the default list.
func TestComposeAllowedOriginsMatchesDefault(t *testing.T) {
	compose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	m := composeAllowedOrigins.FindSubmatch(compose)
	if m == nil {
		t.Fatalf("no ZG_GATEWAY_ALLOWED_ORIGINS=${...:-<default>} entry in %s; if the entry was "+
			"reshaped deliberately, update this test rather than dropping it", composePath)
	}
	if got := string(m[1]); got != openaiproxy.DefaultAllowedOriginsCSV {
		t.Errorf("compose allowlist and the built-in default disagree:\n compose: %q\n default: %q\n"+
			"update whichever is stale — the deployed enclave serves the compose value", got,
			openaiproxy.DefaultAllowedOriginsCSV)
	}
}
