package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
)

// The cap's own mechanics are tested in openaiproxy (limit_test.go). What is
// tested HERE is the wiring — which routes it covers and where it sits relative
// to the credential gate. Those placements are decisions, not details: get the
// order wrong and a credential-less flood eats the slots; put it on /healthz and
// an overloaded CVM fails its own probe and gets killed. None of that is visible
// from openaiproxy, and every other test in this package runs with the cap off.

// blockedGateway stands up a gateway whose upstream router parks on the
// route-preview call, so a request sent to it occupies its slot and stays there.
// It returns the gateway server and a func that reports when the parked request
// has actually reached the router (so a test never races a request still in
// transit against the assertion that the cap is full).
//
// Preview is the first upstream call the core makes on the sealed path, which is
// why blocking it is enough — no sealing or provider key material is involved.
func blockedGateway(t *testing.T, maxInFlight int, identity *identityCache) (gw *httptest.Server, entered <-chan struct{}) {
	t.Helper()
	return blockedGatewayWith(t, maxInFlight, identity, nil)
}

// blockedGatewayWith is blockedGateway with the provider-identity route mounted
// too, for the test that the panel's provider hop is also served while the cap is
// full.
func blockedGatewayWith(t *testing.T, maxInFlight int, identity *identityCache, providerIdentities route.ProviderIdentitySource) (gw *httptest.Server, entered <-chan struct{}) {
	t.Helper()
	release := make(chan struct{})
	reached := make(chan struct{}, 8)

	routerMux := http.NewServeMux()
	routerMux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
		<-release
	})
	router := httptest.NewServer(routerMux)

	client := core.NewWithResolver(route.New(router.URL))
	gw = httptest.NewServer(newHandler(client, nil, mustURL(t, router.URL), testOrigins(), "", "",
		maxInFlight, identity, providerIdentities, nil, discardLogger()))

	// Cleanup runs LIFO, and Close blocks on in-flight requests — so the parked
	// handler must be released before either server is closed, which means
	// registering that cleanup last.
	t.Cleanup(router.Close)
	t.Cleanup(gw.Close)
	t.Cleanup(func() { close(release) })
	return gw, reached
}

// post sends a chat completion with the given Authorization value ("" = none)
// and returns the status.
func post(t *testing.T, gw *httptest.Server, auth string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	// A short timeout, because every status this helper asserts on is produced
	// WITHOUT touching the parked upstream — the gate refuses on shape, the cap
	// refuses on capacity. So a request that hangs means the wiring is wrong, and
	// the timeout turns that into a fast, legible failure instead of a minutes-long
	// stall in whatever regression removed the middleware.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v (a hang here means the request reached the upstream, "+
			"i.e. it was neither gated nor shed)", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestGatewayCap_CredentialGateRunsFirst is the ordering claim the placement
// rests on: the cap sits INSIDE the credential gate, so traffic that is refused
// on shape alone never consumes a slot. With the only slot held, a
// credential-less request must still be answered 401 by the gate — a 503 here
// would mean junk traffic can exhaust the capacity reserved for real requests.
func TestGatewayCap_CredentialGateRunsFirst(t *testing.T) {
	gw, entered := blockedGateway(t, 1, nil)

	go func() { _ = postAsync(gw, "Bearer sk-holder") }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the holding request never reached the router; the cap is not occupied")
	}

	if got := post(t, gw, ""); got != http.StatusUnauthorized {
		t.Errorf("credential-less request at capacity = %d, want %d — the gate must run before the cap, "+
			"or unauthenticated traffic can eat the slots", got, http.StatusUnauthorized)
	}
	if got := post(t, gw, "Bearer mk-management"); got != http.StatusForbidden {
		t.Errorf("mgmt-key request at capacity = %d, want %d — same ordering claim", got, http.StatusForbidden)
	}
}

// TestGatewayCap_SealedRouteIsCapped confirms the cap is actually mounted on the
// sealed route: with the one slot held, a properly credentialed request is shed.
// Without this, deleting the LimitInFlight wrapper from newHandler would leave
// the suite green.
func TestGatewayCap_SealedRouteIsCapped(t *testing.T) {
	gw, entered := blockedGateway(t, 1, nil)

	go func() { _ = postAsync(gw, "Bearer sk-holder") }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the holding request never reached the router; the cap is not occupied")
	}

	if got := post(t, gw, "Bearer sk-second"); got != http.StatusServiceUnavailable {
		t.Errorf("second sealed request at capacity = %d, want %d — the cap is not mounted on this route",
			got, http.StatusServiceUnavailable)
	}
}

// TestGatewayCap_HealthzIsNotCapped pins the exemption that keeps an overloaded
// CVM alive. /healthz is the container's own probe (deploy/phala/), so a 503
// there would fail the healthcheck and have the platform restart the very
// gateway that was merely busy — turning a load spike into an outage.
func TestGatewayCap_HealthzIsNotCapped(t *testing.T) {
	gw, entered := blockedGateway(t, 1, nil)

	go func() { _ = postAsync(gw, "Bearer sk-holder") }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the holding request never reached the router; the cap is not occupied")
	}

	resp, err := http.Get(gw.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz at capacity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz at capacity = %d, want 200 — a capped probe would get the CVM killed under load",
			resp.StatusCode)
	}
}

// postAsync fires the slot-holding request. Its response never arrives (the
// upstream is parked until cleanup), so the error is expected and discarded;
// it exists only to occupy the cap.
func postAsync(gw *httptest.Server, auth string) error {
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
