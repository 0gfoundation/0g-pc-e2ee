package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readyzBody returns the status and body of GET /readyz against a handler built
// with the given readiness func.
func readyzBody(t *testing.T, ready func() error) (int, string) {
	t.Helper()
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"),
		testOrigins(), "", noInFlightCap, ready, discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// With nothing to assert (no warmer configured) the route must answer ready rather
// than fail closed: a sidecar or a local run has no sweep data and is not broken.
func TestReadyz_NilReadinessIsReady(t *testing.T) {
	status, body := readyzBody(t, nil)
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !strings.Contains(body, "ready") {
		t.Errorf("body = %q, want it to say ready", body)
	}
}

func TestReadyz_ReadyWhenCheckPasses(t *testing.T) {
	status, _ := readyzBody(t, func() error { return nil })
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
}

// The failure must be a 503 and must carry the reason: switch.sh prints the probe
// body, and "0 of 7 prepared" versus "no sweep yet" are different operator actions.
func TestReadyz_NotReadyIs503WithReason(t *testing.T) {
	status, body := readyzBody(t, func() error { return errors.New("no provider is usable: 0 of 7 prepared") })
	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", status)
	}
	if !strings.Contains(body, "0 of 7 prepared") {
		t.Errorf("body = %q, want the reason surfaced", body)
	}
}

// /readyz must be mounted explicitly. Unmounted it would fall through to the
// catch-all router passthrough and answer with the ROUTER's status — a probe that
// silently reports on the wrong process, which is worse than no probe.
func TestReadyz_NotServedByRouterPassthrough(t *testing.T) {
	var routerHits int
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routerHits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("router says ok\n"))
	}))
	defer router.Close()

	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, router.URL),
		testOrigins(), "", noInFlightCap,
		func() error { return errors.New("not ready") }, discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 from OUR handler", resp.StatusCode)
	}
	if routerHits != 0 {
		t.Errorf("router received %d requests: /readyz must not be proxied upstream", routerHits)
	}
}

// Widening /healthz to cover readiness would break the container healthcheck that
// compose gates dstack-ingress startup on, so it must stay independent.
func TestHealthz_UnaffectedByReadiness(t *testing.T) {
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"),
		testOrigins(), "", noInFlightCap,
		func() error { return errors.New("not ready") }, discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200 even while not ready", resp.StatusCode)
	}
}
