package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// routeClient builds the gateway's client the way main does: route-only, no
// pinned provider. The preview URL is unused by the operational-route tests.
func routeClient() *core.Client {
	return core.NewWithResolver(route.New("http://router.unused"))
}

// noInFlightCap is the max-inflight value newHandler gets in tests that are not
// about overload: 0 disables the concurrency cap, so these keep exercising the
// routing/CORS/streaming paths exactly as they did before the cap existed. The
// cap's own behavior is tested in openaiproxy (limit_test.go).
const noInFlightCap = 0

// discardLogger is a logger the operational-route tests hand to newHandler when
// they don't assert on the access log; TestGatewayAccessLog uses its own buffer.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// testOrigins is the browser allowlist newHandler gets in tests that don't
// exercise CORS: the binary's own built-in default, so the middleware runs in the
// configuration production runs in rather than an empty one. The CORS tests
// (cors_test.go) pass their own list.
func testOrigins() []string {
	return openaiproxy.ParseOrigins(openaiproxy.DefaultAllowedOriginsCSV)
}

// mustURL parses a router base URL for newHandler's catch-all, failing the test
// on a malformed one. The operational-route tests point it at an unused host;
// only the tests that exercise the catch-all point it at a live router.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse router url %q: %v", raw, err)
	}
	return u
}

func TestGatewayHealthz(t *testing.T) {
	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, "http://router.unused"), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/healthz")
	if err != nil {
		t.Fatalf("get /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz: got %d, want 200", resp.StatusCode)
	}
}

// TestGatewayAuthGateWiring confirms the front-door credential gate
// (openaiproxy.RequireInferenceCredential) is mounted on the sealed inference route and
// only there: a credential-less or mgmt-key request to /v1/chat/completions is
// rejected at the gate (before any seal/route work — the router URL here is
// unreachable, so reaching the core would surface as a 502, not the 401/403 the
// gate returns), while /healthz stays open for the container probe.
func TestGatewayAuthGateWiring(t *testing.T) {
	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, "http://router.unused"), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	post := func(t *testing.T, auth string) int {
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
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := post(t, ""); got != http.StatusUnauthorized {
		t.Errorf("no credential: got %d, want 401", got)
	}
	if got := post(t, "Bearer mk-abc"); got != http.StatusForbidden {
		t.Errorf("mgmt key: got %d, want 403", got)
	}

	// The gate must not touch the health route.
	resp, err := http.Get(gw.URL + "/healthz")
	if err != nil {
		t.Fatalf("get /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz behind gate: got %d, want 200", resp.StatusCode)
	}
}

// The -health probe (used as the container healthcheck, since the distroless
// image has no shell or curl) must return nil against a live /healthz and an
// error against an unreachable one, and it must derive the port from the same
// -listen value the server binds.
func TestGatewayHealthProbe(t *testing.T) {
	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, "http://router.unused"), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	// Healthy: probe the live server's /healthz directly.
	if err := probeHealth(gw.URL+"/healthz", 3*time.Second); err != nil {
		t.Fatalf("probeHealth against a live gateway: %v", err)
	}

	// Unreachable: a server we immediately close refuses the connection, so the
	// probe must fail (this is what a down gateway looks like to the healthcheck).
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	if err := probeHealth(deadURL+"/healthz", 3*time.Second); err == nil {
		t.Fatal("probeHealth against a closed gateway: got nil, want an error")
	}

	// Port derivation: the probe URL must target loopback on the -listen port,
	// whatever interface the server binds.
	url, err := healthURLFromListen("0.0.0.0:8443")
	if err != nil {
		t.Fatalf("healthURLFromListen: %v", err)
	}
	if url != "http://127.0.0.1:8443/healthz" {
		t.Fatalf("healthURLFromListen: got %q, want loopback on port 8443", url)
	}
	// A -listen with no port is a configuration error, not a silent no-probe.
	if _, err := healthURLFromListen("8443"); err == nil {
		t.Fatal("healthURLFromListen(\"8443\"): got nil, want an error")
	}
}

// In route mode the gateway holds no pinned provider: it previews against a
// router, fetches the chosen provider's key, seals, and streams plaintext back.
// This confirms the route resolver is wired into the same shared proxy the
// pin-only path uses; exhaustive route behavior lives in the route package.
func TestGatewayRouteMode(t *testing.T) {
	encPriv, encPub, _ := crypto.GenerateRecipientKey()
	signer := "0x" + strings.Repeat("a", 40)       // broker signer_address (envelope pin)
	providerAddr := "0x" + strings.Repeat("c", 40) // router provider address (routing pin)

	// The broker serves only the provider's e2ee pubkey (control plane).
	brokerMux := http.NewServeMux()
	brokerMux.HandleFunc("GET /v1/e2ee/pubkey", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"v":              wire.Version,
			"kem_id":         wire.KEMID,
			"enc_pub":        base64.RawURLEncoding.EncodeToString(encPub),
			"key_id":         "k",
			"signer_address": signer,
		})
	})
	broker := httptest.NewServer(brokerMux)
	defer broker.Close()

	// The router serves route-preview (pointing at the broker) and the chat data
	// plane — the sealed request goes here, and the router forwards to the pinned
	// provider (which the mock stands in for by opening the seal).
	routerMux := http.NewServeMux()
	routerMux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":       "routing.preview",
			"service_type": "chatbot",
			"providers": []map[string]string{{
				"address":      providerAddr,
				"canonical_id": "gpt-4o",
				"endpoint":     broker.URL,
				"model_id":     "gpt-4o",
			}},
		})
	})
	routerMux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		// The routing pin is the provider address, not the signer.
		if r.Header.Get("X-0G-Provider-Address") != providerAddr {
			t.Errorf("chat not pinned to provider address: %q", r.Header.Get("X-0G-Provider-Address"))
		}
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		_ = json.Unmarshal(body, &env)
		if _, leaked := env["messages"]; leaked {
			t.Error("prompt reached the router in cleartext")
		}
		e2ee, _ := env.E2EE()
		if _, err := wire.OpenRequest(encPriv, env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, _ := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		resp := wire.Response{
			"id":      json.RawMessage(`"chatcmpl-route"`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"routed answer"},"finish_reason":"stop"}]`),
		}
		sealed, _ := wire.SealResponse(crypto.PublicKey(ephPub), resp, nil)
		_ = json.NewEncoder(w).Encode(sealed)
	})
	router := httptest.NewServer(routerMux)
	defer router.Close()

	client := core.NewWithResolver(route.New(router.URL))
	gw := httptest.NewServer(newHandler(sealedClients(client, nil), mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	// Carry an inference key: the sealed path is now behind the front-door
	// credential gate (openaiproxy.RequireInferenceCredential), which rejects a
	// credential-less request before it ever reaches the seal/route path.
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("build gateway request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-test")
	// Carry a browser Origin (matched here through the "*." wildcard) so this also
	// covers CORS on the SEALED path's real response — the one path where the
	// handler writes its own headers (setResKey / setPassthrough) around the
	// middleware's, and where losing them would leave a browser able to preflight
	// successfully and then unable to read the answer.
	req.Header.Set("Origin", "https://chat.0g.ai")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post to gateway: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d: %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("routed answer")) {
		t.Fatalf("user did not get routed plaintext back: %s", body)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://chat.0g.ai" {
		t.Errorf("sealed response Allow-Origin: got %q, want the origin echoed", got)
	}
	// Without Expose-Headers the browser cannot read ZG-Res-Key, so the user could
	// not fetch the §8 signature to audit the very response it just received.
	if got := resp.Header.Get("Access-Control-Expose-Headers"); !strings.Contains(got, "ZG-Res-Key") {
		t.Errorf("sealed response Expose-Headers: got %q, want it to carry ZG-Res-Key", got)
	}
}

// TestGatewayRoutesOtherRequestsToRouter covers the catch-all: a path the mux
// has no specific route for — the router's non-sealed OpenAI surface, e.g.
// GET /v1/models — is reverse-proxied to the router as-is (path, query, and a
// Host header rewritten to the router), and its response comes straight back.
// This is the cleartext passthrough; it must never carry a prompt (see
// newRouterProxy), which the sealed chat route — exercised by
// TestGatewayRouteMode — continues to own.
// The catch-all sends every request it forwards to the one router host, so it
// needs the shared server-sized connection pool like every other path to that
// host. A nil Transport is the defect this guards: ReverseProxy silently falls
// back to the process-global http.DefaultTransport and its 2 idle connections per
// host, which no functional test would notice — it only shows up as a throughput
// ceiling under concurrency the load rig does not even drive through this route.
func TestRouterProxyUsesThePooledTransport(t *testing.T) {
	proxy, ok := newRouterProxy(mustURL(t, "http://router.unused"), discardLogger()).(*httputil.ReverseProxy)
	if !ok {
		t.Fatal("newRouterProxy did not return a *httputil.ReverseProxy")
	}
	if proxy.Transport == nil {
		t.Fatal("Transport: nil — the proxy would fall back to the process-global http.DefaultTransport")
	}
	tr, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport: got %T, want *http.Transport", proxy.Transport)
	}
	if want := core.NewPooledTransport().MaxIdleConnsPerHost; tr.MaxIdleConnsPerHost != want {
		t.Errorf("MaxIdleConnsPerHost: got %d, want %d (core.NewPooledTransport's)", tr.MaxIdleConnsPerHost, want)
	}
	if tr == http.DefaultTransport {
		t.Error("Transport is http.DefaultTransport itself: the pool would be shared process-wide")
	}
}

func TestGatewayRoutesOtherRequestsToRouter(t *testing.T) {
	var gotPath, gotQuery, gotHost, gotAuth string
	routerMux := http.NewServeMux()
	routerMux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotHost, gotAuth = r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o"}]}`))
	})
	router := httptest.NewServer(routerMux)
	defer router.Close()

	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/v1/models?limit=1", nil)
	req.Header.Set("Authorization", "Bearer user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get /v1/models: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d: %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(`"gpt-4o"`)) {
		t.Fatalf("router response not passed through: %s", body)
	}
	if gotPath != "/v1/models" {
		t.Errorf("router saw path %q, want /v1/models", gotPath)
	}
	if gotQuery != "limit=1" {
		t.Errorf("router saw query %q, want limit=1", gotQuery)
	}
	// The Host header must be the router's, not the gateway's listen host, so the
	// router's TLS/vhost routing resolves correctly.
	if want := mustURL(t, router.URL).Host; gotHost != want {
		t.Errorf("router saw Host %q, want %q", gotHost, want)
	}
	// The passthrough forwards the request verbatim, so the caller's credential
	// reaches the router (which is the auth/billing point) unchanged.
	if gotAuth != "Bearer user-key" {
		t.Errorf("router saw Authorization %q, want the forwarded credential", gotAuth)
	}
}

// TestGatewayRouterPassthroughUnreachable covers the catch-all's ErrorHandler:
// when the router is unreachable, the passthrough must fail closed with a 502
// carrying the SAME JSON error envelope the sealed path uses (so a thin client
// parses errors identically on both paths), and must NOT leak the transport-level
// error detail (router host/port) into the client-facing body.
func TestGatewayRouterPassthroughUnreachable(t *testing.T) {
	// Point the catch-all at a server we immediately close, so a connection to it
	// is refused — a deterministic transport failure without depending on a
	// hard-coded unused port.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, deadURL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/v1/models")
	if err != nil {
		t.Fatalf("get /v1/models: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unreachable router: got %d, want 502", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	// The envelope's canonical shape: a client-facing error object plus the _0g
	// attribution, source "upstream" (a failure reaching the router), never the
	// raw transport error.
	var env struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
		ZG struct {
			Source string `json:"source"`
		} `json:"_0g"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("502 body is not JSON: %v\n%s", err, body)
	}
	if env.ZG.Source != "upstream" {
		t.Errorf("_0g.source: got %q, want upstream", env.ZG.Source)
	}
	if env.Error.Type != "upstream_error" {
		t.Errorf("error.type: got %q, want upstream_error", env.Error.Type)
	}
	if env.Error.Message == "" {
		t.Error("error.message is empty")
	}
	if bytes.Contains(body, []byte(mustURL(t, deadURL).Host)) {
		t.Errorf("502 body leaked the router host: %s", body)
	}
}

// TestGatewayAccessLog covers the middleware's contract: health probes are not
// logged (they would drown real traffic), every other request emits one
// structured line with the expected metadata fields, a caller-supplied request
// id is honored and echoed back, and — the security-critical part — no
// credential or request content leaks into the log line.
func TestGatewayAccessLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	// A stand-in router that answers a non-health path with a 5xx, so the log line
	// exercises the error-severity mapping. A router 5xx is a successful proxy
	// round trip, passed through verbatim as one logged request; the catch-all's
	// ErrorHandler (which would add a second line) fires only on a transport
	// failure — see newRouterProxy.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotImplemented)
	}))
	defer upstream.Close()
	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, upstream.URL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, logger))
	defer gw.Close()

	// A health probe must not produce a log line.
	if resp, err := http.Get(gw.URL + "/healthz"); err != nil {
		t.Fatalf("get /healthz: %v", err)
	} else {
		resp.Body.Close()
	}

	// A real request carrying a secret Authorization header and a forwarded
	// request id, reverse-proxied to the router as a non-sealed metadata path.
	const secret = "Bearer super-secret-token"
	const callerID = "caller-req-123"
	const reqPath = "/v1/models"
	req, _ := http.NewRequest(http.MethodGet, gw.URL+reqPath, nil)
	req.Header.Set("Authorization", secret)
	req.Header.Set("X-Request-Id", callerID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", reqPath, err)
	}
	resp.Body.Close()

	if got := resp.Header.Get("X-Request-Id"); got != callerID {
		t.Fatalf("X-Request-Id not echoed: got %q, want %q", got, callerID)
	}

	// Close synchronizes: after Close returns the server goroutine has finished
	// ServeHTTP, so the access-log line is fully written to buf.
	gw.Close()

	if strings.Contains(buf.String(), "super-secret-token") {
		t.Fatalf("access log leaked the Authorization credential:\n%s", buf.String())
	}

	lines := splitLogLines(buf.String())
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 log line (health probe must be skipped), got %d:\n%s", len(lines), buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, lines[0])
	}
	if rec["msg"] != "request" {
		t.Errorf("msg: got %v, want %q", rec["msg"], "request")
	}
	if rec["path"] != reqPath {
		t.Errorf("path: got %v, want %q", rec["path"], reqPath)
	}
	if rec["method"] != http.MethodGet {
		t.Errorf("method: got %v, want %q", rec["method"], http.MethodGet)
	}
	if rec["request_id"] != callerID {
		t.Errorf("request_id: got %v, want %q", rec["request_id"], callerID)
	}
	if rec["status"] != float64(http.StatusNotImplemented) {
		t.Errorf("status: got %v, want %d", rec["status"], http.StatusNotImplemented)
	}
	// 501 is a server error, so the line's severity must be ERROR (Cloud Logging
	// keys alerts off this).
	if rec["level"] != "ERROR" {
		t.Errorf("level: got %v, want ERROR for a 5xx", rec["level"])
	}
	for _, field := range []string{"duration_ms", "bytes_out", "provider_pinned", "stream"} {
		if _, ok := rec[field]; !ok {
			t.Errorf("log line missing field %q: %s", field, lines[0])
		}
	}
}

// An empty metrics address disables the endpoint; the returned stop must still
// be a safe no-op the caller can defer unconditionally.
func TestStartMetricsDisabled(t *testing.T) {
	stop := startMetrics("", false, discardLogger())
	stop()
}

// TestMetricsEndpointServes binds the metrics server to a concrete loopback port
// and confirms /metrics answers 200 with the exposition format.
func TestMetricsEndpointServes(t *testing.T) {
	const addr = "127.0.0.1:19464"
	stop := startMetrics(addr, false, discardLogger())
	defer stop()

	// The listener starts in a goroutine; retry briefly until it is accepting.
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + addr + "/metrics")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("get /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics: got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("go_goroutines")) {
		t.Fatalf("/metrics did not serve the exposition format:\n%s", body)
	}
}

// The profiler is opt-in: it must not appear on the metrics listener unless
// -pprof asked for it, and it must appear when it did. It rides that listener
// because that port is never published through the ingress, so a regression that
// mounted it unconditionally would put process internals on an operator's port
// without anyone choosing it.
func TestPprofOptIn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		addr     string
		pprofOn  bool
		wantCode int
	}{
		{"off by default", "127.0.0.1:19465", false, http.StatusNotFound},
		{"on when enabled", "127.0.0.1:19466", true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop := startMetrics(tc.addr, tc.pprofOn, discardLogger())
			defer stop()

			var resp *http.Response
			var err error
			for i := 0; i < 50; i++ {
				resp, err = http.Get("http://" + tc.addr + "/debug/pprof/")
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("get /debug/pprof/: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantCode {
				t.Errorf("/debug/pprof/: got %d, want %d", resp.StatusCode, tc.wantCode)
			}
		})
	}
}

// splitLogLines returns the non-empty lines of s, each one JSON log record.
func splitLogLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

// TestGatewayRefusesEveryUnservedSealedSurface: a row of endpoint.All this build
// holds no client for (direct-broker mode serves chat alone) must answer 501
// rather than be left unmounted — and that must hold for EVERY row, not just the
// one someone remembered to write an else-branch for.
//
// Unmounted is NOT inert here, which is the whole point of the test. The catch-all
// is a reverse proxy to the router and routerTarget is parsed in every mode, so an
// unmounted sealed path does not 404 — it forwards the caller's PROMPT to the
// router in cleartext, which is the one thing this gateway exists to prevent. So
// the assertion is in two halves per row: the client sees a refusal, and the
// router never saw the request at all.
//
// Driven with NO clients so every row takes the refusal branch, and over the
// table rather than a list here, so a row added to endpoint.All is covered the
// day it lands. Before the mount loop this was an image-only test guarding a
// hand-written image-only else-branch; a third surface would have had neither.
func TestGatewayRefusesEveryUnservedSealedSurface(t *testing.T) {
	var (
		mu        sync.Mutex
		routerSaw []string
	)
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		routerSaw = append(routerSaw, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer router.Close()

	gw := httptest.NewServer(newHandler(map[string]*core.Client{}, mustURL(t, router.URL), testOrigins(), "", "", noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	for _, ep := range endpoint.All {
		t.Run(ep.Path, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, gw.URL+ep.Path,
				strings.NewReader(`{"model":"m","prompt":"my secret prompt","messages":[{"role":"user","content":"my secret prompt"}]}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer sk-user-key")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post %s: %v", ep.Path, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("status: got %d, want 501 (body %s)", resp.StatusCode, body)
			}
			mu.Lock()
			saw := append([]string(nil), routerSaw...)
			mu.Unlock()
			if len(saw) != 0 {
				t.Fatalf("the prompt was forwarded to the router in cleartext: paths %v", saw)
			}
			// The refusal uses the same JSON error envelope as every other gateway
			// error, so a thin client parses it without a special case — and names
			// the path, so the caller learns which surface this build lacks.
			var env struct {
				Error struct {
					Message string `json:"message"`
					Type    string `json:"type"`
				} `json:"error"`
			}
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatalf("refusal body is not the standard error envelope: %v (%s)", err, body)
			}
			if !strings.Contains(env.Error.Message, ep.Path) {
				t.Errorf("refusal must name the surface, got %q", env.Error.Message)
			}
		})
	}
}

// blockingResolver parks inside Resolve until released, so a test can hold a
// request inside the sealed handler — and therefore inside the in-flight
// limiter's semaphore — while it fires a second one.
type blockingResolver struct {
	entered chan struct{}
	release chan struct{}
}

func (b blockingResolver) Resolve(ctx context.Context, _ endpoint.Endpoint, _ wire.Request) (core.Candidates, error) {
	b.entered <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	// The test never gets this far caring about the outcome: the assertion is about
	// the SLOT this request held, not the answer it produced.
	return nil, errors.New("blocked resolver yields no candidates")
}

// TestSealedRoutesShareOneInFlightLimiter: the chat and image routes must draw
// from ONE semaphore, so the process ceiling is maxInFlight and not 2×.
//
// openaiproxy.LimitInFlight builds a fresh semaphore per call, so wrapping each
// route in its own call reads exactly like sharing one and is not: the two routes
// each get the full budget. Nothing observable says so — the gateway serves
// normally, and metrics.SetInFlightLimit still publishes the single configured
// number — while peak memory can reach twice what defaultMaxInFlight sized the
// process for, and every alert on in-flight/limit divides by the wrong ceiling.
//
// With a cap of 1, holding a chat request inside the handler must shed an image
// request with 503. Two semaphores would let it straight through.
func TestSealedRoutesShareOneInFlightLimiter(t *testing.T) {
	blocker := blockingResolver{entered: make(chan struct{}), release: make(chan struct{})}

	// Chat holds the slot; the image client is ordinary — the point is that the
	// image ROUTE cannot find a slot, not that the image client is special.
	gw := httptest.NewServer(newHandler(
		sealedClients(core.NewWithResolver(blocker), routeClient()),
		mustURL(t, "http://router.unused"), testOrigins(), "", "",
		1, nil, nil, nil, discardLogger()))
	// Release BEFORE Close: httptest's Close waits for outstanding requests, and
	// the whole point of this fixture is that one is parked indefinitely. Deferred
	// second so it runs first.
	defer gw.Close()
	defer close(blocker.release)

	go func() {
		req, _ := http.NewRequest(http.MethodPost, gw.URL+"/v1/chat/completions",
			strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-user-key")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-blocker.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the chat request never reached the resolver; it never took a slot")
	}

	req, _ := http.NewRequest(http.MethodPost, gw.URL+"/v1/images/generations",
		strings.NewReader(`{"model":"z-image","prompt":"p","response_format":"b64_json"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post /v1/images/generations: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("image request status = %d, want 503: the sole in-flight slot was held by "+
			"the chat request, so the two routes are not sharing one limiter (body %s)", resp.StatusCode, body)
	}
	// A shed carries Retry-After; without it a client has nothing to back off on,
	// and this would pass against an unrelated 503.
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("a shed response must carry Retry-After (body %s)", body)
	}
}

// sealedClients is the map newHandler takes, built from the two clients most
// tests think in terms of. nil for either leaves that surface unserved, which the
// gateway then mounts as an explicit refusal.
func sealedClients(chat, image *core.Client) map[string]*core.Client {
	m := map[string]*core.Client{}
	if chat != nil {
		m[endpoint.Chat.Path] = chat
	}
	if image != nil {
		m[endpoint.Image.Path] = image
	}
	return m
}

// A row this build DOES serve is mounted at its own path, not left to the
// cleartext catch-all and not refused.
//
// The complement of TestGatewayRefusesEveryUnservedSealedSurface, and worth
// stating separately for the surface that most recently became a row: before
// /v1/messages was one, an Anthropic SDK pointed at this gateway fell through to
// the reverse proxy — which is not a 404, it is the caller's PROMPT forwarded to
// the router in the clear, the one thing this process exists to prevent.
//
// The assertion is deliberately negative on the outcome (it must not be refused,
// and the router must not have heard the path) rather than expecting a 200: the
// resolver here points at an unused host, so the request fails upstream. That it
// fails INSIDE the sealed handler is the property under test.
func TestGatewayMountsAServedAnthropicSurface(t *testing.T) {
	var (
		mu        sync.Mutex
		routerSaw []string
	)
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		routerSaw = append(routerSaw, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer router.Close()

	clients := map[string]*core.Client{endpoint.Anthropic.Path: routeClient()}
	gw := httptest.NewServer(newHandler(clients, mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	req, _ := http.NewRequest(http.MethodPost, gw.URL+endpoint.Anthropic.Path,
		strings.NewReader(`{"model":"claude-x","max_tokens":16,"system":"my secret system prompt",`+
			`"messages":[{"role":"user","content":"my secret prompt"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", endpoint.Anthropic.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNotImplemented {
		t.Errorf("a served row must not be refused: got 501 (body %s)", body)
	}
	if resp.StatusCode == http.StatusNotFound {
		t.Errorf("%s is not mounted: got 404 (body %s)", endpoint.Anthropic.Path, body)
	}
	mu.Lock()
	saw := append([]string(nil), routerSaw...)
	mu.Unlock()
	for _, p := range saw {
		if p == endpoint.Anthropic.Path {
			t.Fatalf("the request reached the cleartext catch-all: the router saw %v", saw)
		}
	}
	if bytes.Contains(body, []byte("my secret")) {
		t.Errorf("the prompt was echoed back in the error body: %s", body)
	}
}

// A sealed surface claims its SUBTREE, not just its exact path.
//
// Mounting the exact path alone left every sub-resource of a sealed surface
// falling through to the catch-all, which is a cleartext reverse proxy to the
// router. An Anthropic SDK's messages.count_tokens() POSTs the whole
// conversation and system prompt to /v1/messages/count_tokens; Message Batches
// POSTs the same payload to /v1/messages/batches. Neither matched a pattern, so
// both went to the untrusted router in the clear — and came back 200, so nothing
// about the exchange looked wrong.
//
// The assertion is on what the ROUTER RECEIVED, not on the status code: a 501
// with the payload already forwarded would be the same failure wearing a better
// answer.
//
// Driven off endpoint.All so a row added later is covered the day it lands, and
// with a client for every row, since whether this build seals a surface has no
// bearing on whether its sub-resources may leak.
func TestGatewayRefusesSubResourcesOfASealedSurface(t *testing.T) {
	var (
		mu        sync.Mutex
		routerSaw []string
		bodies    []string
	)
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		routerSaw = append(routerSaw, r.Method+" "+r.URL.Path)
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer router.Close()

	clients := map[string]*core.Client{}
	for _, ep := range endpoint.All {
		clients[ep.Path] = routeClient()
	}
	gw := httptest.NewServer(newHandler(clients, mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	const secret = "my secret prompt"
	for _, ep := range endpoint.All {
		for _, suffix := range []string{"count_tokens", "batches", "some/deeper/path"} {
			path := ep.Path + "/" + suffix
			t.Run(path, func(t *testing.T) {
				req, _ := http.NewRequest(http.MethodPost, gw.URL+path, strings.NewReader(
					`{"model":"m","system":"`+secret+`","messages":[{"role":"user","content":"`+secret+`"}]}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-user-key")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("post %s: %v", path, err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != http.StatusNotImplemented {
					t.Errorf("status = %d, want 501 (body %s)", resp.StatusCode, body)
				}
			})
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(routerSaw) != 0 {
		t.Fatalf("a sub-resource of a sealed surface was forwarded to the router: %v", routerSaw)
	}
	for i, b := range bodies {
		if strings.Contains(b, secret) {
			t.Errorf("the prompt reached the router in the clear at %s: %s", routerSaw[i], b)
		}
	}
}

// The exact path on a method this gateway does not seal is refused too, rather
// than proxied or bounced.
//
// Two things this pins. A GET on the surface's own path used to reach the
// cleartext proxy — harmless in itself (no body, so no prompt) but the surface's
// path is this gateway's to answer. And registering the subtree alone made Go's
// ServeMux answer the slash-less form with an implicit 307 INTO the subtree,
// since the only pattern for the exact path was method-specific; the method-less
// exact registration removes that redirect while still losing to `POST <path>`
// for the sealed method.
func TestGatewayRefusesUnsealedMethodsOnASealedPath(t *testing.T) {
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the router must not see %s %s", r.Method, r.URL.Path)
	}))
	defer router.Close()

	clients := map[string]*core.Client{endpoint.Anthropic.Path: routeClient()}
	gw := httptest.NewServer(newHandler(clients, mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	// No redirect following, so a 307 shows up as itself instead of resolving.
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, gw.URL+endpoint.Anthropic.Path, nil)
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", endpoint.Anthropic.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d (Location %q), want 501: %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
}

// The catch-all must still reverse-proxy everything that is NOT part of a sealed
// surface — the router's cleartext metadata APIs a thin client needs. Asserted
// alongside the refusals because they are one decision: a subtree claim that
// swallowed the model catalog would pass both tests above.
func TestGatewayStillProxiesNonSealedPaths(t *testing.T) {
	var (
		mu        sync.Mutex
		routerSaw []string
	)
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		routerSaw = append(routerSaw, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer router.Close()

	clients := map[string]*core.Client{}
	for _, ep := range endpoint.All {
		clients[ep.Path] = routeClient()
	}
	gw := httptest.NewServer(newHandler(clients, mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	for _, path := range []string{"/v1/models", "/v1/providers", "/v1/service-types"} {
		req, _ := http.NewRequest(http.MethodGet, gw.URL+path, nil)
		req.Header.Set("Authorization", "Bearer sk-user-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want it proxied (body %s)", path, resp.StatusCode, body)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(routerSaw) != 3 {
		t.Errorf("the router saw %v, want all three metadata paths proxied", routerSaw)
	}
}

// A CORS preflight is answered by the middleware ABOVE the mux, so the refusals
// must not intercept one: a browser sends no credentials on a preflight, and a
// 501 there would break every browser client of the sealed surface before it
// ever sent the real request.
func TestGatewayAnswersPreflightOnRefusedPaths(t *testing.T) {
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer router.Close()
	clients := map[string]*core.Client{endpoint.Anthropic.Path: routeClient()}
	const origin = "https://app.example"
	gw := httptest.NewServer(newHandler(clients, mustURL(t, router.URL), []string{origin}, "", "",
		noInFlightCap, nil, nil, nil, discardLogger()))
	defer gw.Close()

	for _, path := range []string{endpoint.Anthropic.Path, endpoint.Anthropic.Path + "/count_tokens"} {
		req, _ := http.NewRequest(http.MethodOptions, gw.URL+path, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("preflight %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("preflight %s = %d, want 204", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("preflight %s allow-origin = %q, want %q", path, got, origin)
		}
	}
}
