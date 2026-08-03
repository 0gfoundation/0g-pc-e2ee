package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// routeClient builds the gateway's client the way main does: route-only, no
// pinned provider. The preview URL is unused by the operational-route tests.
func routeClient() *core.Client {
	return core.NewWithResolver(route.New("http://router.unused"))
}

// discardLogger is a logger the operational-route tests hand to newHandler when
// they don't assert on the access log; TestGatewayAccessLog uses its own buffer.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
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
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), discardLogger()))
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

// /quote is still a stub: it must answer 501 (Not Implemented), not 404, so a
// validator can tell the endpoint exists but attestation is not wired yet.
func TestGatewayQuoteStub(t *testing.T) {
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), discardLogger()))
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/quote")
	if err != nil {
		t.Fatalf("get /quote: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("/quote: got %d, want 501", resp.StatusCode)
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
	gw := httptest.NewServer(newHandler(client, mustURL(t, router.URL), discardLogger()))
	defer gw.Close()

	userReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(userReq))
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
}

// TestGatewayRoutesOtherRequestsToRouter covers the catch-all: a path the mux
// has no specific route for — the router's non-sealed OpenAI surface, e.g.
// GET /v1/models — is reverse-proxied to the router as-is (path, query, and a
// Host header rewritten to the router), and its response comes straight back.
// This is the cleartext passthrough; it must never carry a prompt (see
// newRouterProxy), which the sealed chat route — exercised by
// TestGatewayRouteMode — continues to own.
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

	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, router.URL), discardLogger()))
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

// TestGatewayAccessLog covers the middleware's contract: health probes are not
// logged (they would drown real traffic), every other request emits one
// structured line with the expected metadata fields, a caller-supplied request
// id is honored and echoed back, and — the security-critical part — no
// credential or request content leaks into the log line.
func TestGatewayAccessLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	gw := httptest.NewServer(newHandler(routeClient(), mustURL(t, "http://router.unused"), logger))
	defer gw.Close()

	// A health probe must not produce a log line.
	if resp, err := http.Get(gw.URL + "/healthz"); err != nil {
		t.Fatalf("get /healthz: %v", err)
	} else {
		resp.Body.Close()
	}

	// A real request carrying a secret Authorization header and a forwarded
	// request id. /quote is a convenient non-health route (it answers 501).
	const secret = "Bearer super-secret-token"
	const callerID = "caller-req-123"
	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/quote", nil)
	req.Header.Set("Authorization", secret)
	req.Header.Set("X-Request-Id", callerID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get /quote: %v", err)
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
	if rec["path"] != "/quote" {
		t.Errorf("path: got %v, want %q", rec["path"], "/quote")
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
