package openaiproxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
)

func meta(env map[string]any, t *testing.T) map[string]any {
	t.Helper()
	m, ok := env["_0g"].(map[string]any)
	if !ok {
		t.Fatalf("_0g attribution missing/typed wrong: %#v", env["_0g"])
	}
	return m
}

func errObj(env map[string]any, t *testing.T) map[string]any {
	t.Helper()
	e, ok := env["error"].(map[string]any)
	if !ok {
		t.Fatalf("error object missing/typed wrong: %#v", env["error"])
	}
	return e
}

func TestErrorEnvelope_UpstreamPassthroughVerbatim(t *testing.T) {
	body := `{"error":{"message":"No available providers","type":"server_error","code":"no_available_provider"}}`
	err := &core.Error{Stage: core.StageUpstream, Status: 503, Err: errors.New("route preview returned 503"), Body: body}

	env := options{}.errorEnvelope(err)
	e := errObj(env, t)
	// Router's fields pass through verbatim.
	if e["message"] != "No available providers" || e["type"] != "server_error" || e["code"] != "no_available_provider" {
		t.Errorf("upstream error object not passed through verbatim: %#v", e)
	}
	// Attribution is a SIBLING, never inside the (verbatim) error object.
	if _, leaked := e["_0g"]; leaked {
		t.Error("_0g must not be nested inside the error object")
	}
	m := meta(env, t)
	if m["source"] != "upstream" || m["upstream_status"] != 503 {
		t.Errorf("attribution = %#v, want source=upstream upstream_status=503", m)
	}
}

func TestErrorEnvelope_GatewayNonCoreError(t *testing.T) {
	env := options{}.errorEnvelope(errors.New("boom"))
	e := errObj(env, t)
	if e["message"] != "boom" || e["type"] != "gateway_error" {
		t.Errorf("error = %#v", e)
	}
	if meta(env, t)["source"] != "gateway" {
		t.Errorf("source = %v, want gateway", meta(env, t)["source"])
	}
}

func TestErrorEnvelope_GatewayStageInternal(t *testing.T) {
	err := &core.Error{Stage: core.StageInternal, Err: errors.New("generate ephemeral key")}
	env := options{}.errorEnvelope(err)
	if errObj(env, t)["type"] != "gateway_error" {
		t.Errorf("type = %v, want gateway_error", errObj(env, t)["type"])
	}
	if meta(env, t)["source"] != "gateway" {
		t.Errorf("source = %v, want gateway", meta(env, t)["source"])
	}
}

func TestErrorEnvelope_UpstreamNonJSONBody(t *testing.T) {
	err := &core.Error{Stage: core.StageUpstream, Status: 502, Err: errors.New("provider returned 502"), Body: "<html>502 Bad Gateway</html>"}

	// Non-verbose (gateway): synthesized error, raw body NOT echoed.
	env := options{}.errorEnvelope(err)
	if errObj(env, t)["type"] != "upstream_error" {
		t.Errorf("type = %v, want upstream_error", errObj(env, t)["type"])
	}
	if _, echoed := meta(env, t)["upstream_body"]; echoed {
		t.Error("raw upstream body must NOT be echoed when verbose is off")
	}

	// Verbose (sidecar): raw body echoed under _0g.
	venv := options{verboseUpstreamErrors: true}.errorEnvelope(err)
	if got := meta(venv, t)["upstream_body"]; got != "<html>502 Bad Gateway</html>" {
		t.Errorf("upstream_body = %v, want the raw body", got)
	}
}

func TestParseUpstreamErrorObject(t *testing.T) {
	if _, ok := parseUpstreamErrorObject(""); ok {
		t.Error("empty body should not parse")
	}
	if _, ok := parseUpstreamErrorObject("not json"); ok {
		t.Error("non-JSON should not parse")
	}
	if _, ok := parseUpstreamErrorObject(`{"error":{"code":"x"}}`); ok {
		t.Error("message-less error object should not parse")
	}
	obj, ok := parseUpstreamErrorObject(`{"error":{"message":"m","code":"c"}}`)
	if !ok || obj["message"] != "m" || obj["code"] != "c" {
		t.Errorf("valid error object failed: ok=%v obj=%#v", ok, obj)
	}
}

// TestHandler_GatewayErrorWireShape drives the real handler with an invalid body
// (a gateway-origin fault, short-circuiting before the core call) and checks the
// on-the-wire envelope carries gateway attribution.
func TestHandler_GatewayErrorWireShape(t *testing.T) {
	h := Handler(core.New(core.Provider{URL: "http://unused.invalid"}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var env map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	m, _ := env["_0g"].(map[string]any)
	if m == nil || m["source"] != "gateway" {
		t.Errorf("_0g = %#v, want source=gateway", env["_0g"])
	}
	if e, _ := env["error"].(map[string]any); e == nil || e["type"] != "gateway_error" {
		t.Errorf("error = %#v, want type=gateway_error", env["error"])
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	got := truncate(strings.Repeat("a", 20), 8)
	if !strings.HasPrefix(got, strings.Repeat("a", 8)) || !strings.Contains(got, "truncated") {
		t.Errorf("truncate long = %q", got)
	}
}
