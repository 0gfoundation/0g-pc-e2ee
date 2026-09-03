package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/client/sig"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// upstreamRecorder wraps the fixture's handler and keeps the raw body of each
// request that reached a given path.
//
// It is what makes the ROUTER's view assertable separately from the enclave's.
// The fixture is one process impersonating both, so without this the only
// observable is the final response — and "the enclave opened the request" does
// not by itself say the router could not read it. Capturing the bytes as they
// ARRIVE is the router's view; the handler opening them afterwards is the
// enclave's.
type upstreamRecorder struct {
	inner http.Handler
	mu    sync.Mutex
	seen  map[string][]byte
}

func recordUpstream(inner http.Handler) *upstreamRecorder {
	return &upstreamRecorder{inner: inner, seen: map[string][]byte{}}
}

func (u *upstreamRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.seen[r.URL.Path] = body
		u.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	u.inner.ServeHTTP(w, r)
}

// bodyAt returns the decoded body last seen at path, failing the test when
// nothing reached it — an assertion in its own right, since a hop that never
// happened would otherwise pass every "field is absent" check below.
func (u *upstreamRecorder) bodyAt(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	u.mu.Lock()
	raw, ok := u.seen[path]
	u.mu.Unlock()
	if !ok {
		t.Fatalf("nothing reached %s; the hop did not happen", path)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("body at %s is not a JSON object: %v", path, err)
	}
	return body
}

// anthropicGateway is the real serving stack for /v1/messages: the HTTP front
// end over the real client core over the real route resolver, pointed at the
// fixture. It is how proxycli.Build wires the gateway, minus the attestation the
// fixture cannot satisfy.
//
// It deliberately does NOT pass WithSealFields: -seal-fields is chat's set by
// definition, and this surface seals its own profile's default (messages, plus
// system when present). Passing chat's set here is the misconfiguration the row
// exists to make impossible.
func anthropicGateway(t *testing.T, upstreamURL string, c *http.Client) *httptest.Server {
	t.Helper()
	router := route.New(upstreamURL)
	client := core.NewWithResolver(router,
		core.WithEndpoint(endpoint.Anthropic),
		core.WithUnboundFields(wire.DefaultUnboundFields()),
		core.WithResponseVerification(route.NewSignatureFetcher(c), sig.Recover),
	)
	mux := http.NewServeMux()
	openaiproxy.Register(mux, endpoint.Anthropic, client)
	gw := httptest.NewServer(mux)
	t.Cleanup(gw.Close)
	return gw
}

// The whole chain for the Anthropic surface, in one process and three hops:
// an SDK-shaped request to the gateway, the gateway's control-plane hop to the
// router's route-preview, its data-plane hop to the router's /v1/messages, and
// the enclave behind it.
//
// This is the test that could not be written before /v1/messages was a row, and
// the one no single-package test replaces: each layer's own tests assert their
// half against a stub, so a mismatch BETWEEN them — the router asked for one
// pool while the request was sealed for another, or the surface previewed as
// OpenAI chat — passes everywhere and fails only here.
//
// Four things are asserted, at the point each becomes observable:
//
//  1. the router's CONTROL-PLANE view: it must learn which pool to rank
//     (api_format), and must not see the payload;
//  2. the router's DATA-PLANE view: it must be able to route and bill (model,
//     max_tokens, stream) and must not be able to read the conversation;
//  3. the ENCLAVE's view: it opened the request under the Anthropic profile,
//     which is what a 200 proves — handleMessages 400s otherwise;
//  4. the CLIENT's view: proper §7.2 SSE, each event named from its own bound
//     type, ending at message_stop with no `[DONE]`, and the §8 signature
//     verified over the frame sequence.
func TestAnthropicEndToEndThroughRouterAndEnclave(t *testing.T) {
	cfg := testConfig()
	cfg.Chunks = 3
	cfg.ChunkBytes = 2
	s, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	rec := recordUpstream(s.handler())
	upstream := httptest.NewServer(rec)
	defer upstream.Close()

	gw := anthropicGateway(t, upstream.URL, upstream.Client())

	const (
		secretPrompt = "the secret user prompt"
		secretSystem = "the secret system prompt"
	)
	userReq := `{"model":"mock-model","max_tokens":1024,"stream":true,` +
		`"system":"` + secretSystem + `",` +
		`"messages":[{"role":"user","content":"` + secretPrompt + `"}]}`
	resp, err := http.Post(gw.URL+endpoint.Anthropic.Path, "application/json", strings.NewReader(userReq))
	if err != nil {
		t.Fatalf("post %s: %v", endpoint.Anthropic.Path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}

	// (1) The control-plane hop.
	preview := rec.bodyAt(t, "/v1/routing/preview")
	if got := string(preview["service_type"]); got != `"chatbot"` {
		t.Errorf("preview service_type = %s, want %q — the router refuses \"anthropic-chat\" as one", got, "chatbot")
	}
	if got := string(preview["api_format"]); got != `"anthropic"` {
		t.Errorf("preview api_format = %s, want %q — without it the router ranks the OpenAI pool", got, "anthropic")
	}
	for _, f := range []string{"model", "max_tokens"} {
		if _, ok := preview[f]; !ok {
			t.Errorf("the router needs cleartext %q to rank providers", f)
		}
	}
	for _, f := range []string{"messages", "system"} {
		if _, leaked := preview[f]; leaked {
			t.Errorf("%q reached the router's preview in the clear", f)
		}
	}

	// (2) The data-plane hop.
	sealedReq := rec.bodyAt(t, endpoint.Anthropic.UpstreamPath)
	for _, f := range []string{"model", "max_tokens", "stream", "_e2ee"} {
		if _, ok := sealedReq[f]; !ok {
			t.Errorf("the sealed request must carry cleartext %q", f)
		}
	}
	for _, f := range []string{"messages", "system"} {
		if _, leaked := sealedReq[f]; leaked {
			t.Errorf("%q reached the router in the clear on the sealed request", f)
		}
	}
	// stream_options is an OpenAI CHAT convention and is BOUND once sealed, so
	// grafting it here would both invent a field /v1/messages does not define and
	// make it undeniable to the enclave.
	if _, grafted := sealedReq["stream_options"]; grafted {
		t.Error("stream_options was grafted onto an Anthropic request")
	}

	// (3) + (4). The enclave opened it under the Anthropic profile — a 200 is that
	// proof, since handleMessages 400s on a request sealed under any other — and
	// the response verified, since WithResponseVerification would have failed the
	// stream otherwise.
	for _, secret := range []string{secretPrompt, secretSystem} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("%q appeared in the response the client received", secret)
		}
	}
	names, types, text := parseAnthropicSSE(t, raw)
	if bytes.Contains(raw, []byte("[DONE]")) {
		t.Error("the stream carried [DONE]: an OpenAI chat convention the Anthropic taxonomy has no rule for")
	}
	for i, name := range names {
		if name == "" {
			t.Errorf("frame %d (%s) has no event: line; an Anthropic SDK dispatches on it", i, types[i])
			continue
		}
		if name != types[i] {
			t.Errorf("frame %d announced as %q but its bound type is %q", i, name, types[i])
		}
	}
	if n := len(types); n == 0 || types[n-1] != "message_stop" {
		t.Fatalf("stream ended with %v, want message_stop last", types)
	}
	// cfg.Chunks deltas of cfg.ChunkBytes each: the content survived the seal,
	// the router hop and the per-frame unseal intact.
	if want := strings.Repeat("x", cfg.Chunks*cfg.ChunkBytes); text != want {
		t.Errorf("reassembled text = %q, want %q", text, want)
	}
}

// The non-streaming half of the same chain: one sealed `message` frame, opened
// and returned as JSON. Worth its own case because the frame taxonomy's
// non-streaming shape seals a DIFFERENT field (`content`, not `delta`) and is
// final by definition rather than by a terminal event — so a receiver that
// handled only the streaming shape would pass the test above and fail here.
func TestAnthropicNonStreamingEndToEnd(t *testing.T) {
	cfg := testConfig()
	cfg.Chunks = 2
	cfg.ChunkBytes = 3
	s, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	rec := recordUpstream(s.handler())
	upstream := httptest.NewServer(rec)
	defer upstream.Close()

	gw := anthropicGateway(t, upstream.URL, upstream.Client())

	const secretSystem = "the secret system prompt"
	resp, err := http.Post(gw.URL+endpoint.Anthropic.Path, "application/json", strings.NewReader(
		`{"model":"mock-model","max_tokens":64,"system":"`+secretSystem+`",`+
			`"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("post %s: %v", endpoint.Anthropic.Path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte(secretSystem)) {
		t.Error("the system prompt came back in the response")
	}
	if _, leaked := rec.bodyAt(t, endpoint.Anthropic.UpstreamPath)["system"]; leaked {
		t.Error("the system prompt reached the router in the clear")
	}

	var opened struct {
		Type    string `json:"type"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &opened); err != nil {
		t.Fatalf("response is not a JSON object: %v (%s)", err, raw)
	}
	if opened.Type != "message" {
		t.Errorf("type = %q, want %q", opened.Type, "message")
	}
	if len(opened.Content) != 1 {
		t.Fatalf("content has %d blocks, want 1: %s", len(opened.Content), raw)
	}
	// The content array was SEALED, so its arrival intact is the round trip.
	if want := strings.Repeat("x", cfg.ChunkBytes); opened.Content[0].Text != want {
		t.Errorf("content text = %q, want %q", opened.Content[0].Text, want)
	}
}

// parseAnthropicSSE splits an SSE body into per-event (name, bound type) pairs
// and the reassembled text. The pairing is the point: a receiver that emitted a
// constant event name, or forwarded the upstream's, would still produce names.
func parseAnthropicSSE(t *testing.T, raw []byte) (names, types []string, text string) {
	t.Helper()
	for _, block := range strings.Split(string(raw), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var name, data string
		for _, line := range strings.Split(block, "\n") {
			if v, ok := strings.CutPrefix(line, "event: "); ok {
				name = v
			}
			if v, ok := strings.CutPrefix(line, "data: "); ok {
				data = v
			}
		}
		if data == "" || data == "[DONE]" {
			continue
		}
		var frame struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &frame); err != nil {
			t.Fatalf("bad SSE frame %q: %v", data, err)
		}
		names = append(names, name)
		types = append(types, frame.Type)
		text += frame.Delta.Text
	}
	return names, types, text
}
