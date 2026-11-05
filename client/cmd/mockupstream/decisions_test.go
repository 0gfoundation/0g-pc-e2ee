package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/client/sig"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func decisionsGateway(t *testing.T, upstreamURL string, c *http.Client) *httptest.Server {
	t.Helper()
	client := core.NewWithResolver(route.New(upstreamURL),
		core.WithEndpoint(endpoint.Decisions),
		core.WithUnboundFields(wire.DefaultUnboundFields()),
		core.WithResponseVerification(route.NewSignatureFetcher(c), sig.Recover),
	)
	mux := http.NewServeMux()
	openaiproxy.Register(mux, endpoint.Decisions, client)
	gw := httptest.NewServer(mux)
	t.Cleanup(gw.Close)
	return gw
}

// The whole chain for the decisions surface: the router's preview and
// data-plane bodies carry `model` but neither the state nor the questions, and
// the client gets answers derived from what the enclave opened.
func TestDecisionsEndToEndThroughRouterAndEnclave(t *testing.T) {
	s, err := newServer(testConfig())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	rec := recordUpstream(s.handler())
	upstream := httptest.NewServer(rec)
	defer upstream.Close()
	gw := decisionsGateway(t, upstream.URL, upstream.Client())

	const secretState = "patient 4471 asks about results"
	const secretCriterion = "Answering a factual medical question"
	body := `{"model":"mock-model","state":"` + secretState + `",` +
		`"questions":{"task":{"type":"choice","criteria":{"qa_knowledge":"` + secretCriterion + `","zz_other":"x"}}}}`
	resp, err := http.Post(gw.URL+endpoint.Decisions.Path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}

	preview := rec.bodyAt(t, "/v1/routing/preview")
	if got := string(preview["service_type"]); got != `"decisions"` {
		t.Errorf("preview service_type = %s, want %q", got, "decisions")
	}
	for _, f := range []string{"state", "questions"} {
		if _, leaked := preview[f]; leaked {
			t.Errorf("%q reached the router's preview in the clear", f)
		}
	}
	sealedRaw := rec.rawAt(t, endpoint.Decisions.UpstreamPath)
	for _, secret := range []string{secretState, secretCriterion, "qa_knowledge"} {
		if bytes.Contains(sealedRaw, []byte(secret)) {
			t.Errorf("%q is in the body the router received", secret)
		}
	}
	if !bytes.Contains(sealedRaw, []byte(`"model"`)) {
		t.Error("the sealed request must carry cleartext model")
	}

	var out struct {
		Answers map[string]struct {
			Choice string `json:"choice"`
		} `json:"answers"`
		Usage struct {
			InputTokens int `json:"input_tokens"`
		} `json:"usage"`
		E2EE json.RawMessage `json:"_e2ee"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("client response is not a JSON object: %v\n%s", err, raw)
	}
	if got := out.Answers["task"].Choice; got != "qa_knowledge" {
		t.Errorf("answers.task.choice = %q, want qa_knowledge (derived from the opened questions)", got)
	}
	if want := len(strings.Fields(secretState)); out.Usage.InputTokens != want {
		t.Errorf("usage.input_tokens = %d, want %d (derived from the opened state)", out.Usage.InputTokens, want)
	}
	if out.E2EE != nil {
		t.Error("the opened response still carries _e2ee")
	}
}
