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

// embeddingGateway is the real serving stack for /v1/embeddings, pointed at the
// fixture: HTTP front end, client core and route resolver, minus attestation.
func embeddingGateway(t *testing.T, upstreamURL string, c *http.Client) *httptest.Server {
	t.Helper()
	router := route.New(upstreamURL)
	client := core.NewWithResolver(router,
		core.WithEndpoint(endpoint.Embedding),
		core.WithUnboundFields(wire.DefaultUnboundFields()),
		core.WithResponseVerification(route.NewSignatureFetcher(c), sig.Recover),
	)
	mux := http.NewServeMux()
	openaiproxy.Register(mux, endpoint.Embedding, client)
	gw := httptest.NewServer(mux)
	t.Cleanup(gw.Close)
	return gw
}

func postEmbeddings(t *testing.T, gwURL, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(gwURL+endpoint.Embedding.Path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", endpoint.Embedding.Path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// The whole chain for the embedding surface: an SDK-shaped request to the
// gateway, the route preview, the router's /v1/embeddings, and the enclave
// behind it, which opens under the embedding profile and answers sealed.
//
// Asserted at each hop: the router's preview and data-plane bodies carry the
// routing fields but not the input; the client gets vectors derived from the
// input the enclave opened, plus the cleartext billable count.
func TestEmbeddingEndToEndThroughRouterAndEnclave(t *testing.T) {
	s, err := newServer(testConfig())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	rec := recordUpstream(s.handler())
	upstream := httptest.NewServer(rec)
	defer upstream.Close()
	gw := embeddingGateway(t, upstream.URL, upstream.Client())

	const secretA = "quarterly revenue fell sharply"
	const secretB = "layoffs planned"
	body := `{"model":"mock-model","input":["` + secretA + `","` + secretB + `"],` +
		`"encoding_format":"float","dimensions":256}`
	status, raw := postEmbeddings(t, gw.URL, body)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, raw)
	}

	// The control-plane hop.
	preview := rec.bodyAt(t, "/v1/routing/preview")
	if got := string(preview["service_type"]); got != `"embedding"` {
		t.Errorf("preview service_type = %s, want %q", got, "embedding")
	}
	if _, ok := preview["model"]; !ok {
		t.Error("the router needs cleartext \"model\" to rank providers")
	}
	if _, leaked := preview["input"]; leaked {
		t.Error("\"input\" reached the router's preview in the clear")
	}

	// The data-plane hop: routing fields and the two knobs stay readable, the
	// input is nowhere in the bytes.
	sealedReq := rec.bodyAt(t, endpoint.Embedding.UpstreamPath)
	for _, f := range []string{"model", "encoding_format", "dimensions", "_e2ee"} {
		if _, ok := sealedReq[f]; !ok {
			t.Errorf("the sealed request must carry cleartext %q", f)
		}
	}
	if _, leaked := sealedReq["input"]; leaked {
		t.Error("\"input\" reached the router in the clear on the sealed request")
	}
	sealedRaw := rec.rawAt(t, endpoint.Embedding.UpstreamPath)
	for _, secret := range []string{secretA, secretB} {
		if bytes.Contains(sealedRaw, []byte(secret)) {
			t.Errorf("%q is in the body the router received", secret)
		}
	}

	// The client's view. handleEmbeddings derives one vector per input string
	// (its byte length) and prompt_tokens from the word count, so these values
	// only come out right if the input survived seal → route → open.
	var out struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		} `json:"usage"`
		E2EE json.RawMessage `json:"_e2ee"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("client response is not a JSON object: %v\n%s", err, raw)
	}
	if len(out.Data) != 2 {
		t.Fatalf("got %d vectors, want one per input string: %s", len(out.Data), raw)
	}
	for i, want := range []int{len(secretA), len(secretB)} {
		if got := out.Data[i].Embedding; len(got) != 1 || int(got[0]) != want {
			t.Errorf("vector %d = %v, want [%d]", i, got, want)
		}
	}
	if want := len(strings.Fields(secretA)) + len(strings.Fields(secretB)); out.Usage.PromptTokens != want {
		t.Errorf("usage.prompt_tokens = %d, want %d", out.Usage.PromptTokens, want)
	}
	if out.E2EE != nil {
		t.Error("the opened response still carries _e2ee")
	}
}

// The endpoint has no streaming shape, so the gateway refuses `stream: true`
// before anything reaches the router.
func TestEmbeddingGatewayRefusesStreaming(t *testing.T) {
	s, err := newServer(testConfig())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	rec := recordUpstream(s.handler())
	upstream := httptest.NewServer(rec)
	defer upstream.Close()
	gw := embeddingGateway(t, upstream.URL, upstream.Client())

	status, raw := postEmbeddings(t, gw.URL, `{"model":"mock-model","input":"hi","stream":true}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", status, raw)
	}
	rec.mu.Lock()
	n := len(rec.seen)
	rec.mu.Unlock()
	if n != 0 {
		t.Errorf("the router saw %d requests for a refused stream, want 0", n)
	}
}
