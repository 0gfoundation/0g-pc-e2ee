package clientip

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// testdata/client_vectors.json is byte-identical to the router's copy (0g-router
// backend/internal/service/testdata/client_vectors.json); both sides classify
// every vector, so the two rule tables agree on every case it holds.
func TestClassifySharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/client_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name      string `json:"name"`
			UserAgent string `json:"user_agent"`
			Title     string `json:"title"`
			Referer   string `json:"referer"`
			Client    string `json:"client"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range doc.Vectors {
		if got := Classify(v.UserAgent, v.Title, v.Referer); got != v.Client {
			t.Errorf("%s: Classify(%q, %q, %q) = %q, want %q", v.Name, v.UserAgent, v.Title, v.Referer, got, v.Client)
		}
	}
}

// clientVia runs an inbound request with the given headers through the
// Middleware and returns the router-bound request a handler builds, after Stamp.
// forwarded is copied onto the outbound, as routingHeaders forwards X-0G-*.
func clientVia(t *testing.T, s *Signer, remoteAddr string, inbound, forwarded http.Header) *http.Request {
	t.Helper()
	var out *http.Request
	h := s.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://router.example/v1/chat/completions", nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, vs := range forwarded {
			req.Header[k] = vs
		}
		Stamp(req)
		out = req
	}))
	in := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	in.RemoteAddr = remoteAddr
	for k, vs := range inbound {
		in.Header[k] = vs
	}
	h.ServeHTTP(httptest.NewRecorder(), in)
	return out
}

func TestStampSendsClientName(t *testing.T) {
	s := mustSigner(t, "https://router.example")
	for _, tc := range []struct {
		name    string
		inbound http.Header
		want    string
	}{
		{"claude code", http.Header{"User-Agent": {"claude-cli/2.1.310 (external, cli)"}}, "claude-code"},
		{"title beats UA", http.Header{"User-Agent": {"OpenAI/JS 4.96.0"}, "X-Title": {"Cline"}}, "cline"},
		{"referer beats UA", http.Header{"User-Agent": {"node"}, "Http-Referer": {"https://opencode.ai/"}}, "opencode"},
		{"no UA", nil, ClientUnknown},
	} {
		req := clientVia(t, s, "203.0.113.7:51000", tc.inbound, nil)
		if got := req.Header.Values(HeaderClient); len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: X-0G-Client = %v, want %q", tc.name, got, tc.want)
		}
		if req.Header.Get("User-Agent") != "" {
			t.Errorf("%s: raw User-Agent reached the outbound request", tc.name)
		}
	}
}

// A caller-sent X-0G-Client is replaced by the gateway's own verdict.
func TestStampReplacesForgedClientName(t *testing.T) {
	s := mustSigner(t, "https://router.example")
	req := clientVia(t, s, "203.0.113.7:51000",
		http.Header{"User-Agent": {"curl/8.5.0"}, HeaderClient: {"claude-code"}},
		http.Header{HeaderClient: {"claude-code"}})
	if got := req.Header.Values(HeaderClient); len(got) != 1 || got[0] != "curl" {
		t.Fatalf("X-0G-Client = %v, want [curl]", got)
	}
}

// No signed address, no name: a loopback peer, a request bound elsewhere, or a
// request made without the Middleware carries no X-0G-Client at all, and a
// caller-sent one is stripped.
func TestClientNameOnlyRidesWithSignature(t *testing.T) {
	s := mustSigner(t, "https://router.example")
	forged := http.Header{HeaderClient: {"claude-code"}}
	req := clientVia(t, s, "127.0.0.1:40000", http.Header{"User-Agent": {"curl/8.5.0"}}, forged)
	if v := req.Header.Get(HeaderClient); v != "" {
		t.Errorf("loopback peer: X-0G-Client = %q", v)
	}
	if v := stampVia(t, s, "203.0.113.7:51000", "https://broker.provider.example/v1/quote", forged).Header.Get(HeaderClient); v != "" {
		t.Errorf("broker-bound: X-0G-Client = %q", v)
	}
	bare := httptest.NewRequest(http.MethodGet, "https://router.example/x", nil)
	bare.Header.Set(HeaderClient, "claude-code")
	Stamp(bare)
	if v := bare.Header.Get(HeaderClient); v != "" {
		t.Errorf("no middleware: X-0G-Client = %q", v)
	}
}
