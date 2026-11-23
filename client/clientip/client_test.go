package clientip

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

	// Every title and referer rule has a vector that only it can decide (the
	// other header empty, and a UA that does not name the same family), and
	// every User-Agent rule a vector it is the first to match, so neither copy
	// of the rules can lose or change one without its own side's vector test
	// failing (and the shared file then tells the other side what changed).
	for _, r := range clientTitleRules {
		for _, p := range r.titlePrefixes {
			found := false
			for _, v := range doc.Vectors {
				if v.Referer == "" && strings.ToLower(strings.TrimSpace(v.Title)) == p && v.Client == r.client && uaFamily(v.UserAgent) != r.client {
					found = true
				}
			}
			if !found {
				t.Errorf("no vector with title %q alone (want %q)", p, r.client)
			}
		}
		found := false
		for _, v := range doc.Vectors {
			if v.Title == "" && refererHostname(v.Referer) == r.refererDomain && v.Client == r.client && uaFamily(v.UserAgent) != r.client {
				found = true
			}
		}
		if !found {
			t.Errorf("no vector with referer %q alone (want %q)", r.refererDomain, r.client)
		}
	}
}

func TestSharedVectorsCoverEveryUARule(t *testing.T) {
	raw, err := os.ReadFile("testdata/client_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			UserAgent string `json:"user_agent"`
			Title     string `json:"title"`
			Referer   string `json:"referer"`
			Client    string `json:"client"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	covered := make([]bool, len(clientUARules))
	for _, v := range doc.Vectors {
		if v.Title != "" || v.Referer != "" {
			continue
		}
		ua := strings.ToLower(strings.TrimSpace(v.UserAgent))
		for i, r := range clientUARules {
			if (r.prefix && strings.HasPrefix(ua, r.needle)) || (!r.prefix && strings.Contains(ua, r.needle)) {
				covered[i] = covered[i] || v.Client == r.client
				break
			}
		}
	}
	for i, r := range clientUARules {
		if !covered[i] {
			t.Errorf("no vector is first matched by User-Agent rule %q (want %q)", r.needle, r.client)
		}
	}
}

func TestRefererHostname(t *testing.T) {
	for in, want := range map[string]string{
		"":                              "",
		"https://cline.bot":             "cline.bot",
		"HTTPS://Cline.Bot:443/x?y#z":   "cline.bot",
		"charm.land/crush":              "charm.land",
		"https://user:pw@dify.ai/":      "dify.ai",
		"https://cline.bot@example.com": "example.com",
		"https://dify.ai./":             "dify.ai",
		"charm.land/?u=https://x.com":   "charm.land",
	} {
		if got := refererHostname(in); got != want {
			t.Errorf("refererHostname(%q) = %q, want %q", in, got, want)
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

// uaFamily is what the User-Agent alone would say.
func uaFamily(ua string) string { return classifyUA(strings.ToLower(strings.TrimSpace(ua))) }
