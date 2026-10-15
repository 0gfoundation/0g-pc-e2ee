package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// The async poll route as the gateway mounts it (SPEC §7.5.4): which handler a
// poll reaches is decided by its job id, not by the seal policy or model list.

// A real-shaped user job id: broker id + "." + 43-char key segment.
const keyedJobID = "job-1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

type pollRouter struct {
	mu   sync.Mutex
	seen []string
	body string
}

func (p *pollRouter) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.URL.String())
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, p.body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pollGateway(t *testing.T, routerURL string, logger *slog.Logger) *httptest.Server {
	gw := httptest.NewServer(newHandler(sealedClients(routeClient(), nil), mustURL(t, routerURL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, logger))
	t.Cleanup(gw.Close)
	return gw
}

func getPoll(t *testing.T, gw *httptest.Server, id string, credential bool) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/v1/async/jobs/"+id+"?provider_address=0xabc", nil)
	if credential {
		req.Header.Set("Authorization", "Bearer sk-user-key")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// A keyless poll is the cleartext passthrough: relayed verbatim, marked none.
func TestKeylessPollIsRelayedInTheClear(t *testing.T) {
	router := &pollRouter{body: `{"jobId":"job-1","status":"completed","data":{"data":[{"b64_json":"eA=="}]}}`}
	gw := pollGateway(t, router.server(t).URL, discardLogger())

	resp, body := getPoll(t, gw, "job-1", true)
	if resp.StatusCode != http.StatusOK || body != router.body {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueNone {
		t.Errorf("X-0G-E2EE = %q, want none", got)
	}
}

// A keyless poll answered with a sealed frame is refused: without the key it
// cannot be opened, and relaying it would present ciphertext as a result.
func TestKeylessPollRefusesASealedFrame(t *testing.T) {
	router := &pollRouter{body: `{"jobId":"job-1","status":"completed","_e2ee":{"v":1,"ciphertext":"Y3Q"}}`}
	gw := pollGateway(t, router.server(t).URL, discardLogger())

	resp, body := getPoll(t, gw, "job-1", true)
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "Y3Q") {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
}

// A keyed poll goes through the sealed gate: refused without a credential, and
// with one it reaches the router with the key segment cut off.
func TestKeyedPollGoesThroughTheGate(t *testing.T) {
	router := &pollRouter{body: `{"jobId":"job-1","status":"pending"}`}
	gw := pollGateway(t, router.server(t).URL, discardLogger())

	if resp, _ := getPoll(t, gw, keyedJobID, false); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no credential: %d, want 401", resp.StatusCode)
	}
	resp, body := getPoll(t, gw, keyedJobID, true)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, keyedJobID) {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueSealed {
		t.Errorf("X-0G-E2EE = %q, want sealed", got)
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if len(router.seen) != 1 || router.seen[0] != "/v1/async/jobs/job-1?provider_address=0xabc" {
		t.Errorf("router saw %v", router.seen)
	}
}

// The access log never carries a polled job's key segment.
func TestAccessLogRedactsTheJobKey(t *testing.T) {
	router := &pollRouter{body: `{"jobId":"job-1","status":"pending"}`}
	var buf bytes.Buffer
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(lockedWriter{&buf, &mu}, nil))
	gw := pollGateway(t, router.server(t).URL, logger)

	getPoll(t, gw, keyedJobID, true)
	getPoll(t, gw, "job-1.not-a-valid-key", true)
	mu.Lock()
	defer mu.Unlock()
	key := keyedJobID[strings.LastIndex(keyedJobID, ".")+1:]
	if strings.Contains(buf.String(), key) || strings.Contains(buf.String(), "not-a-valid-key") {
		t.Errorf("access log carries a key segment:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "/v1/async/jobs/job-1.<redacted>") {
		t.Errorf("access log does not record the redacted path:\n%s", buf.String())
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// The keyless check cannot be skipped by asking for a compressed answer: the
// caller's Accept-Encoding is not forwarded, so a router that compresses
// whenever asked still has its answer read as JSON before it is relayed.
func TestKeylessPollCheckSurvivesAcceptEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := []byte(`{"status":"completed","_e2ee":{"v":1}}`)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write(body)
			_ = zw.Close()
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	gw := pollGateway(t, srv.URL, discardLogger())
	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/v1/async/jobs/job-1", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d, want 502: a compressed sealed frame was relayed unchecked", resp.StatusCode)
	}
}

// A router that answers in an encoding nobody asked for — one the transport
// does not undo, unlike the gzip it requests itself — is not relayed unchecked.
func TestKeylessPollRefusesAnUnrequestedEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		zw, _ := flate.NewWriter(w, flate.DefaultCompression)
		_, _ = zw.Write([]byte(`{"status":"completed","_e2ee":{"v":1}}`))
		_ = zw.Close()
	}))
	t.Cleanup(srv.Close)
	gw := pollGateway(t, srv.URL, discardLogger())
	resp, _ := getPoll(t, gw, "job-1", true)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d, want 502", resp.StatusCode)
	}
}
