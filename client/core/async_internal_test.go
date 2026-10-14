package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

type listCandidates []Provider

func (l listCandidates) Len() int { return len(l) }
func (l listCandidates) Provider(_ context.Context, i int) (Provider, error) {
	return l[i], nil
}

// asyncProvider answers an async submit with status, recording the envelope's
// client_eph_pub so a test can tell attempts apart.
type asyncProvider struct {
	status int
	addr   string
	mu     sync.Mutex
	ephs   []string
}

func (p *asyncProvider) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		_ = json.Unmarshal(body, &env)
		meta, _ := env.E2EE()
		p.mu.Lock()
		p.ephs = append(p.ephs, meta.ClientEphPub)
		p.mu.Unlock()
		if p.status != http.StatusAccepted {
			http.Error(w, `{"error":{"message":"busy"}}`, p.status)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"jobId":"job-2","status":"pending","provider_address":"`+p.addr+`"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func asyncCandidate(t *testing.T, srv *httptest.Server, addr string) Provider {
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	return Provider{URL: srv.URL, EncPubKey: encPub, Address: addr,
		SignerAddr: "0x000000000000000000000000000000000000dEaD"}
}

func asyncSubmitReq() wire.Request {
	return wire.Request{
		"model":           json.RawMessage(`"z-image"`),
		"prompt":          json.RawMessage(`"p"`),
		"response_format": json.RawMessage(`"b64_json"`),
	}
}

// A transient failure falls back to the next candidate, re-sealed under a fresh
// response key: the key is what the job id carries, so it is never reused
// across two jobs.
func TestSubmitAsyncFallsBackWithAFreshKey(t *testing.T) {
	busy := &asyncProvider{status: http.StatusTooManyRequests}
	ok := &asyncProvider{status: http.StatusAccepted, addr: "0xB"}
	c := NewWithResolver(fixedResolver{listCandidates{
		asyncCandidate(t, busy.server(t), "0xA"),
		asyncCandidate(t, ok.server(t), "0xB"),
	}}, WithEndpoint(endpoint.AsyncImage))

	out, status, err := c.SubmitAsync(context.Background(), asyncSubmitReq())
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("SubmitAsync: %d %v", status, err)
	}
	var id string
	_ = json.Unmarshal(out["jobId"], &id)
	if !strings.HasPrefix(id, "job-2.") {
		t.Errorf("jobId = %q", id)
	}
	if len(busy.ephs) != 1 || len(ok.ephs) != 1 || busy.ephs[0] == ok.ephs[0] {
		t.Errorf("attempts used keys %v / %v, want one fresh key each", busy.ephs, ok.ephs)
	}
}

// A 4xx is the caller's and recurs on every candidate: no fallback.
func TestSubmitAsyncDoesNotFallBackOnA4xx(t *testing.T) {
	bad := &asyncProvider{status: http.StatusBadRequest}
	next := &asyncProvider{status: http.StatusAccepted, addr: "0xB"}
	c := NewWithResolver(fixedResolver{listCandidates{
		asyncCandidate(t, bad.server(t), "0xA"),
		asyncCandidate(t, next.server(t), "0xB"),
	}}, WithEndpoint(endpoint.AsyncImage))

	_, _, err := c.SubmitAsync(context.Background(), asyncSubmitReq())
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusBadRequest {
		t.Fatalf("err = %v, want the 400", err)
	}
	if len(next.ephs) != 0 {
		t.Error("a 4xx must not fall back")
	}
}

// Only an async surface submits.
func TestSubmitAsyncRefusesASyncSurface(t *testing.T) {
	c := NewWithResolver(fixedResolver{listCandidates{}}, WithEndpoint(endpoint.Image))
	if _, _, err := c.SubmitAsync(context.Background(), asyncSubmitReq()); err == nil {
		t.Fatal("a sync surface must not submit")
	}
}
