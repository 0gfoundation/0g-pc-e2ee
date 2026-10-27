package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// What a stale-key 409 looks like on the wire: the broker's own body, and the same
// body after the router normalized it into the OpenAI / Anthropic error envelopes.
const (
	brokerMismatchBody    = `{"error":"e2ee_key_mismatch: sealed request key_id \"old\" is not the enclave's current enc key (current \"new\"); re-fetch the enc key and re-seal"}`
	routerMismatchBody    = `{"error":{"message":"e2ee_key_mismatch: sealed request key_id \"old\" is not the enclave's current enc key","type":"api_error","metadata":{"raw":"{}"}},"x_0g_trace":{"request_id":"r"}}`
	anthropicMismatchBody = `{"type":"error","error":{"message":"e2ee_key_mismatch: stale","type":"api_error"}}`
)

func TestIsKeyMismatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"broker body", http.StatusConflict, brokerMismatchBody, true},
		{"router-normalized body", http.StatusConflict, routerMismatchBody, true},
		{"anthropic envelope", http.StatusConflict, anthropicMismatchBody, true},
		{"another 409", http.StatusConflict, `{"error":{"message":"conflict","type":"api_error"}}`, false},
		{"token not at the start", http.StatusConflict, `{"error":"upstream said e2ee_key_mismatch"}`, false},
		{"token on a 400", http.StatusBadRequest, brokerMismatchBody, false},
		{"not JSON", http.StatusConflict, `e2ee_key_mismatch`, false},
		{"empty", http.StatusConflict, ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &Error{Stage: StageUpstream, Status: tc.status, Err: errors.New("x"), Body: tc.body}
			if got := isKeyMismatch(err); got != tc.want {
				t.Errorf("isKeyMismatch = %v, want %v", got, tc.want)
			}
		})
	}
	if isKeyMismatch(errors.New("e2ee_key_mismatch")) {
		t.Error("a bare error is not a provider reply")
	}
}

// keyedProvider answers an async submit with a stale-key 409 while the envelope is
// sealed to a key it does not hold, and accepts it otherwise. alwaysStale makes
// every attempt stale, as a forged or looping 409 would.
type keyedProvider struct {
	current     crypto.PublicKey
	alwaysStale bool
	conflict    string // the 409 body; brokerMismatchBody when empty
	addr        string
	hits        int32
}

func (p *keyedProvider) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&p.hits, 1)
		body, _ := io.ReadAll(r.Body)
		if p.alwaysStale || !bytes.Contains(body, []byte(keyIDOf(t, p.current))) {
			msg := p.conflict
			if msg == "" {
				msg = brokerMismatchBody
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, msg)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"jobId":"job-1","status":"pending","provider_address":"`+p.addr+`"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// keyIDOf is the envelope key_id a request sealed to pub carries (SPEC §5:
// base64url(SHA-256(enc_pub)[0:8])).
func keyIDOf(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func newKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// refreshingCandidates is a candidate list whose refresh hands back fresh[i] — the
// key a re-verification would find.
type refreshingCandidates struct {
	list  []Provider
	fresh []crypto.PublicKey

	mu     sync.Mutex
	stales []crypto.PublicKey
}

func (c *refreshingCandidates) Len() int { return len(c.list) }
func (c *refreshingCandidates) Provider(_ context.Context, i int) (Provider, error) {
	return c.list[i], nil
}

func (c *refreshingCandidates) RefreshProvider(_ context.Context, i int, stale crypto.PublicKey) (Provider, error) {
	c.mu.Lock()
	c.stales = append(c.stales, stale)
	c.mu.Unlock()
	p := c.list[i]
	p.EncPubKey = c.fresh[i]
	return p, nil
}

func (c *refreshingCandidates) refreshes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.stales)
}

func asyncClient(cands Candidates, h *countingHook) *Client {
	return NewWithResolver(fixedResolver{cands}, WithEndpoint(endpoint.AsyncImage), WithMetrics(h))
}

// The case this exists for: the broker rotated its key while our quote cache still
// held the old one. The request is re-sealed to the re-read key and sent to the
// SAME provider — not handed to the caller as a 409, and not moved to another
// candidate, which would have nothing to do with the provider's key.
func TestStaleKeyIsResealedToTheSameProvider(t *testing.T) {
	current := newKey(t)
	a := &keyedProvider{current: current, addr: "0xA"}
	b := &keyedProvider{current: newKey(t), addr: "0xB"}
	stale := asyncCandidate(t, a.server(t), "0xA")
	cands := &refreshingCandidates{
		list:  []Provider{stale, asyncCandidate(t, b.server(t), "0xB")},
		fresh: []crypto.PublicKey{current, nil},
	}
	h := &countingHook{}

	if _, _, err := asyncClient(cands, h).SubmitAsync(context.Background(), asyncSubmitReq()); err != nil {
		t.Fatalf("SubmitAsync: %v", err)
	}
	if got := atomic.LoadInt32(&a.hits); got != 2 {
		t.Errorf("provider A hits = %d, want 2 (the stale attempt, then the re-sealed one)", got)
	}
	if got := atomic.LoadInt32(&b.hits); got != 0 {
		t.Errorf("provider B hits = %d, want 0 — a stale key is no reason to change provider", got)
	}
	if len(cands.stales) != 1 || !bytes.Equal(cands.stales[0], stale.EncPubKey) {
		t.Errorf("refresh was asked about %x, want exactly the rejected key %x", cands.stales, stale.EncPubKey)
	}
	if h.keyRefresh[KeyRefreshResealed] != 1 {
		t.Errorf("key refresh outcomes = %v, want one %q", h.keyRefresh, KeyRefreshResealed)
	}
	if len(h.fallbacks) != 0 {
		t.Errorf("fallbacks = %v, want none", h.fallbacks)
	}
}

// The router normalizes the broker's body into an error envelope; the re-seal must
// still fire on what the gateway actually receives.
func TestStaleKeyIsResealedFromTheRouterNormalizedBody(t *testing.T) {
	current := newKey(t)
	a := &keyedProvider{current: current, addr: "0xA", conflict: routerMismatchBody}
	cands := &refreshingCandidates{
		list:  []Provider{asyncCandidate(t, a.server(t), "0xA")},
		fresh: []crypto.PublicKey{current},
	}
	if _, _, err := asyncClient(cands, &countingHook{}).SubmitAsync(context.Background(), asyncSubmitReq()); err != nil {
		t.Fatalf("SubmitAsync: %v", err)
	}
	if got := atomic.LoadInt32(&a.hits); got != 2 {
		t.Errorf("provider hits = %d, want 2", got)
	}
}

// One re-seal per candidate per request, however many 409s come back: the body is
// untrusted, and a router that kept answering 409 must not hold the request in a
// loop of key re-reads.
func TestStaleKeyIsResealedAtMostOnce(t *testing.T) {
	a := &keyedProvider{alwaysStale: true, addr: "0xA"}
	b := &keyedProvider{current: newKey(t), addr: "0xB"}
	bProv := asyncCandidate(t, b.server(t), "0xB")
	b.current = bProv.EncPubKey
	cands := &refreshingCandidates{
		list:  []Provider{asyncCandidate(t, a.server(t), "0xA"), bProv},
		fresh: []crypto.PublicKey{newKey(t), newKey(t)},
	}
	h := &countingHook{}

	if _, _, err := asyncClient(cands, h).SubmitAsync(context.Background(), asyncSubmitReq()); err != nil {
		t.Fatalf("SubmitAsync: %v", err)
	}
	if got := atomic.LoadInt32(&a.hits); got != 2 {
		t.Errorf("provider A hits = %d, want 2 (one re-seal, then give up on it)", got)
	}
	if got := atomic.LoadInt32(&b.hits); got != 1 {
		t.Errorf("provider B hits = %d, want 1 — an unrecoverable stale key falls back", got)
	}
	if cands.refreshes() != 1 {
		t.Errorf("refreshes = %d, want 1", cands.refreshes())
	}
	if h.fallbacks[FallbackUpstream] != 1 {
		t.Errorf("fallbacks = %v, want one %q", h.fallbacks, FallbackUpstream)
	}
}

// A re-read that comes back with the very key the provider rejected leaves nothing
// to re-seal to. Sending the same envelope again would only earn the same 409, so
// the walk moves on — and that outcome is the one a forged 409 produces.
func TestUnchangedKeyFallsBackWithoutResending(t *testing.T) {
	a := &keyedProvider{alwaysStale: true, addr: "0xA"}
	b := &keyedProvider{addr: "0xB"}
	aProv := asyncCandidate(t, a.server(t), "0xA")
	bProv := asyncCandidate(t, b.server(t), "0xB")
	b.current = bProv.EncPubKey
	cands := &refreshingCandidates{
		list:  []Provider{aProv, bProv},
		fresh: []crypto.PublicKey{aProv.EncPubKey, nil},
	}
	h := &countingHook{}

	if _, _, err := asyncClient(cands, h).SubmitAsync(context.Background(), asyncSubmitReq()); err != nil {
		t.Fatalf("SubmitAsync: %v", err)
	}
	if got := atomic.LoadInt32(&a.hits); got != 1 {
		t.Errorf("provider A hits = %d, want 1 — nothing changed, so nothing to resend", got)
	}
	if got := atomic.LoadInt32(&b.hits); got != 1 {
		t.Errorf("provider B hits = %d, want 1", got)
	}
	if h.keyRefresh[KeyRefreshUnchanged] != 1 {
		t.Errorf("key refresh outcomes = %v, want one %q", h.keyRefresh, KeyRefreshUnchanged)
	}
}

// A candidate list that cannot re-read keys (a static provider) still treats the
// stale key as the provider's problem: it falls back rather than ending the walk.
func TestStaleKeyWithoutARefresherFallsBack(t *testing.T) {
	a := &keyedProvider{alwaysStale: true, addr: "0xA"}
	b := &keyedProvider{addr: "0xB"}
	bProv := asyncCandidate(t, b.server(t), "0xB")
	b.current = bProv.EncPubKey
	h := &countingHook{}

	_, _, err := asyncClient(listCandidates{asyncCandidate(t, a.server(t), "0xA"), bProv}, h).
		SubmitAsync(context.Background(), asyncSubmitReq())
	if err != nil {
		t.Fatalf("SubmitAsync: %v", err)
	}
	if got := atomic.LoadInt32(&b.hits); got != 1 {
		t.Errorf("provider B hits = %d, want 1", got)
	}
	if h.keyRefresh[KeyRefreshUnsupported] != 1 {
		t.Errorf("key refresh outcomes = %v, want one %q", h.keyRefresh, KeyRefreshUnsupported)
	}
}

// Any other 409 keeps its old meaning — a client fault, terminal, surfaced as is.
func TestOtherConflictIsStillTerminal(t *testing.T) {
	a := &keyedProvider{alwaysStale: true, addr: "0xA", conflict: `{"error":{"message":"conflict","type":"api_error"}}`}
	b := &keyedProvider{addr: "0xB"}
	cands := &refreshingCandidates{
		list:  []Provider{asyncCandidate(t, a.server(t), "0xA"), asyncCandidate(t, b.server(t), "0xB")},
		fresh: []crypto.PublicKey{newKey(t), newKey(t)},
	}

	_, _, err := asyncClient(cands, &countingHook{}).SubmitAsync(context.Background(), asyncSubmitReq())
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusConflict {
		t.Fatalf("err = %v, want the provider's 409", err)
	}
	if atomic.LoadInt32(&b.hits) != 0 || cands.refreshes() != 0 {
		t.Errorf("B hits = %d, refreshes = %d; want neither", b.hits, cands.refreshes())
	}
}
