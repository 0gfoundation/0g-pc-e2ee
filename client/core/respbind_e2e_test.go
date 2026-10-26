package core_test

// End-to-end coverage of the response binding (SPEC §7.6) through Complete and
// CompleteStream. The attack it closes: the router holds the request envelope,
// so it holds the cleartext client_eph_pub, and it can answer with a stream of
// its own sealed to it. Without the binding the client opens and delivers that
// stream frame by frame and only the §8 tail check objects, after the text was
// shown. With it the first frame does not open, so nothing is delivered.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// bindEnclave opens the sealed request the way a broker implementing §7.6 does
// (or, with ignoreBind, the way one that predates it does) and answers with a
// sealed chat response.
type bindEnclave struct {
	encPriv    crypto.PrivateKey
	ignoreBind bool

	mu       sync.Mutex
	sawBind  bool
	upstream wire.Request // the request as forwarded upstream
}

func (e *bindEnclave) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var env wire.Request
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ephPub, err := clientEphPub(env)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	opened, err := wire.OpenRequestFor(wire.ProfileChat, e.encPriv, env)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var bind []byte
	forward := opened
	if !e.ignoreBind {
		if bind, forward, err = wire.TakeResponseBind(wire.ProfileChat, opened); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	e.mu.Lock()
	e.sawBind = bind != nil
	e.upstream = forward
	e.mu.Unlock()

	var rs *wire.ResponseSealer
	if bind != nil {
		rs, err = wire.NewBoundResponseSealerFor(wire.ProfileChat, ephPub, bind)
	} else {
		rs, err = wire.NewResponseSealerFor(wire.ProfileChat, ephPub)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	serveChat(w, env, rs, "genuine")
}

// forgingRouter is the attacker: it never forwards the request, and answers with
// content of its own sealed in base mode to the request's client_eph_pub — all
// it can do without the binding value.
type forgingRouter struct{}

func (forgingRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var env wire.Request
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ephPub, err := clientEphPub(env)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rs, err := wire.NewResponseSealerFor(wire.ProfileChat, ephPub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	serveChat(w, env, rs, "FORGED")
}

// serveChat answers with three streamed frames or one buffered frame, each
// carrying content.
func serveChat(w http.ResponseWriter, env wire.Request, rs *wire.ResponseSealer, content string) {
	if !strings.Contains(string(env["stream"]), "true") {
		sealed, err := rs.SealFrame(wire.Response{
			"model":   json.RawMessage(`"gpt-4o"`),
			"usage":   json.RawMessage(`{"total_tokens":3}`),
			"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"` + content + `"}}]`),
		}, nil, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sealed)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	const n = 3
	for i := 0; i < n; i++ {
		sealed, err := rs.SealFrame(wire.Response{
			"model":   json.RawMessage(`"gpt-4o"`),
			"choices": json.RawMessage(`[{"index":0,"delta":{"content":"` + content + `"}}]`),
		}, nil, i == n-1)
		if err != nil {
			return
		}
		b, _ := json.Marshal(sealed)
		fmt.Fprintf(w, "data: %s\n\n", b)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
}

// listCandidates serves a fixed candidate list, best first.
type listCandidates []core.Provider

func (l listCandidates) Len() int { return len(l) }
func (l listCandidates) Provider(_ context.Context, i int) (core.Provider, error) {
	return l[i], nil
}

type listResolver listCandidates

func (l listResolver) Resolve(context.Context, endpoint.Endpoint, wire.Request) (core.Candidates, error) {
	return listCandidates(l), nil
}

// newEnclave starts a bindEnclave and returns it with the Provider that seals to
// it.
func newEnclave(t *testing.T, ignoreBind, bindResponse bool) (*bindEnclave, core.Provider) {
	t.Helper()
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &bindEnclave{encPriv: encPriv, ignoreBind: ignoreBind}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	return e, core.Provider{
		URL:          srv.URL + "/v1/chat/completions",
		EncPubKey:    encPub,
		SignerAddr:   "0x0000000000000000000000000000000000000001",
		BindResponse: bindResponse,
	}
}

// newForgingRouter starts a forgingRouter in front of a provider whose key it
// does not hold.
func newForgingRouter(t *testing.T, bindResponse bool) core.Provider {
	t.Helper()
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(forgingRouter{})
	t.Cleanup(srv.Close)
	return core.Provider{
		URL:          srv.URL + "/v1/chat/completions",
		EncPubKey:    encPub,
		SignerAddr:   "0x0000000000000000000000000000000000000001",
		BindResponse: bindResponse,
	}
}

// collect runs CompleteStream and returns every delivered frame's choices.
func collect(t *testing.T, c *core.Client) (string, error) {
	t.Helper()
	var got strings.Builder
	err := c.CompleteStream(context.Background(), chatReq(true), func(f wire.Response) error {
		got.Write(f["choices"])
		return nil
	})
	return got.String(), err
}

// The genuine path: the binding rides sealed, the enclave strips it before the
// upstream call, and the bound response opens.
func TestE2E_ResponseBind_GenuineProvider(t *testing.T) {
	e, prov := newEnclave(t, false, true)
	c := core.New(prov)

	got, err := collect(t, c)
	if err != nil {
		t.Fatalf("bound stream: %v", err)
	}
	if strings.Count(got, "genuine") != 3 {
		t.Fatalf("delivered %q, want three genuine frames", got)
	}
	e.mu.Lock()
	sawBind, upstream := e.sawBind, e.upstream
	e.mu.Unlock()
	if !sawBind {
		t.Fatal("the enclave received no _bind")
	}
	if _, ok := upstream["_bind"]; ok {
		t.Fatal("_bind reached the upstream request")
	}

	out, err := c.Complete(context.Background(), chatReq(false))
	if err != nil {
		t.Fatalf("bound buffered response: %v", err)
	}
	if !strings.Contains(string(out["choices"]), "genuine") {
		t.Fatalf("choices = %s", out["choices"])
	}
}

// Without the binding, a substituted stream is delivered — the status quo this
// test pins so the next one has something to be contrasted with.
func TestE2E_ResponseBind_UnboundClientDeliversASubstitutedStream(t *testing.T) {
	c := core.New(newForgingRouter(t, false))
	got, err := collect(t, c)
	if err != nil {
		t.Fatalf("unbound stream: %v", err)
	}
	if !strings.Contains(got, "FORGED") {
		t.Fatalf("precondition: an unbound client should deliver the forged stream, got %q", got)
	}
}

// The acceptance test of issue #169: a router that substitutes the stream gets
// nothing through to the caller — the first frame is refused, so no byte of it
// is delivered.
func TestE2E_ResponseBind_SubstitutedStreamDeliversNothing(t *testing.T) {
	c := core.New(newForgingRouter(t, true))
	got, err := collect(t, c)
	if err == nil {
		t.Fatal("a substituted stream was accepted by a bound client")
	}
	if got != "" {
		t.Fatalf("forged bytes reached the caller: %q", got)
	}
	if !strings.Contains(err.Error(), "§7.6") {
		t.Fatalf("error does not name the response binding: %v", err)
	}

	if _, err := c.Complete(context.Background(), chatReq(false)); err == nil {
		t.Fatal("a substituted buffered response was accepted by a bound client")
	}
}

// Refused before the first frame is delivered, so the stream is not committed
// and the walk falls back: the next candidate answers, and the caller sees only
// its frames.
func TestE2E_ResponseBind_SubstitutedStreamFallsBack(t *testing.T) {
	_, genuine := newEnclave(t, false, true)
	c := core.NewWithResolver(listResolver{newForgingRouter(t, true), genuine})
	got, err := collect(t, c)
	if err != nil {
		t.Fatalf("stream with a fallback: %v", err)
	}
	if strings.Contains(got, "FORGED") {
		t.Fatalf("forged bytes reached the caller: %q", got)
	}
	if strings.Count(got, "genuine") != 3 {
		t.Fatalf("delivered %q, want the fallback's three frames", got)
	}
}

// A provider that does not implement §7.6 but was marked as binding fails
// closed: its base-mode response is refused like a forged one. This is why the
// flag is set only from what the provider itself advertises.
func TestE2E_ResponseBind_ProviderIgnoringTheBindFailsClosed(t *testing.T) {
	_, prov := newEnclave(t, true, true)
	got, err := collect(t, core.New(prov))
	if err == nil {
		t.Fatal("a base-mode response was accepted on a bound request")
	}
	if got != "" {
		t.Fatalf("bytes reached the caller: %q", got)
	}
}

// Without BindResponse nothing is attached: a provider not known to implement
// §7.6 is sealed to exactly as before.
func TestE2E_ResponseBind_NotAttachedWithoutTheFlag(t *testing.T) {
	e, prov := newEnclave(t, false, false)
	if _, err := collect(t, core.New(prov)); err != nil {
		t.Fatalf("unbound stream: %v", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sawBind {
		t.Fatal("_bind was attached for a provider not marked as binding")
	}
}
