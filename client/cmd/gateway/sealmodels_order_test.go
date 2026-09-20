package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
)

// countingBody reports how many bytes of a request body were actually read.
// The whole question in this file is ORDERING, and the only way to see it is to
// watch who pulls the bytes.
type countingBody struct {
	remaining int
	read      atomic.Int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > c.remaining {
		n = c.remaining
	}
	for i := range p[:n] {
		p[i] = 'x'
	}
	c.remaining -= n
	c.read.Add(int64(n))
	return n, nil
}

func (c *countingBody) Close() error { return nil }

// A request the credential gate will refuse must be refused BEFORE its body is
// read. The per-model dispatcher buffers to find the model, and buffering has to
// sit behind the gate rather than in front of it.
//
// LimitInFlight's own contract says a request "rejected on shape alone" must not
// consume a slot, and the same reasoning covers memory: computeMaxInFlight
// derives the process ceiling from how many requests can be buffering at once,
// which is only true while nothing buffers ahead of the gate. There is no
// ReadTimeout on these servers (only ReadHeaderTimeout) and no global
// MaxBytesHandler, so a slow body fed in a byte at a time could otherwise hold
// buffer indefinitely while holding no slot and carrying no credential.
//
// This could only ever bite a deployment with a model list configured, since the
// dispatcher is not mounted otherwise — which is exactly why it needs a test
// rather than a reading.
func TestCredentiallessRequestBodyIsNeverBuffered(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()

	h := newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger(),
		withEntryPolicy(entryPolicy{sealModels: parseSealModels(sealedModel)}))

	body := &countingBody{remaining: 9 << 20}
	req := httptest.NewRequest(http.MethodPost, endpoint.Chat.Path, body)
	req.Header.Set("Content-Type", "application/json")
	// No Authorization and no x-api-key: refused on shape alone.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — this case is about what happens BEFORE the 401", w.Code)
	}
	if got := body.read.Load(); got != 0 {
		t.Errorf("the gateway read %d bytes of an unauthenticated request's body, want 0: "+
			"buffering to find the model must sit BEHIND the credential gate, or an "+
			"unauthenticated caller makes the process hold bytes it can never attribute "+
			"to anyone", got)
	}
}

// Same invariant one layer down: a request the concurrency cap sheds must not
// have been buffered either. The cap is what the memory ceiling is computed
// from, so a request over it has by definition no budget to buffer in.
//
// The slot is held by a request the dispatcher routes to the CLEARTEXT branch,
// which doubles as the assertion that that branch is inside the limiter too. It
// buffers exactly as much as the sealed one, so leaving it outside would put the
// same memory outside the ceiling by another door.
func TestShedRequestBodyIsNeverBuffered(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{})
	var once sync.Once
	cr := &countingRouter{}
	cr.extra = func(w http.ResponseWriter, _ *http.Request) bool {
		once.Do(func() { close(arrived); <-release })
		return true
	}
	router := cr.server()
	defer router.Close()

	// One slot for the whole gateway.
	h := newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		1, nil, nil, nil, discardLogger(),
		withEntryPolicy(entryPolicy{sealModels: parseSealModels(sealedModel)}))

	// An unlisted model → cleartext branch → parks in the router, holding the slot.
	var holder sync.WaitGroup
	holder.Add(1)
	go func() {
		defer holder.Done()
		req := httptest.NewRequest(http.MethodPost, endpoint.Chat.Path,
			strings.NewReader(modelBody("some-other-model")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-user-key")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()
	<-arrived

	body := &countingBody{remaining: 9 << 20}
	req := httptest.NewRequest(http.MethodPost, endpoint.Chat.Path, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	close(release)
	holder.Wait()

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: the one slot is held by the parked request, which "+
			"also means the cleartext branch must be inside the limiter", w.Code)
	}
	if got := body.read.Load(); got != 0 {
		t.Errorf("the gateway read %d bytes of a SHED request's body, want 0: the in-flight "+
			"cap is where the memory ceiling comes from, so nothing may buffer ahead of it", got)
	}
}
