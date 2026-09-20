package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// truncatingRouter writes a valid status line, headers and the first bytes of a
// JSON body, then kills the connection. This is the shape of a router that
// crashes, gets OOM-killed, or has its connection reset mid-response — and it is
// the shape a cache must never retain, because the prefix is a syntactically
// plausible catalog.
func truncatingRouter(t *testing.T, prefix string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, prefix)
		w.(http.Flusher).Flush()
		// Rip the TCP connection out from under the response. Hijack after a flush
		// is the only way to produce a genuinely truncated body: returning normally
		// would let net/http finish the chunked encoding cleanly.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // RST, not FIN — a clean close can read as a complete body
		}
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A response the gateway never received in full must not be served to anyone,
// and must not become the cached catalog for a whole TTL.
//
// The "only cache 200" guard does not cover this: the status line said 200 long
// before the body died. And a truncated JSON catalog is WORSE than the 500 that
// guard was written for — a 500 is visibly an error, while `{"data":[{"id":` is
// charged to the catalog itself.
func TestTruncatedUpstreamResponseIsNeverCached(t *testing.T) {
	const prefix = `{"data":[{"id":"model-a"`
	router := truncatingRouter(t, prefix)
	gw := catalogGateway(t, router, entryPolicy{})

	// The leader sees the abort as a transport error, which is correct and is not
	// what this test is about.
	if _, _, err := rawGet(gw.URL + "/v1/models"); err == nil {
		t.Log("leader completed without a transport error; the assertion below is what matters")
	}

	// The next caller must NOT be handed the leader's truncated bytes.
	status, body, err := rawGet(gw.URL + "/v1/models")
	if err == nil && status == http.StatusOK && strings.HasPrefix(body, prefix) && len(body) == len(prefix) {
		t.Fatalf("second caller got the leader's TRUNCATED body as a complete 200 (%q): a "+
			"response that never arrived in full was cached as the catalog", body)
	}
}

// The same root cause, one step earlier: if the leader panics before writing
// anything, the entry keeps status 0, and every waiter PARKED ON IT replays that
// — calling WriteHeader(0), which panics inside each waiter's own handler.
//
// The waiters have to be concurrent for this to bite. A caller arriving after
// the leader has settled finds the entry already deleted and becomes a fresh
// leader, so a sequential version of this test passes while the bug is wide
// open.
func TestLeaderPanicBeforeAnyWriteDoesNotPoisonWaiters(t *testing.T) {
	arrived := make(chan struct{})
	var once sync.Once
	var served atomic.Int64
	panicky := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1) == 1 {
			// Park so the waiters can pile onto this entry, then fail the way
			// ReverseProxy does when the round trip produces no response at all.
			once.Do(func() { close(arrived) })
			time.Sleep(250 * time.Millisecond)
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	cache := newCatalogCache(10 * time.Second)
	srv := httptest.NewServer(cache.wrap(panicky))
	defer srv.Close()

	go func() { _, _, _ = rawGet(srv.URL + "/v1/models") }()
	<-arrived
	time.Sleep(50 * time.Millisecond) // let the leader be established

	var wg sync.WaitGroup
	statuses := make([]int, 3)
	bodies := make([]string, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, body, err := rawGet(srv.URL + "/v1/models")
			if err != nil {
				statuses[i] = -1
				bodies[i] = err.Error()
				return
			}
			statuses[i], bodies[i] = status, body
		}(i)
	}
	wg.Wait()

	for i := range statuses {
		if statuses[i] != http.StatusOK || bodies[i] != `{"ok":true}` {
			t.Errorf("waiter %d got %d %q, want a fresh 200: a leader that wrote nothing leaves "+
				"status 0, and replaying it is WriteHeader(0)", i, statuses[i], bodies[i])
		}
	}
}

// A body shorter than its declared Content-Length is truncated whether or not
// anything panicked, and must not be cached either.
//
// This is the independent half of the truncation check, and it is independent
// on purpose. The panic detection above relies on ReverseProxy choosing to
// panic, which it decides with an unexported heuristic
// (shouldPanicOnCopyError: only when it can tell it is under an http.Server).
// That is true for this gateway today, and it is not a promise — if it ever
// stopped panicking, `completed` would be true and a poisoned catalog would be
// cached again, silently. Comparing the bytes we hold against the length the
// upstream declared does not depend on any of that.
func TestShortBodyAgainstDeclaredContentLengthIsNotCached(t *testing.T) {
	var served atomic.Int64
	short := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "999") // a claim it then does not meet
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"data":[`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	cache := newCatalogCache(10 * time.Second)
	srv := httptest.NewServer(cache.wrap(short))
	defer srv.Close()

	_, _, _ = rawGet(srv.URL + "/v1/models") // the short one
	status, body, err := rawGet(srv.URL + "/v1/models")
	if err != nil {
		t.Fatalf("second caller: %v", err)
	}
	if status != http.StatusOK || body != `{"ok":true}` {
		t.Errorf("second caller got %d %q, want a fresh 200: a body shorter than its declared "+
			"Content-Length is truncated and must not be retained", status, body)
	}
}

// 256 one-shot queries must not disable the cache for good. Expired entries are
// only ever deleted when their own key is asked for again, so without a sweep
// the map stays full of dead keys and the cap test fails for every new key —
// handing back the single shared per-IP budget this whole thing exists to avoid,
// for 256 requests and until the next restart.
func TestCacheSurvivesAFloodOfOneShotQueries(t *testing.T) {
	cr := &countingRouter{}
	router := cr.server()
	defer router.Close()

	cache := newCatalogCache(10 * time.Second)
	now := time.Now()
	cache.now = func() time.Time { return now }
	srv := httptest.NewServer(cache.wrap(newRouterProxy(mustURL(t, router.URL), discardLogger())))
	defer srv.Close()

	// Flood: every key distinct, each asked for exactly once.
	for i := 0; i < catalogCacheMaxEntries; i++ {
		getBody(t, fmt.Sprintf("%s/v1/models?junk=%d", srv.URL, i))
	}

	// Long after they have all expired, ordinary traffic must cache again.
	now = now.Add(time.Hour)
	before := cr.hits.Load()
	for i := 0; i < 5; i++ {
		getBody(t, srv.URL+"/v1/models")
	}
	if got := cr.hits.Load() - before; got != 1 {
		t.Errorf("router saw %d requests for 5 identical reads an hour after the flood, want 1: "+
			"%d one-shot queries permanently disabled the cache", got, catalogCacheMaxEntries)
	}
	cache.mu.Lock()
	n := len(cache.entries)
	cache.mu.Unlock()
	if n >= catalogCacheMaxEntries {
		t.Errorf("cache still holds %d entries, all expired: nothing ever reclaims them", n)
	}
}

// The leader's client hanging up must not fail everyone sharing its request.
// Pressing stop, or a phone changing networks, is ordinary; and because errors
// are not cached, an attacker who connects and aborts wins the leader slot
// almost every time.
func TestLeaderDisconnectDoesNotFailTheWaiters(t *testing.T) {
	release := make(chan struct{})
	atRouter := make(chan struct{})
	var once sync.Once
	cr := &countingRouter{}
	cr.extra = func(w http.ResponseWriter, _ *http.Request) bool {
		once.Do(func() {
			close(atRouter)
			<-release
		})
		return true
	}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	// The leader: starts the request, then gives up on it.
	leaderCtx, abandonLeader := context.WithCancel(context.Background())
	leaderReq, _ := http.NewRequestWithContext(leaderCtx, http.MethodGet, gw.URL+"/v1/models", nil)
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		// The SAME transport settings the waiters use. Content coding is part of
		// the cache key, so a leader whose client auto-negotiates gzip while the
		// waiters do not lands in a different bucket and shares nothing — which
		// makes this test pass while proving nothing.
		tr := &http.Transport{DisableCompression: true, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		resp, err := tr.RoundTrip(leaderReq)
		if err == nil {
			resp.Body.Close()
		}
	}()

	// Wait until the leader's upstream request is genuinely parked in the router,
	// then pile the waiters onto its entry.
	<-atRouter
	var wg sync.WaitGroup
	statuses := make([]int, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, _, err := rawGet(gw.URL + "/v1/models")
			if err != nil {
				statuses[i] = -1
				return
			}
			statuses[i] = status
		}(i)
	}
	time.Sleep(150 * time.Millisecond)

	// The leader walks away while its shared upstream request is still in flight.
	// Give the cancellation time to reach the gateway's OUTBOUND round trip before
	// letting the router answer — otherwise the response wins the race and the bug
	// hides.
	abandonLeader()
	<-leaderDone
	time.Sleep(250 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, s := range statuses {
		if s != http.StatusOK {
			t.Errorf("waiter %d got %d, want 200: it would have got 200 with no cache at all — "+
				"the leader's client hanging up must not cancel the request they share", i, s)
		}
	}
}

// rawGet issues a GET without the conveniences that would hide a truncated
// body: no automatic retry, no transparent decompression, and a read error
// surfaced rather than swallowed.
func rawGet(url string) (int, string, error) {
	tr := &http.Transport{DisableCompression: true, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}
