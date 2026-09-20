package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Single-flight must not quietly switch itself off when the map is full — which
// is precisely when the load it exists for is highest.
//
// The cap is a bound on what is STORED. It was also, accidentally, a bound on
// what could be SHARED: an entry that did not go into the map could not be found
// by anyone, so concurrent readers of one key each became their own leader. The
// comments claimed the opposite in two places ("served and shared in flight"),
// which is the worst kind of wrong — the reader has no reason to check.
//
// And a full map is not only an attacker's doing. /v1/models takes repeatable
// filters, so ordinary query diversity reaches the cap; an attacker trying to
// HOLD it full would need >1500 upstream req/min and would hit the router's
// limit long before this degradation mattered.
func TestSingleFlightSurvivesAFullMap(t *testing.T) {
	const callers = 20
	release := make(chan struct{})
	var once sync.Once
	cr := &countingRouter{}
	cr.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("shared") != "" {
			once.Do(func() { <-release })
		}
		return true
	}
	router := cr.server()
	defer router.Close()

	cache := newCatalogCache(10 * time.Second)
	srv := httptest.NewServer(cache.wrap(newRouterProxy(mustURL(t, router.URL), discardLogger())))
	defer srv.Close()

	// Fill the stored map with live entries, so a new key cannot be published.
	for i := 0; i < catalogCacheMaxEntries; i++ {
		getBody(t, fmt.Sprintf("%s/v1/models?junk=%d", srv.URL, i))
	}

	before := cr.hits.Load()
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			getBody(t, srv.URL+"/v1/models?shared=1")
		}()
	}
	time.Sleep(200 * time.Millisecond) // let them all pile onto the one key
	close(release)
	wg.Wait()

	if got := cr.hits.Load() - before; got != 1 {
		t.Errorf("router saw %d concurrent requests for one key with the map full, want 1: "+
			"single-flight is load-bearing and must not switch off exactly when key "+
			"cardinality — and so load — is highest", got)
	}
}

// A key that made it into the settled map keeps serving from cache even while
// the map is at the cap.
//
// This started as an attempt to reproduce a separate report: settle deleting by
// key unconditionally, so an UNPUBLISHED leader could remove the entry a later
// leader had published. It never reproduced on its own, and the reason is that
// it was not separate — it needs two leaders alive on one key at once, which is
// exactly the bug above. With in-flight keys discoverable, the second caller
// joins the first instead of becoming a rival leader, and settle releases only
// the inflight key it provably owns, so the aliasing has no way to occur.
//
// The test stays for the part that is still observable and still worth pinning.
func TestUnpublishedLeaderDoesNotEvictAnotherLeadersEntry(t *testing.T) {
	cr := &countingRouter{}
	router := cr.server()
	defer router.Close()

	cache := newCatalogCache(10 * time.Second)
	srv := httptest.NewServer(cache.wrap(newRouterProxy(mustURL(t, router.URL), discardLogger())))
	defer srv.Close()

	for i := 0; i < catalogCacheMaxEntries; i++ {
		getBody(t, fmt.Sprintf("%s/v1/models?junk=%d", srv.URL, i))
	}
	// Free exactly one slot, so the first request for `late` publishes.
	cache.mu.Lock()
	for k := range cache.entries {
		delete(cache.entries, k)
		break
	}
	cache.mu.Unlock()

	getBody(t, srv.URL+"/v1/models?late=1") // publishes
	before := cr.hits.Load()
	for i := 0; i < 3; i++ {
		getBody(t, srv.URL+"/v1/models?late=1")
	}
	if got := cr.hits.Load() - before; got != 0 {
		t.Errorf("router saw %d requests for a published key, want 0: an unpublished leader's "+
			"delete-by-key removed an entry it never owned", got)
	}
}

// A replayed response must not clobber headers this request's own middleware
// set — and Vary: Origin is the one that matters, because dropping it invites a
// shared cache to serve one origin's Access-Control-Allow-Origin to another.
//
// The setup is ordinary, not contrived: the leader is a request with no Origin
// (an SDK or a poller), and the upstream sends its own Vary — any compressing
// ingress sends Vary: Accept-Encoding, and the router's gin-contrib/cors sends
// Vary: Origin. StripCORSHeaders removes Access-Control-* and deliberately not
// Vary, so the snapshot carries the upstream's. Then a browser request hits the
// cache: CORS adds Vary: Origin just before the mux, and the replay assigns over
// it.
func TestReplayKeepsThisRequestsVary(t *testing.T) {
	cr := &countingRouter{}
	cr.extra = func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Vary", "Accept-Encoding") // a compressing ingress
		return true
	}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	// Leader: no Origin, so CORS adds nothing and the snapshot is the upstream's.
	if _, _, err := rawGet(gw.URL + "/v1/models"); err != nil {
		t.Fatalf("leader: %v", err)
	}

	// A browser on an allowed origin now hits the cache.
	req, _ := http.NewRequest(http.MethodGet, gw.URL+"/v1/models", nil)
	req.Header.Set("Origin", testOrigins()[0])
	tr := &http.Transport{DisableCompression: true, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("browser request: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != testOrigins()[0] {
		t.Fatalf("Access-Control-Allow-Origin = %q, want the request's origin — the rest of "+
			"this test only matters when the response is origin-specific", got)
	}
	var sawOrigin bool
	for _, v := range resp.Header.Values("Vary") {
		for _, part := range splitAndTrim(v) {
			if http.CanonicalHeaderKey(part) == "Origin" {
				sawOrigin = true
			}
		}
	}
	if !sawOrigin {
		t.Errorf("Vary = %v on an origin-specific cached response, want it to include Origin: "+
			"replaying over this request's Vary lets a shared cache hand one origin's "+
			"Access-Control-Allow-Origin to another", resp.Header.Values("Vary"))
	}
}

// The snapshot must come from the UPSTREAM response only. It used to read the
// live ResponseWriter's map, which the outer CORS middleware has already written
// into — so a request-specific header could be captured and then replayed to
// everybody. Today the allowlist limits the blast radius to Vary; the point is
// that it should not depend on the allowlist at all.
func TestSnapshotDoesNotCaptureOuterMiddlewareHeaders(t *testing.T) {
	var served atomic.Int64
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	cache := newCatalogCache(10 * time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			w.Header().Add("Vary", "Origin")
		}
		cache.wrap(upstream).ServeHTTP(w, r)
	}))
	defer srv.Close()

	// Leader HAS an Origin, so the writer's map holds Vary: Origin when the
	// snapshot is taken.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/models", nil)
	req.Header.Set("Origin", "https://leader.example")
	tr := &http.Transport{DisableCompression: true, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("leader: %v", err)
	}
	resp.Body.Close()

	cache.mu.Lock()
	var snapshot http.Header
	for _, e := range cache.entries {
		snapshot = e.header
	}
	cache.mu.Unlock()
	if snapshot == nil {
		t.Fatal("nothing was cached")
	}
	if got := snapshot.Values("Vary"); len(got) != 0 {
		t.Errorf("the cached snapshot carries Vary %v, which the OUTER middleware set for one "+
			"request: the snapshot must hold upstream response headers only, so a future "+
			"allowlist entry cannot smuggle a per-request header into the cache", got)
	}
}

func splitAndTrim(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			for len(part) > 0 && (part[0] == ' ' || part[0] == '\t') {
				part = part[1:]
			}
			for len(part) > 0 && (part[len(part)-1] == ' ' || part[len(part)-1] == '\t') {
				part = part[:len(part)-1]
			}
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}
