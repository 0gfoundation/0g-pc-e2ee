package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// countingRouter answers every request with a body that says which request it
// was, so a test can tell a fresh upstream answer from a replayed one without
// reading a counter — the body itself is the evidence.
type countingRouter struct {
	hits atomic.Int64
	// extra runs before the body is written, for a case that needs a specific
	// status or header.
	extra func(w http.ResponseWriter, r *http.Request) bool
}

func (cr *countingRouter) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := cr.hits.Add(1)
		if cr.extra != nil && !cr.extra(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"hit":%d}`, n)
	}))
}

func catalogGateway(t *testing.T, router *httptest.Server, policy entryPolicy) *httptest.Server {
	t.Helper()
	gw := httptest.NewServer(newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger(), withEntryPolicy(policy)))
	t.Cleanup(gw.Close)
	return gw
}

func getBody(t *testing.T, url string) (int, string, http.Header) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

// The whole point: repeated catalog reads cost the router one request, because
// its per-IP budget is one budget for everybody once this gateway is the only
// public name.
func TestCatalogReadsAreServedFromOneUpstreamRequest(t *testing.T) {
	cr := &countingRouter{}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	for path := range cacheableCatalogPaths {
		t.Run(path, func(t *testing.T) {
			before := cr.hits.Load()
			var bodies []string
			for i := 0; i < 5; i++ {
				status, body, hdr := getBody(t, gw.URL+path)
				if status != http.StatusOK {
					t.Fatalf("status = %d, want 200 (body %s)", status, body)
				}
				// A cached response must still carry the cleartext marker: it is set
				// by MarkE2EE outside the cache, so a hit that lost it would mean the
				// cache had been mounted in the wrong place.
				if got := hdr.Get(openaiproxy.HeaderE2EE); got != openaiproxy.E2EEValueNone {
					t.Errorf("%s = %q on request %d, want %q", openaiproxy.HeaderE2EE, got, i, openaiproxy.E2EEValueNone)
				}
				if got := hdr.Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type = %q on request %d, want it replayed", got, i)
				}
				bodies = append(bodies, body)
			}
			if got := cr.hits.Load() - before; got != 1 {
				t.Errorf("router saw %d requests for %s, want 1: the per-IP budget is shared by "+
					"every user once this gateway is the only public name", got, path)
			}
			for i, b := range bodies {
				if b != bodies[0] {
					t.Errorf("request %d body %q != first %q", i, b, bodies[0])
				}
			}
		})
	}
}

// A path NOT on the allowlist must reach the router every time. This is the
// half that keeps the cache from becoming a correctness bug: the passthrough is
// a catch-all, so anything the router mounts next arrives here, and some of it
// is per-user.
func TestUnlistedPathsAreNeverCached(t *testing.T) {
	cr := &countingRouter{}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	for _, path := range []string{
		"/v1/account/balance", // authenticated and per-user — the dangerous shape
		"/v1/models/extra",    // a sub-path of a cached one is not the cached one
		"/v1/api-keys",
		"/anything-else",
	} {
		t.Run(path, func(t *testing.T) {
			before := cr.hits.Load()
			for i := 0; i < 3; i++ {
				if status, body, _ := getBody(t, gw.URL+path); status != http.StatusOK {
					t.Fatalf("status = %d (body %s)", status, body)
				}
			}
			if got := cr.hits.Load() - before; got != 3 {
				t.Errorf("router saw %d requests for %s, want 3: only the explicit allowlist may "+
					"be cached, or one user's response reaches another", got, path)
			}
		})
	}
}

// Only GET. A POST to a cached path is a different operation with a body, and
// replaying a stored GET for it would answer the wrong question.
func TestCatalogCacheIgnoresNonGET(t *testing.T) {
	cr := &countingRouter{}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	for i := 0; i < 3; i++ {
		resp, err := http.Post(gw.URL+"/v1/models", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}
	if got := cr.hits.Load(); got != 3 {
		t.Errorf("router saw %d POSTs, want 3", got)
	}
}

// Distinct query strings are distinct answers. /v1/models takes filters, so
// collapsing them would serve a filtered catalog to a caller that asked for the
// whole one.
func TestCatalogCacheKeysOnQuery(t *testing.T) {
	cr := &countingRouter{}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	_, first, _ := getBody(t, gw.URL+"/v1/models?input_modality=text")
	_, second, _ := getBody(t, gw.URL+"/v1/models?input_modality=image")
	_, firstAgain, _ := getBody(t, gw.URL+"/v1/models?input_modality=text")

	if first == second {
		t.Errorf("two different queries returned the same body %q", first)
	}
	if firstAgain != first {
		t.Errorf("repeat of the first query returned %q, want the cached %q", firstAgain, first)
	}
	if got := cr.hits.Load(); got != 2 {
		t.Errorf("router saw %d requests, want 2 (one per distinct query)", got)
	}
}

// A non-200 must not be retained. A router blip would otherwise be pinned in
// front of the catalog for a whole TTL — turning a one-request failure into a
// ten-second outage for everybody.
func TestCatalogCacheDoesNotRetainErrors(t *testing.T) {
	cr := &countingRouter{}
	var fail atomic.Bool
	fail.Store(true)
	cr.extra = func(w http.ResponseWriter, _ *http.Request) bool {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
			return false
		}
		return true
	}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	if status, _, _ := getBody(t, gw.URL+"/v1/models"); status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want the router's 500 passed through", status)
	}
	fail.Store(false)
	if status, body, _ := getBody(t, gw.URL+"/v1/models"); status != http.StatusOK {
		t.Errorf("status = %d (body %s), want 200: the 500 must not have been cached", status, body)
	}
	if got := cr.hits.Load(); got != 2 {
		t.Errorf("router saw %d requests, want 2", got)
	}
}

// Single-flight. Without it the cache does not solve the problem it exists for:
// at every expiry the whole waiting population misses at once and goes upstream
// together, which is the exact burst the router's one shared bucket cannot take.
func TestConcurrentCatalogMissesCollapseToOneUpstreamRequest(t *testing.T) {
	const callers = 50
	release := make(chan struct{})
	cr := &countingRouter{}
	cr.extra = func(w http.ResponseWriter, _ *http.Request) bool {
		// Hold the first (and, if single-flight is broken, every) request open so
		// all the callers are genuinely in flight at the same moment.
		<-release
		return true
	}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	var wg sync.WaitGroup
	bodies := make([]string, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, body, _ := getBody(t, gw.URL+"/v1/models")
			bodies[i] = body
		}(i)
	}
	// Give them time to pile up on the same key before the upstream answers.
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := cr.hits.Load(); got != 1 {
		t.Errorf("router saw %d concurrent requests, want 1: %d callers missing together is the "+
			"herd the shared per-IP budget cannot absorb", got, callers)
	}
	for i, b := range bodies {
		if b != bodies[0] {
			t.Errorf("caller %d got %q, want the shared %q", i, b, bodies[0])
		}
	}
}

// An expired entry refetches, and a disabled cache never caches at all.
func TestCatalogCacheTTLExpiryAndDisable(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		cr := &countingRouter{}
		router := cr.server()
		defer router.Close()
		// Build the handler with a policy, then reach into the cache's clock: the
		// alternative is sleeping out a real TTL in a unit test.
		cache := newCatalogCache(10 * time.Second)
		now := time.Now()
		cache.now = func() time.Time { return now }
		wrapped := cache.wrap(newRouterProxy(mustURL(t, router.URL), discardLogger()))
		srv := httptest.NewServer(wrapped)
		defer srv.Close()

		getBody(t, srv.URL+"/v1/models")
		getBody(t, srv.URL+"/v1/models")
		if got := cr.hits.Load(); got != 1 {
			t.Fatalf("router saw %d requests before expiry, want 1", got)
		}
		now = now.Add(11 * time.Second)
		getBody(t, srv.URL+"/v1/models")
		if got := cr.hits.Load(); got != 2 {
			t.Errorf("router saw %d requests after expiry, want 2", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		cr := &countingRouter{}
		router := cr.server()
		defer router.Close()
		gw := catalogGateway(t, router, entryPolicy{catalogCacheTTL: -1})
		for i := 0; i < 3; i++ {
			getBody(t, gw.URL+"/v1/models")
		}
		if got := cr.hits.Load(); got != 3 {
			t.Errorf("router saw %d requests with the cache disabled, want 3", got)
		}
	})
}

// The zero entryPolicy must be the ordinary deployment, caching included —
// entryPolicy's own contract. A duration field whose zero means "off" would
// quietly hand every test, and any future call site, a gateway shape nothing
// deploys.
func TestZeroPolicyCachesAndFlagZeroDisables(t *testing.T) {
	if c := (entryPolicy{}).newCatalogCache(); c == nil {
		t.Error("the zero entryPolicy has no catalog cache; its zero value must be the ordinary deployment")
	} else if c.ttl != defaultCatalogCacheTTL {
		t.Errorf("zero policy TTL = %v, want the default %v", c.ttl, defaultCatalogCacheTTL)
	}
	if c := (entryPolicy{catalogCacheTTL: disabledIfZero(0)}).newCatalogCache(); c != nil {
		t.Error("-catalog-cache-ttl=0 must disable the cache; the flag's 0 and the policy's 0 mean different things")
	}
	if c := (entryPolicy{catalogCacheTTL: disabledIfZero(30 * time.Second)}).newCatalogCache(); c == nil || c.ttl != 30*time.Second {
		t.Errorf("an explicit TTL must pass through unchanged, got %+v", c)
	}
}

// The cache must never sit in front of a sealed surface's namespace, which
// carries prompts under -unsealed-subtree=passthrough. Two POSTs with different
// bodies must reach the router as two distinct requests — if either the mount
// point or the allowlist ever let one of these be cached, the second caller
// would receive the first caller's completion.
func TestSealedNamespacePassthroughIsNeverCached(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{unsealedSubtree: unsealedSubtreePassthrough})

	var sent []string
	for _, ep := range endpoint.All {
		for _, body := range []string{`{"prompt":"first"}`, `{"prompt":"second"}`} {
			req, _ := http.NewRequest(http.MethodPost, gw.URL+ep.Path+"/count_tokens", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post %s: %v", ep.Path, err)
			}
			resp.Body.Close()
			sent = append(sent, body)
		}
	}
	_, _, bodies := rr.snapshot()
	if len(bodies) != len(sent) {
		t.Fatalf("router saw %d prompt requests, want %d: a cache in the namespace path would "+
			"serve one caller's completion to another", len(bodies), len(sent))
	}
	for i, got := range bodies {
		if got != sent[i] {
			t.Errorf("router request %d body = %q, want %q", i, got, sent[i])
		}
	}
}

// gzip is negotiated per caller, so it is part of the key. The property that
// matters is what the CLIENT can read: a cached gzip body handed to a client
// that did not ask for it is undecodable, and that is the bug this guards.
//
// Asserted on the response rather than on what the router saw, because the
// router's view is only visible on a MISS — replay drops upstream headers by
// design — so an assertion there would silently be testing the first request
// only.
func TestCatalogCacheKeysOnGzipAcceptance(t *testing.T) {
	cr := &countingRouter{}
	cr.extra = func(w http.ResponseWriter, r *http.Request) bool {
		// Compress only when the caller asked, exactly as a real upstream would,
		// so a cached gzip body reaching an identity client would be detectable.
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = fmt.Fprintf(gz, `{"hit":%d}`, cr.hits.Load())
			_ = gz.Close()
			return false
		}
		return true
	}
	router := cr.server()
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	// DisableCompression: otherwise the client adds and transparently strips its
	// own gzip, hiding the very coding under test.
	tr := &http.Transport{DisableCompression: true}
	do := func(accept string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, gw.URL+"/v1/models", nil)
		req.Header.Set("Accept-Encoding", accept)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("get with Accept-Encoding=%q: %v", accept, err)
		}
		return resp
	}
	readJSON := func(resp *http.Response) string {
		t.Helper()
		defer resp.Body.Close()
		r := io.Reader(resp.Body)
		if resp.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(resp.Body)
			if err != nil {
				t.Fatalf("response claims gzip but does not decode: %v", err)
			}
			defer gz.Close()
			r = gz
		}
		body, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.HasPrefix(string(body), `{"hit":`) {
			t.Fatalf("body %q is not the JSON the router sent — it was handed to a client "+
				"that cannot decode it", body)
		}
		return string(body)
	}

	// Two spellings of "I accept gzip" must share one entry, and both must get a
	// body they can actually decode.
	var gzipBodies []string
	for _, accept := range []string{"gzip, deflate", "gzip, deflate, br, zstd"} {
		resp := do(accept)
		if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
			t.Errorf("Content-Encoding = %q for client %q, want gzip preserved", got, accept)
		}
		gzipBodies = append(gzipBodies, readJSON(resp))
	}
	if gzipBodies[0] != gzipBodies[1] {
		t.Errorf("gzip spellings got different bodies %q / %q", gzipBodies[0], gzipBodies[1])
	}
	if got := cr.hits.Load(); got != 1 {
		t.Errorf("router saw %d requests for two gzip-accepting clients, want 1: spelling "+
			"variants must not shard the cache", got)
	}

	// A client that does not accept gzip is a separate entry, and must NOT be
	// handed the cached gzip bytes.
	resp := do("identity")
	if got := resp.Header.Get("Content-Encoding"); got == "gzip" {
		t.Error("a client that did not accept gzip was served gzip: the coding must be part of the key")
	}
	readJSON(resp)
	if got := cr.hits.Load(); got != 2 {
		t.Errorf("router saw %d requests total, want 2 (gzip and identity are distinct bodies)", got)
	}
}

func TestAcceptsGzip(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", false},
		{"gzip", true},
		{"gzip, deflate", true},
		{" GZIP ;q=1.0", true},
		{"br, zstd", false},
		{"identity", false},
		{"gzip;q=0", false},
		{"deflate, gzip;q=0.5", true},
		{"ungzip", false},
	} {
		if got := acceptsGzip(tc.in); got != tc.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
