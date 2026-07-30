package dcap

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// recordingGetter records every URL it is asked for and returns a canned body,
// so a test can assert how many times the underlying network would be hit.
type recordingGetter struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (g *recordingGetter) Get(u string) (map[string][]string, []byte, error) {
	g.mu.Lock()
	g.calls = append(g.calls, u)
	g.mu.Unlock()
	if g.err != nil {
		return nil, nil, g.err
	}
	return map[string][]string{"X-Test": {"1"}}, []byte("body:" + u), nil
}

func (g *recordingGetter) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

const (
	tcbURL = intelPCSBase + "/tdx/certification/v4/tcb?fmspc=90c06f000000"
	qeURL  = intelPCSBase + "/sgx/certification/v4/qe/identity?update=standard"
)

func TestCachingGetter_DedupsByURL(t *testing.T) {
	rec := &recordingGetter{}
	g := newCachingGetter(time.Hour, rec)

	// Same URL fetched repeatedly (many providers sharing an FMSPC, or repeated
	// warmer sweeps) hits the network exactly once.
	for i := 0; i < 5; i++ {
		if _, body, err := g.Get(tcbURL); err != nil || string(body) != "body:"+tcbURL {
			t.Fatalf("get %d: body=%q err=%v", i, body, err)
		}
	}
	// A different URL is a separate entry.
	if _, _, err := g.Get(qeURL); err != nil {
		t.Fatalf("qe get: %v", err)
	}
	if got := rec.count(); got != 2 {
		t.Errorf("underlying fetches = %d, want 2 (one per distinct URL)", got)
	}
}

func TestCachingGetter_ExpiresAfterTTL(t *testing.T) {
	rec := &recordingGetter{}
	g := newCachingGetter(time.Hour, rec)

	if _, _, err := g.Get(tcbURL); err != nil {
		t.Fatal(err)
	}
	// Force expiry by back-dating the entry, then a second get must re-fetch.
	g.mu.Lock()
	e := g.m[tcbURL]
	e.exp = time.Now().Add(-time.Second)
	g.m[tcbURL] = e
	g.mu.Unlock()

	if _, _, err := g.Get(tcbURL); err != nil {
		t.Fatal(err)
	}
	if got := rec.count(); got != 2 {
		t.Errorf("fetches = %d, want 2 (expired entry re-fetched)", got)
	}
}

func TestCachingGetter_DoesNotCacheErrors(t *testing.T) {
	rec := &recordingGetter{err: errors.New("boom")}
	g := newCachingGetter(time.Hour, rec)

	for i := 0; i < 3; i++ {
		if _, _, err := g.Get(tcbURL); err == nil {
			t.Fatal("expected error to propagate")
		}
	}
	if got := rec.count(); got != 3 {
		t.Errorf("fetches = %d, want 3 (errors are never cached)", got)
	}
}

func TestCachingGetter_ReturnedBodyIsIsolated(t *testing.T) {
	rec := &recordingGetter{}
	g := newCachingGetter(time.Hour, rec)

	// A caller that mutates the body it got back must not corrupt the cached copy
	// that the next verification reads.
	_, body1, err := g.Get(tcbURL)
	if err != nil {
		t.Fatal(err)
	}
	for i := range body1 {
		body1[i] = 'X'
	}
	_, body2, err := g.Get(tcbURL) // served from cache
	if err != nil {
		t.Fatal(err)
	}
	if want := "body:" + tcbURL; string(body2) != want {
		t.Errorf("cache poisoned by caller mutation: got %q, want %q", body2, want)
	}
	if got := rec.count(); got != 1 {
		t.Errorf("second get should be a cache hit: fetches = %d, want 1", got)
	}
}

func TestPCCSRewriteGetter_RewritesIntelHostOnly(t *testing.T) {
	rec := &recordingGetter{}
	g := newPCCSRewriteGetter("https://pccs.phala.network/", rec) // trailing slash trimmed

	if _, _, err := g.Get(tcbURL); err != nil {
		t.Fatal(err)
	}
	// A non-Intel URL must pass through untouched.
	const other = "https://example.test/whatever"
	if _, _, err := g.Get(other); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"https://pccs.phala.network/tdx/certification/v4/tcb?fmspc=90c06f000000",
		other,
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) != 2 || rec.calls[0] != want[0] || rec.calls[1] != want[1] {
		t.Errorf("rewritten calls = %v, want %v", rec.calls, want)
	}
}

func TestEffectiveGetter_NilWhenUnconfigured(t *testing.T) {
	// No getter, no PCCS, no TTL → nil, so NewQuoteParser leaves the library
	// default in place (pre-B2 behavior).
	if g := (Config{}).effectiveGetter(); g != nil {
		t.Errorf("effectiveGetter = %v, want nil for an unconfigured Config", g)
	}
}

func TestEffectiveGetter_ComposesCacheOverRewrite(t *testing.T) {
	rec := &recordingGetter{}
	cfg := Config{Getter: rec, PCCSBaseURL: "https://pccs.phala.network", CollateralTTL: time.Hour}
	g := cfg.effectiveGetter()
	if g == nil {
		t.Fatal("effectiveGetter = nil, want a composed getter")
	}
	// Two identical fetches: cached (one underlying call) AND rewritten to PCCS.
	for i := 0; i < 2; i++ {
		if _, _, err := g.Get(tcbURL); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("underlying fetches = %d, want 1 (cache over rewrite)", got)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if want := "https://pccs.phala.network/tdx/certification/v4/tcb?fmspc=90c06f000000"; rec.calls[0] != want {
		t.Errorf("underlying URL = %q, want rewritten %q", rec.calls[0], want)
	}
}
