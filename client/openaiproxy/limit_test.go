package openaiproxy

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// blockingHandler returns a handler that parks until release is closed, plus a
// channel that reports each entry. It lets a test hold exactly N requests inside
// the limiter and then observe what happens to the next one.
func blockingHandler(release <-chan struct{}) (http.Handler, chan struct{}) {
	entered := make(chan struct{}, 64)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}), entered
}

// TestLimitInFlight_ShedsOverTheCap is the property the cap exists for: at the
// limit, the next request is refused immediately rather than admitted or queued.
func TestLimitInFlight_ShedsOverTheCap(t *testing.T) {
	release := make(chan struct{})
	h, entered := blockingHandler(release)
	srv := httptest.NewServer(LimitInFlight(2, h))
	// Defers run LIFO, and Close blocks until every in-flight request finishes —
	// so the parked handlers must be released FIRST, which means registering
	// that defer LAST.
	defer srv.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(release)

	// Fill both slots and wait until the handler really holds them — otherwise
	// the third request could win a race against a request still in transit and
	// this would test nothing.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not receive the first two requests")
		}
	}

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("third request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("over-cap request status = %d, want %d (server full, not a per-caller quota)",
			resp.StatusCode, http.StatusServiceUnavailable)
	}
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Error("a shed request must carry Retry-After so a client knows it is retryable")
	}
	// The envelope must match every other error this proxy emits, so a thin
	// client parses overload the same way it parses everything else.
	var body struct {
		Error map[string]any `json:"error"`
		ZG    struct {
			Source string `json:"source"`
		} `json:"_0g"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode shed body: %v", err)
	}
	if body.ZG.Source != "gateway" {
		t.Errorf("shed attribution = %q, want \"gateway\" (the cap is ours, not upstream's)", body.ZG.Source)
	}
	if body.Error["message"] == nil {
		t.Error("shed body must carry an error message")
	}

	// Nothing extra reached the handler: the shed request was refused, not queued.
	select {
	case <-entered:
		t.Error("over-cap request reached the handler; it must be shed, not queued")
	default:
	}
}

// TestLimitInFlight_ReleasesSlots confirms a completed request returns its slot.
// A leaked slot is permanent, so this is the failure that would strangle the
// gateway to zero capacity over time rather than showing up at once.
func TestLimitInFlight_ReleasesSlots(t *testing.T) {
	srv := httptest.NewServer(LimitInFlight(1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()

	for i := 0; i < 5; i++ {
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 — a slot was not released", i, resp.StatusCode)
		}
	}
}

// TestLimitInFlight_ReleasesSlotOnPanic covers the same invariant on the path
// that would otherwise skip the release: a handler that panics. net/http
// recovers the panic per connection, so without the deferred release the slot
// would be gone for the life of the process.
func TestLimitInFlight_ReleasesSlotOnPanic(t *testing.T) {
	var panicOnce sync.Once
	srv := httptest.NewServer(LimitInFlight(1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first := false
		panicOnce.Do(func() { first = true })
		if first {
			panic("boom")
		}
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()
	// net/http logs the recovered panic and its stack; send it nowhere so the
	// expected panic doesn't look like a failure in the test output.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)

	// The panicking request kills its connection; the error is expected.
	if resp, err := http.Get(srv.URL); err == nil {
		resp.Body.Close()
	}

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request after panic: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status after a panicking request = %d, want 200 — the panic leaked the slot", resp.StatusCode)
	}
}

// TestLimitInFlight_DisabledIsPassthrough locks in that max<=0 returns the
// handler untouched, so the load-test rig and local runs measure an unbounded
// gateway rather than one with an invisible ceiling.
func TestLimitInFlight_DisabledIsPassthrough(t *testing.T) {
	release := make(chan struct{})
	h, entered := blockingHandler(release)
	srv := httptest.NewServer(LimitInFlight(0, h))
	// Same LIFO ordering as above: release the parked handlers before Close.
	defer srv.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(release)

	// More concurrent requests than any plausible cap: with the cap off, all of
	// them must reach the handler.
	const concurrent = 4
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, err := http.Get(srv.URL); err == nil {
				resp.Body.Close()
			}
		}()
	}
	for i := 0; i < concurrent; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("with the cap disabled all %d concurrent requests must reach the handler", concurrent)
		}
	}
}
