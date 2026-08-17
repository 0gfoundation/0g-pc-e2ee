package chain

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeRegistry struct {
	mu     sync.Mutex
	signer string
	ack    bool
	err    error
	calls  int
	// block, when non-nil, holds each lookup until it is closed — used to keep
	// several callers in flight at once so singleflight coalescing is observable.
	block chan struct{}
}

func (f *fakeRegistry) AcknowledgedSigner(context.Context, string) (Signer, error) {
	f.mu.Lock()
	f.calls++
	block, err, signer, ack := f.block, f.err, f.signer, f.ack
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	if err != nil {
		return Signer{}, err
	}
	return Signer{Address: signer, Acknowledged: ack}, nil
}

func (f *fakeRegistry) RefreshSigner(ctx context.Context, providerAddr string) (Signer, error) {
	return f.AcknowledgedSigner(ctx, providerAddr)
}

func (f *fakeRegistry) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeRegistry) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeRegistry) setSigner(signer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signer = signer
}

// newTestCache builds a cachedRegistry with a controllable clock.
func newTestCache(inner SignerRegistry, ttl, grace time.Duration, now *time.Time) *cachedRegistry {
	return &cachedRegistry{
		inner:   inner,
		ttl:     ttl,
		grace:   grace,
		entries: map[string]cacheEntry{},
		now:     func() time.Time { return *now },
	}
}

func TestCached_HitWithinTTL(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	for i := 0; i < 3; i++ {
		got, err := c.AcknowledgedSigner(context.Background(), "0xProvider")
		if err != nil || got.Address != "0xabc" || !got.Acknowledged {
			t.Fatalf("call %d: got (%+v, %v)", i, got, err)
		}
		if got.Stale {
			t.Errorf("call %d: fresh entry reported Stale", i)
		}
	}
	if inner.callCount() != 1 {
		t.Errorf("inner called %d times, want 1 (cached)", inner.callCount())
	}
}

func TestCached_Expiry(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // past TTL
	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	if inner.callCount() != 2 {
		t.Errorf("inner called %d times, want 2 (expired)", inner.callCount())
	}
}

func TestCached_ErrorsNotCached(t *testing.T) {
	inner := &fakeRegistry{err: errors.New("rpc down")}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	for i := 0; i < 2; i++ {
		if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
			t.Fatal("want error")
		}
	}
	if inner.callCount() != 2 {
		t.Errorf("inner called %d times, want 2 (errors not cached)", inner.callCount())
	}
}

// A refresh failure after the TTL lapses must serve the expired value rather than
// fail the caller — the whole point of the grace window, since an RPC outage
// would otherwise fail every candidate of every request.
func TestCached_StaleServedWithinGrace(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, 30*time.Minute, &now)

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	inner.setErr(errors.New("rpc down"))
	now = now.Add(5 * time.Minute) // past TTL, inside grace

	got, err := c.AcknowledgedSigner(context.Background(), "0xP")
	if err != nil {
		t.Fatalf("want stale value served, got error: %v", err)
	}
	if got.Address != "0xabc" || !got.Acknowledged {
		t.Errorf("stale value = %+v, want the last known-good entry", got)
	}
	if !got.Stale {
		t.Error("value served past TTL must be marked Stale")
	}
}

func TestCached_StaleExpiresAfterGrace(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, 10*time.Minute, &now)

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	inner.setErr(errors.New("rpc down"))
	now = now.Add(time.Minute + 10*time.Minute + time.Second) // past TTL + grace

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
		t.Error("want error once the grace window has lapsed")
	}
}

func TestCached_ZeroGraceDisablesStale(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, 0, &now)

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	inner.setErr(errors.New("rpc down"))
	now = now.Add(2 * time.Minute)

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
		t.Error("want error with the grace window disabled")
	}
}

// RefreshSigner is the caller's route to evidence it may act negatively on, so it
// must never hand back a stale entry — even when one is available and the live
// read fails.
func TestCached_RefreshNeverServesStale(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, 30*time.Minute, &now)

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	inner.setErr(errors.New("rpc down"))
	now = now.Add(5 * time.Minute) // inside grace: AcknowledgedSigner would serve stale

	if _, err := c.RefreshSigner(context.Background(), "0xP"); err == nil {
		t.Error("RefreshSigner must fail rather than serve a stale entry")
	}
}

// RefreshSigner bypasses a still-fresh entry: it must observe a rotation the
// cache has not yet picked up.
func TestCached_RefreshBypassesFreshEntry(t *testing.T) {
	inner := &fakeRegistry{signer: "0xold", ack: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	inner.setSigner("0xnew")

	got, err := c.RefreshSigner(context.Background(), "0xP")
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "0xnew" {
		t.Errorf("RefreshSigner = %s, want the live value 0xnew", got.Address)
	}
	if got.Stale {
		t.Error("a live read must not be marked Stale")
	}
	// And the refresh updates the cache, so the next ordinary lookup agrees.
	next, err := c.AcknowledgedSigner(context.Background(), "0xP")
	if err != nil {
		t.Fatal(err)
	}
	if next.Address != "0xnew" {
		t.Errorf("cached value after refresh = %s, want 0xnew", next.Address)
	}
}

// Concurrent misses for one provider must collapse into a single RPC, so a TTL
// expiry under load cannot stampede an endpoint that may already be struggling.
func TestCached_SingleflightCollapsesConcurrentMisses(t *testing.T) {
	block := make(chan struct{})
	inner := &fakeRegistry{signer: "0xabc", ack: true, block: block}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = c.AcknowledgedSigner(context.Background(), "0xP")
		}()
	}
	// Give the goroutines a moment to pile onto the same key, then release them.
	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	if got := inner.callCount(); got != 1 {
		t.Errorf("inner called %d times, want 1 (singleflighted)", got)
	}
}

// One caller's cancellation must not fail the shared lookup for the others.
func TestCached_CancelledCallerDoesNotDoomOthers(t *testing.T) {
	block := make(chan struct{})
	inner := &fakeRegistry{signer: "0xabc", ack: true, block: block}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := c.AcknowledgedSigner(leaderCtx, "0xP")
		leaderDone <- err
	}()
	time.Sleep(20 * time.Millisecond)

	followerDone := make(chan error, 1)
	go func() {
		_, err := c.AcknowledgedSigner(context.Background(), "0xP")
		followerDone <- err
	}()
	time.Sleep(20 * time.Millisecond)

	cancelLeader()
	if err := <-leaderDone; err == nil {
		t.Error("cancelled caller should see its own context error")
	}
	close(block)
	if err := <-followerDone; err != nil {
		t.Errorf("follower failed because another caller cancelled: %v", err)
	}
}

func TestCached_ZeroTTLDisables(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	c := Cached(inner, 0, DefaultGrace)
	if c != SignerRegistry(inner) {
		t.Error("Cached with non-positive TTL should return the inner registry unchanged")
	}
}
