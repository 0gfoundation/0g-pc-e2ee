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
		inner:    inner,
		ttl:      ttl,
		grace:    grace,
		cooldown: FailureCooldown,
		entries:  map[string]cacheEntry{},
		failures: map[string]failure{},
		now:      func() time.Time { return *now },
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

// A failure never becomes a cached VALUE — nothing is stored to be served as
// though it were a reading. It does start a cooldown, so the retry comes on the
// next request after that lapses rather than immediately; the point is that the
// registry never begins answering from a failed lookup, at any distance in time.
func TestCached_ErrorsNeverBecomeCachedValues(t *testing.T) {
	inner := &fakeRegistry{err: errors.New("rpc down")}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	for i := 0; i < 2; i++ {
		if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
			t.Fatal("want error")
		}
		now = now.Add(FailureCooldown + time.Second)
	}
	if inner.callCount() != 2 {
		t.Errorf("inner called %d times, want 2 (a lapsed cooldown retries)", inner.callCount())
	}
	if _, ok := c.load("0xp"); ok {
		t.Error("a failed lookup must not leave a cache entry behind")
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

// The grace window prevents FAILURE; the cooldown prevents COST. Without it every
// request during an outage pays the inner registry's full retry budget before
// falling back to the stale value, which for a per-candidate lookup on the request
// path is seconds of hang per request.
func TestCached_CooldownSkipsLiveCallsDuringAnOutage(t *testing.T) {
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, 30*time.Minute, &now)
	c.cooldown = FailureCooldown

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	inner.setErr(errors.New("rpc down"))
	now = now.Add(2 * time.Minute) // past TTL, inside grace

	// First call after expiry attempts the chain and falls back to the stale entry.
	if got, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil || !got.Stale {
		t.Fatalf("first call: got (%+v, %v), want the stale entry", got, err)
	}
	attempts := inner.callCount()

	// Subsequent calls inside the cooldown must answer from the stale entry without
	// touching the chain at all.
	for i := 0; i < 3; i++ {
		got, err := c.AcknowledgedSigner(context.Background(), "0xP")
		if err != nil || !got.Stale || got.Address != "0xabc" {
			t.Fatalf("call %d: got (%+v, %v), want the stale entry", i, got, err)
		}
	}
	if inner.callCount() != attempts {
		t.Errorf("inner called %d more times during the cooldown, want 0",
			inner.callCount()-attempts)
	}

	// Past the cooldown it probes again, so a recovery is picked up.
	now = now.Add(FailureCooldown + time.Second)
	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	if inner.callCount() <= attempts {
		t.Error("want a fresh probe once the cooldown lapsed")
	}
}

// With no cached entry to fall back on, the cooldown still applies: failing fast
// beats hanging for the retry budget on every request.
func TestCached_CooldownWithoutAStaleEntryFailsFast(t *testing.T) {
	inner := &fakeRegistry{err: errors.New("rpc down")}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, 30*time.Minute, &now)
	c.cooldown = FailureCooldown

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
		t.Fatal("want error")
	}
	if got := inner.callCount(); got != 1 {
		t.Fatalf("inner called %d times, want 1", got)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
			t.Fatal("want the remembered error")
		}
	}
	if got := inner.callCount(); got != 1 {
		t.Errorf("inner called %d times, want 1 (cooldown suppresses the retries)", got)
	}
}

// A success ends the outage for that provider, so the next expiry must go straight
// to a live read rather than waiting out a cooldown that no longer applies.
func TestCached_SuccessClearsTheCooldown(t *testing.T) {
	inner := &fakeRegistry{err: errors.New("rpc down")}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, 30*time.Minute, &now)
	c.cooldown = FailureCooldown

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
		t.Fatal("want error")
	}
	inner.setErr(nil)
	inner.setSigner("0xabc")
	now = now.Add(FailureCooldown + time.Second)
	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	// Entry is fresh now; expire it and confirm the next lookup reads through
	// immediately rather than being suppressed by the old failure mark.
	now = now.Add(2 * time.Minute)
	before := inner.callCount()
	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err != nil {
		t.Fatal(err)
	}
	if inner.callCount() != before+1 {
		t.Error("a success should have cleared the failure mark")
	}
}

// RefreshSigner is the evidence path: it must reach the chain even mid-outage,
// because the alternative is condemning a provider on no evidence.
func TestCached_RefreshIgnoresTheCooldown(t *testing.T) {
	inner := &fakeRegistry{err: errors.New("rpc down")}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, 30*time.Minute, &now)
	c.cooldown = FailureCooldown

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
		t.Fatal("want error")
	}
	before := inner.callCount()
	if _, err := c.RefreshSigner(context.Background(), "0xP"); err == nil {
		t.Fatal("want error")
	}
	if inner.callCount() != before+1 {
		t.Error("RefreshSigner must attempt the chain despite the cooldown")
	}
}

// A caller that gives up mid-lookup must not stamp a cooldown on the provider.
// refresh returns the CALLER's ctx.Err() when its context ends, which says nothing
// about the chain — but recorded as a failure it would make unrelated requests skip
// the live lookup and answer "context canceled" for someone else's disconnect.
//
// TestCached_CancelledCallerDoesNotDoomOthers covers the concurrent follower, which
// shares the in-flight result; this covers the caller that arrives AFTER, which
// would have been served from the failure map instead of joining anything.
func TestCached_CancelledCallerDoesNotPoisonTheCooldown(t *testing.T) {
	block := make(chan struct{})
	inner := &fakeRegistry{signer: "0xabc", ack: true, block: block}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	// A: starts a live lookup, then disconnects while it is in flight.
	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan error, 1)
	go func() {
		_, err := c.AcknowledgedSigner(ctxA, "0xP")
		doneA <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancelA()
	if err := <-doneA; err == nil {
		t.Fatal("A should see its own cancellation")
	}

	// B: an unrelated request arriving afterwards, on a cold cache. It must reach
	// the chain rather than inherit A's cancellation from the cooldown.
	close(block)
	got, err := c.AcknowledgedSigner(context.Background(), "0xP")
	if err != nil {
		t.Fatalf("B got %v (want the lookup's result); is it A's cancellation? %v",
			err, errors.Is(err, context.Canceled))
	}
	if got.Address != "0xabc" || !got.Acknowledged {
		t.Errorf("B got %+v, want the looked-up signer", got)
	}
}

// The guard must not swallow a GENUINE failure that happens to be observed by a
// caller whose context is still live — that is the case the cooldown exists for.
func TestCached_LiveCallerStillRecordsFailures(t *testing.T) {
	inner := &fakeRegistry{err: errors.New("rpc down")}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	if _, err := c.AcknowledgedSigner(context.Background(), "0xP"); err == nil {
		t.Fatal("want error")
	}
	if _, ok := c.recentFailure("0xp", now); !ok {
		t.Error("a real failure on a live context must start the cooldown")
	}
}

// Both maps are keyed on a provider address the untrusted router chose, and
// neither has a natural eviction — entries are only overwritten, failures only
// cleared by a success. A router pairing invented addresses with one real
// endpoint must not be able to grow either without bound.
func TestCached_BoundsItsKeySpace(t *testing.T) {
	now := time.Unix(1000, 0)
	inner := &fakeRegistry{signer: "0xabc", ack: true}
	c := newTestCache(inner, time.Minute, DefaultGrace, &now)

	// A modest overshoot past the cap: the claim is that the map stops growing, and
	// each rejected insert sweeps the full map, so a large overshoot only buys a slow
	// test.
	const overshoot = 64
	invented := func(i int) string { return ProviderKey(hexAddr(i)) }
	for i := 0; i < maxCachedProviders+overshoot; i++ {
		c.AcknowledgedSigner(context.Background(), invented(i))
	}
	if got := len(c.entries); got > maxCachedProviders {
		t.Errorf("entries holds %d, want at most %d", got, maxCachedProviders)
	}

	inner.setErr(errors.New("rpc down"))
	for i := maxCachedProviders; i < maxCachedProviders*2+overshoot; i++ {
		c.AcknowledgedSigner(context.Background(), invented(i))
	}
	if got := len(c.failures); got > maxCachedProviders {
		t.Errorf("failures holds %d, want at most %d", got, maxCachedProviders)
	}

	// The cap is not a permanent wedge: once the entries it is holding have gone
	// inert, the sweep frees them and a real provider is cached again.
	now = now.Add(time.Minute + DefaultGrace + FailureCooldown + time.Second)
	inner.setErr(nil)
	if _, err := c.AcknowledgedSigner(context.Background(), "0xreal"); err != nil {
		t.Fatalf("lookup after everything went inert: %v", err)
	}
	if _, ok := c.load(ProviderKey("0xreal")); !ok {
		t.Error("a real provider was not cached after the swept maps had room again")
	}
}

func hexAddr(i int) string {
	const hex = "0123456789ABCDEF"
	var b [40]byte
	for j := 39; j >= 0; j-- {
		b[j] = hex[i&0xf]
		i >>= 4
	}
	return "0x" + string(b[:])
}
