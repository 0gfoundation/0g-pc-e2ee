package chain

import (
	"context"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultGrace is the grace window Cached uses when none is given: how long past
// its TTL an entry stays usable if the refresh RPC is failing. See Cached for why
// this is generous.
const DefaultGrace = 30 * time.Minute

// Cached wraps a SignerRegistry with a per-provider TTL cache, a grace window,
// and single-flighted refreshes. A provider's acknowledged teeSignerAddress
// changes rarely (only on re-registration), so caching it keeps the chain RPC off
// the request path while a bounded TTL still lets a rotation take effect.
//
// Grace window. When an entry's TTL lapses and the refresh FAILS, the expired
// entry stays usable for grace, marked Signer.Stale. Without it, chain RPC
// availability is a hard dependency of the data plane: the route resolver grounds
// every candidate it materializes, so an RPC outage fails every candidate of
// every request — a total outage caused by our own infrastructure rather than by
// anything wrong with a provider. Serving a value that was verified minutes ago
// is a far better trade, because the value is near-static: to exploit the window
// an attacker would need a provider to re-register a new signer AND our RPC to be
// down across exactly that period.
//
// Staleness is asymmetric, and callers MUST honor the asymmetry: a stale reading
// is good enough to CONFIRM that a quote-bound signer matches, and never good
// enough to REJECT one. A broker upgrade rotates the signer, so during a benign
// upgrade a stale entry disagrees with a freshly quoted signer — indistinguishable
// from an attack if you rule on it. A caller about to reject calls RefreshSigner
// to get fresh evidence first.
//
// Single-flight. Concurrent misses for one provider collapse into a single RPC,
// so a TTL expiry under load cannot stampede an endpoint that may already be
// struggling — the same protection the quote path gets from its own singleflight
// group.
//
// Failure cooldown. A failed lookup is remembered for FailureCooldown, and while
// it is remembered the live call is skipped entirely: a stale entry is served at
// once, or the recorded error returned at once. Without this the grace window
// still prevents failure but not COST — the inner registry retries with backoff
// before giving up, so every request would pay the full retry budget (seconds)
// per grounded candidate, serially, for the whole outage. The point of the window
// is that an unreachable chain stops mattering, and a request that hangs for ten
// seconds and then succeeds has not stopped mattering. Recovery still happens
// promptly: one probe per cooldown, plus the warmer's own sweep, and any success
// clears the mark.
//
// Only successful lookups become cached VALUES; a failure is never stored as
// though it were a reading, it only starts the cooldown above. A non-positive ttl
// disables caching entirely (every call reads through). A non-positive grace
// disables the grace window, restoring strict fail-on-error behavior.
func Cached(inner SignerRegistry, ttl, grace time.Duration) SignerRegistry {
	if ttl <= 0 {
		return inner
	}
	return &cachedRegistry{
		inner:    inner,
		ttl:      ttl,
		grace:    grace,
		cooldown: FailureCooldown,
		entries:  make(map[string]cacheEntry),
		failures: make(map[string]failure),
		now:      time.Now,
	}
}

// FailureCooldown is how long a failed lookup suppresses further live attempts
// for the same provider. Sized so an outage costs one probe per provider per
// half-minute instead of one per request, while a recovery is picked up within
// that same half-minute.
const FailureCooldown = 30 * time.Second

type cacheEntry struct {
	signer       string
	acknowledged bool
	expires      time.Time
}

// failure remembers the last failed lookup for a provider, so the cooldown can
// answer immediately with the same error instead of paying the retry budget again.
type failure struct {
	at  time.Time
	err error
}

type cachedRegistry struct {
	inner    SignerRegistry
	ttl      time.Duration
	grace    time.Duration
	cooldown time.Duration
	now      func() time.Time
	mu       sync.Mutex
	entries  map[string]cacheEntry
	failures map[string]failure
	sf       singleflight.Group
}

// AcknowledgedSigner returns a fresh cached entry when there is one, otherwise
// refreshes from the chain. If that refresh fails and an expired entry is still
// within the grace window, the expired value is returned with Stale set rather
// than failing the caller. While a recent failure is in cooldown the live attempt
// is skipped altogether, so an ongoing outage is answered immediately — from the
// stale entry when there is one, otherwise with the error the last attempt gave.
func (c *cachedRegistry) AcknowledgedSigner(ctx context.Context, providerAddr string) (Signer, error) {
	key := strings.ToLower(providerAddr)
	now := c.now()

	if e, ok := c.load(key); ok && now.Before(e.expires) {
		return Signer{Address: e.signer, Acknowledged: e.acknowledged, Cached: true}, nil
	}

	if f, ok := c.recentFailure(key, now); ok {
		if stale, ok := c.staleWithinGrace(key, now); ok {
			return stale, nil
		}
		return Signer{}, f.err
	}

	got, err := c.refresh(ctx, providerAddr)
	if err == nil {
		return got, nil
	}
	c.recordFailure(key, now, err)
	if stale, ok := c.staleWithinGrace(key, now); ok {
		return stale, nil
	}
	return Signer{}, err
}

// RefreshSigner reads through to the chain, bypassing the cache, the grace window
// AND the failure cooldown, and caches a success. A caller uses it when it needs
// evidence it is willing to act NEGATIVELY on — see the asymmetry documented on
// Cached — and that is worth the full retry budget even mid-outage, because the
// alternative is condemning a provider on no evidence. It stays cheap in aggregate
// because it runs only when a reading and a quote disagree, not on the ordinary
// path.
func (c *cachedRegistry) RefreshSigner(ctx context.Context, providerAddr string) (Signer, error) {
	got, err := c.refresh(ctx, providerAddr)
	if err != nil {
		c.recordFailure(strings.ToLower(providerAddr), c.now(), err)
	}
	return got, err
}

// recentFailure reports a failure still inside the cooldown, so a caller can
// answer without attempting the chain again.
func (c *cachedRegistry) recentFailure(key string, now time.Time) (failure, bool) {
	if c.cooldown <= 0 {
		return failure{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.failures[key]
	if !ok || !now.Before(f.at.Add(c.cooldown)) {
		return failure{}, false
	}
	return f, true
}

func (c *cachedRegistry) recordFailure(key string, now time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures == nil {
		c.failures = make(map[string]failure)
	}
	c.failures[key] = failure{at: now, err: err}
}

func (c *cachedRegistry) clearFailure(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.failures, key)
}

// refresh performs a single-flighted live lookup and caches a success. Callers
// that arrive during an in-flight lookup share its result, which is live evidence
// for all of them: the call was issued after the staleness that prompted it.
func (c *cachedRegistry) refresh(ctx context.Context, providerAddr string) (Signer, error) {
	key := strings.ToLower(providerAddr)
	ch := c.sf.DoChan(key, func() (any, error) {
		// Detach from whichever caller happened to lead so its cancellation cannot
		// fail the lookup for everyone coalesced onto it; the inner registry bounds
		// the call with its own per-attempt deadlines. Each caller still honors its
		// OWN context in the select below.
		lookupCtx := context.WithoutCancel(ctx)
		// RefreshSigner, not AcknowledgedSigner: this function's whole contract is "read
		// live". Asking the inner registry for a possibly-cached value and then clearing
		// the provenance flags below would MANUFACTURE freshness — handing a caller that
		// is willing to reject on this reading something it must not reject on. Harmless
		// with the unwrapped *OnChainRegistry the binaries use, where the two are the
		// same call, and wrong the moment anyone nests a cache.
		got, err := c.inner.RefreshSigner(lookupCtx, providerAddr)
		if err != nil {
			return Signer{}, err
		}
		c.store(key, cacheEntry{
			signer:       got.Address,
			acknowledged: got.Acknowledged,
			expires:      c.now().Add(c.ttl),
		})
		// A success ends the outage as far as this provider is concerned; drop the mark
		// so the next expiry goes straight to a live read rather than waiting out a
		// cooldown that no longer describes reality.
		c.clearFailure(key)
		return got, nil
	})
	select {
	case <-ctx.Done():
		return Signer{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return Signer{}, res.Err
		}
		// A shared result is neither Stale nor Cached: it came from a live read, and
		// every caller coalesced onto it gets the same live evidence.
		got := res.Val.(Signer)
		return Signer{Address: got.Address, Acknowledged: got.Acknowledged}, nil
	}
}

// staleWithinGrace returns an expired entry that is still inside the grace
// window, marked Stale.
func (c *cachedRegistry) staleWithinGrace(key string, now time.Time) (Signer, bool) {
	if c.grace <= 0 {
		return Signer{}, false
	}
	e, ok := c.load(key)
	if !ok || !now.Before(e.expires.Add(c.grace)) {
		return Signer{}, false
	}
	return Signer{Address: e.signer, Acknowledged: e.acknowledged, Stale: true, Cached: true}, true
}

func (c *cachedRegistry) load(key string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	return e, ok
}

func (c *cachedRegistry) store(key string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = e
}
