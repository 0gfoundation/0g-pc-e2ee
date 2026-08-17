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
// Only successful lookups are cached; errors are not, so a transient failure is
// retried on the next request rather than pinned for a TTL. A non-positive ttl
// disables caching entirely (every call reads through). A non-positive grace
// disables the grace window, restoring strict fail-on-error behavior.
func Cached(inner SignerRegistry, ttl, grace time.Duration) SignerRegistry {
	if ttl <= 0 {
		return inner
	}
	return &cachedRegistry{
		inner:   inner,
		ttl:     ttl,
		grace:   grace,
		entries: make(map[string]cacheEntry),
		now:     time.Now,
	}
}

type cacheEntry struct {
	signer       string
	acknowledged bool
	expires      time.Time
}

type cachedRegistry struct {
	inner   SignerRegistry
	ttl     time.Duration
	grace   time.Duration
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]cacheEntry
	sf      singleflight.Group
}

// AcknowledgedSigner returns a fresh cached entry when there is one, otherwise
// refreshes from the chain. If that refresh fails and an expired entry is still
// within the grace window, the expired value is returned with Stale set rather
// than failing the caller.
func (c *cachedRegistry) AcknowledgedSigner(ctx context.Context, providerAddr string) (Signer, error) {
	key := strings.ToLower(providerAddr)
	now := c.now()

	if e, ok := c.load(key); ok && now.Before(e.expires) {
		return Signer{Address: e.signer, Acknowledged: e.acknowledged}, nil
	}

	got, err := c.refresh(ctx, providerAddr)
	if err == nil {
		return got, nil
	}
	if stale, ok := c.staleWithinGrace(key, now); ok {
		return stale, nil
	}
	return Signer{}, err
}

// RefreshSigner reads through to the chain, bypassing both the cache and the
// grace window, and caches a success. A caller uses it when it needs evidence it
// is willing to act NEGATIVELY on — see the asymmetry documented on Cached.
func (c *cachedRegistry) RefreshSigner(ctx context.Context, providerAddr string) (Signer, error) {
	return c.refresh(ctx, providerAddr)
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
		got, err := c.inner.AcknowledgedSigner(lookupCtx, providerAddr)
		if err != nil {
			return Signer{}, err
		}
		c.store(key, cacheEntry{
			signer:       got.Address,
			acknowledged: got.Acknowledged,
			expires:      c.now().Add(c.ttl),
		})
		return got, nil
	})
	select {
	case <-ctx.Done():
		return Signer{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return Signer{}, res.Err
		}
		// A shared result is never Stale: it came from a live read. Rebuild it rather
		// than trusting the inner value's flag, so a nested cache cannot leak its own
		// staleness through a refresh.
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
	return Signer{Address: e.signer, Acknowledged: e.acknowledged, Stale: true}, true
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
