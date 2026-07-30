package chain

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Cached wraps a SignerRegistry with a per-provider TTL cache. A provider's
// acknowledged teeSignerAddress changes rarely (only on re-registration), so
// caching it avoids an RPC on every request while a bounded TTL still lets a
// rotation take effect. Only successful lookups are cached; errors are never
// cached, so a transient RPC failure is retried on the next request. A
// non-positive TTL disables caching (every call hits the inner registry).
func Cached(inner SignerRegistry, ttl time.Duration) SignerRegistry {
	if ttl <= 0 {
		return inner
	}
	return &cachedRegistry{inner: inner, ttl: ttl, entries: make(map[string]cacheEntry), now: time.Now}
}

type cacheEntry struct {
	signer       string
	acknowledged bool
	expires      time.Time
}

type cachedRegistry struct {
	inner   SignerRegistry
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]cacheEntry
}

func (c *cachedRegistry) AcknowledgedSigner(ctx context.Context, providerAddr string) (string, bool, error) {
	key := strings.ToLower(providerAddr)
	now := c.now()

	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.signer, e.acknowledged, nil
	}
	c.mu.Unlock()

	signer, acknowledged, err := c.inner.AcknowledgedSigner(ctx, providerAddr)
	if err != nil {
		return "", false, err
	}

	c.mu.Lock()
	c.entries[key] = cacheEntry{signer: signer, acknowledged: acknowledged, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return signer, acknowledged, nil
}
