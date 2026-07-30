package route

import (
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// quoteCache is a small TTL cache of DCAP-verified provider keys, keyed by the
// provider endpoint. It amortizes the expensive verification path (quote fetch +
// go-tdx-guest signature/TCB checks + Intel PCS collateral). Safe for concurrent
// use (mutex-guarded map, like pubkeyCache).
//
// The TTL is bounded on PURPOSE — never permanent. A verified quote attests a
// point in time, and TCB status (UpToDate can flip to OutOfDate), certificate /
// collateral validity, PCK revocation, and provider enc-key rotation all change
// out from under it. A short TTL keeps the trust fresh; a background warmer
// refreshes ahead of expiry so requests still hit the cache. Only successful
// verifications are cached; a non-positive TTL disables caching (verify every
// request).
type quoteCache struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[string]quoteEntry
}

type quoteEntry struct {
	encPub crypto.PublicKey
	signer string
	exp    time.Time
}

// quoteResult is the shared return value of a single (de-duplicated) quote
// verification — the keys a fresh, genuine quote bound.
type quoteResult struct {
	encPub crypto.PublicKey
	signer string
}

func newQuoteCache(ttl time.Duration) *quoteCache {
	return &quoteCache{ttl: ttl, m: make(map[string]quoteEntry)}
}

func (c *quoteCache) get(key string) (crypto.PublicKey, string, bool) {
	if c.ttl <= 0 {
		return nil, "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.exp) {
		return nil, "", false
	}
	return e.encPub, e.signer, true
}

func (c *quoteCache) put(key string, encPub crypto.PublicKey, signer string) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = quoteEntry{encPub: encPub, signer: signer, exp: time.Now().Add(c.ttl)}
}
