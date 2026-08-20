package route

import (
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// quoteCache is a small TTL cache of DCAP-verified provider results — the keys a
// quote bound plus what the verification observed about the enclave (quoteFacts) —
// keyed by the provider endpoint. It amortizes the expensive verification path (quote fetch +
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
	res quoteResult
	exp time.Time
}

// quoteResult is the shared return value of a single (de-duplicated) quote
// verification: the keys a fresh, genuine quote bound, plus the facts the same
// verification established about the enclave behind them.
type quoteResult struct {
	encPub crypto.PublicKey
	signer string
	facts  quoteFacts
}

// quoteFacts is what the verification observed BESIDES the keys — the material the
// provider-identity record is built from.
//
// It is cached with the keys rather than recomputed on read for one reason: a cache
// HIT must be able to describe the verification it is standing in for. Deriving the
// facts only on a miss would leave the endpoint reporting nothing for exactly the
// providers the gateway uses most, and re-deriving them on read would mean fetching
// the quote again — which is precisely what this surface must never do.
type quoteFacts struct {
	// measurement is the boot-chain verdict against the verifier's audited allowlist.
	// Computed at verification time because that is the only place both halves are
	// known: whether the observed chain was permitted, and whether there was any
	// allowlist to permit it (see attest.Verifier.MeasurementBaselineConfigured).
	measurement Verdict
	// composeHash is the hex dstack compose hash from the verified quote's
	// mr_config_id, or "" when that register's layout does not expose one.
	composeHash string
}

func newQuoteCache(ttl time.Duration) *quoteCache {
	return &quoteCache{ttl: ttl, m: make(map[string]quoteEntry)}
}

func (c *quoteCache) get(key string) (quoteResult, bool) {
	if c.ttl <= 0 {
		return quoteResult{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.exp) {
		return quoteResult{}, false
	}
	return e.res, true
}

func (c *quoteCache) put(key string, res quoteResult) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = quoteEntry{res: res, exp: time.Now().Add(c.ttl)}
}

// del removes a cached entry. The warmer calls it when a refresh re-verification
// fails, so a provider that has gone bad (TCB downgrade, unreachable, revoked) is
// dropped immediately rather than served from a still-unexpired entry until TTL.
func (c *quoteCache) del(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}
