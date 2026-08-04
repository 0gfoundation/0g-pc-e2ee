package dcap

import (
	"strings"
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/google/go-tdx-guest/verify/trust"
)

// intelPCSBase is the Intel Provisioning Certification Service host+scheme that
// go-tdx-guest fetches DCAP collateral from (TCB Info, QE Identity, PCK/root
// CRLs) — the URLs are api.trustedservices.intel.com/{sgx,tdx}/certification/v4/…
// A PCCS (e.g. Phala's hosted pccs.phala.network) mirrors the same paths under
// its own host, so a rewrite is a pure host swap that leaves the path+query —
// and thus the FMSPC / ca / encoding parameters — untouched.
const intelPCSBase = "https://api.trustedservices.intel.com"

// pccsRewriteGetter rewrites Intel PCS collateral URLs to a configured PCCS base
// before delegating to inner. It exists so a deployment that cannot (or prefers
// not to) reach Intel PCS directly can point collateral fetches at a PCCS mirror
// without go-tdx-guest knowing. Only api.trustedservices.intel.com URLs — the
// FMSPC-specific TCB Info, the QE Identity, and the PCK CRL — are rewritten; any
// other URL passes through unchanged, so an unrecognized host is never silently
// redirected.
//
// One collateral fetch is deliberately NOT covered: the SGX root-CA CRL, whose
// URL comes from the root certificate's own distribution point on a different
// Intel host (certificates.trustedservices.intel.com) with a different path
// layout, so a host-only swap cannot map it to a PCCS mirror. When revocation
// checking is on, that one request still goes to Intel and fails closed if it
// cannot be reached. It is still de-duplicated by the caching layer.
type pccsRewriteGetter struct {
	base  string // PCCS base, no trailing slash, e.g. https://pccs.phala.network
	inner trust.HTTPSGetter
}

func newPCCSRewriteGetter(base string, inner trust.HTTPSGetter) *pccsRewriteGetter {
	return &pccsRewriteGetter{base: strings.TrimRight(base, "/"), inner: inner}
}

func (g *pccsRewriteGetter) Get(u string) (map[string][]string, []byte, error) {
	if rest, ok := strings.CutPrefix(u, intelPCSBase); ok {
		u = g.base + rest
	}
	return g.inner.Get(u)
}

// collateralEntry is one cached collateral fetch (the getter contract returns
// response headers alongside the body — the *-Issuer-Chain headers matter, so
// both are cached).
type collateralEntry struct {
	header map[string][]string
	body   []byte
	exp    time.Time
}

// cachingGetter memoizes successful collateral fetches by URL for a bounded TTL,
// so the expensive DCAP path does not re-fetch the same TCB Info / QE Identity /
// CRLs for every provider and every warmer sweep. The collateral URL is the
// natural dedup key: the FMSPC-specific TCB Info URL carries ?fmspc=…, so caching
// by URL dedups per FMSPC (providers on the same platform share it), while the
// FMSPC-independent QE Identity and root-CA CRL collapse to one entry across all
// providers.
//
// The TTL is bounded on PURPOSE. Collateral is time-sensitive: TCB Info and QE
// Identity carry nextUpdate, and — most importantly — a PCK/root CRL can revoke a
// platform key at any time. Caching means a freshly published revocation is not
// observed until the entry expires, so the TTL is the acceptable revocation-lag
// window; keep it well under the collateral's nextUpdate and short enough that
// revocation staleness is tolerable (revocation is a secondary defense behind
// measurement + report_data binding and on-chain signer grounding). Only
// successful fetches are cached — an error is never memoized, so a transient
// outage does not stick.
type cachingGetter struct {
	ttl   time.Duration
	inner trust.HTTPSGetter
	mu    sync.Mutex
	m     map[string]collateralEntry
}

func newCachingGetter(ttl time.Duration, inner trust.HTTPSGetter) *cachingGetter {
	return &cachingGetter{ttl: ttl, inner: inner, m: make(map[string]collateralEntry)}
}

func (g *cachingGetter) Get(u string) (map[string][]string, []byte, error) {
	g.mu.Lock()
	if e, ok := g.m[u]; ok && time.Now().Before(e.exp) {
		g.mu.Unlock()
		metrics.CollateralCacheLookup(true)
		// Hand back a copy of the body: the same entry is shared by every caller, so
		// returning the stored slice directly would let one caller's mutation poison
		// the collateral another verification reads. (go-tdx-guest treats it as
		// read-only today; the copy keeps that from being load-bearing.)
		return e.header, append([]byte(nil), e.body...), nil
	}
	g.mu.Unlock()
	metrics.CollateralCacheLookup(false)

	// Miss (or expired): fetch. Two callers can race the same URL here and both
	// fetch; that is a harmless duplicate — the fetch is an idempotent GET and both
	// store the same value — so no singleflight is warranted for this path. The
	// fetch latency and outcome are metered (this is the Intel PCS / PCCS dependency
	// the cache shields).
	start := time.Now()
	header, body, err := g.inner.Get(u)
	metrics.CollateralFetch(err == nil, time.Since(start))
	if err != nil {
		return nil, nil, err
	}
	// Store an independent copy so the cache owns its bytes, decoupled from both the
	// inner getter's slice and the body we return to this caller.
	g.mu.Lock()
	g.m[u] = collateralEntry{header: header, body: append([]byte(nil), body...), exp: time.Now().Add(g.ttl)}
	g.mu.Unlock()
	return header, body, nil
}

// effectiveGetter assembles the collateral getter for the parser from the Config:
// an optional PCCS host rewrite wrapped by an optional dedup cache, over the
// caller's Getter (or go-tdx-guest's default when none is given). Caching is the
// OUTER layer so it keys on the URL the verifier requests (the canonical Intel
// PCS URL) — dedup then works identically whether or not a PCCS rewrite is in
// play. It returns nil to mean "leave the library default in place" (no getter
// override, no PCCS, no cache), preserving the pre-B2 behavior exactly.
func (cfg Config) effectiveGetter() trust.HTTPSGetter {
	if cfg.Getter == nil && cfg.PCCSBaseURL == "" && cfg.CollateralTTL <= 0 {
		return nil
	}
	inner := cfg.Getter
	if inner == nil {
		inner = trust.DefaultHTTPSGetter()
	}
	if cfg.PCCSBaseURL != "" {
		inner = newPCCSRewriteGetter(cfg.PCCSBaseURL, inner)
	}
	if cfg.CollateralTTL > 0 {
		inner = newCachingGetter(cfg.CollateralTTL, inner)
	}
	return inner
}
