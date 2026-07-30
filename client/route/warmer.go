package route

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
)

// EndpointResolver resolves a provider's serving endpoint by its on-chain
// address; *chain.OnChainRegistry satisfies it via ServiceInfo. The warmer uses
// it so each provider's endpoint comes from the authoritative on-chain registry
// (the router catalog is used only to ENUMERATE which providers exist, not for
// their endpoints).
type EndpointResolver interface {
	ServiceInfo(ctx context.Context, providerAddr string) (chain.ServiceInfo, error)
}

// providerListResponse is the subset of GET /v1/providers the warmer reads — the
// provider on-chain addresses. Every other field is ignored.
type providerListResponse struct {
	Data []struct {
		Address string `json:"address"`
	} `json:"data"`
}

// listProviderAddrs enumerates provider on-chain addresses from the router's
// catalog (GET /v1/providers?service_type=…) for the Router's configured service
// type. The addresses are the only thing taken from the router here; each
// provider's endpoint is resolved from chain (see WarmOnce).
func (r *Router) listProviderAddrs(ctx context.Context) ([]string, error) {
	u := r.providersURL + "?service_type=" + url.QueryEscape(r.serviceType)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("list providers: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read providers list: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("providers list returned %d", resp.StatusCode)
	}
	var pl providerListResponse
	if err := json.Unmarshal(body, &pl); err != nil {
		return nil, fmt.Errorf("decode providers list: %w", err)
	}
	addrs := make([]string, 0, len(pl.Data))
	for _, p := range pl.Data {
		if p.Address != "" {
			addrs = append(addrs, p.Address)
		}
	}
	return addrs, nil
}

// refreshQuote forces a (singleflighted) re-verification of endpoint and updates
// the cache — bypassing the cache-hit short-circuit so a still-valid entry is
// actually refreshed. On failure it evicts any stale entry so a provider that has
// gone bad (TCB downgrade, unreachable, revoked) is not served from cache until
// its TTL lapses.
func (r *Router) refreshQuote(ctx context.Context, endpoint string) error {
	quoteURL, err := deriveQuoteURL(endpoint)
	if err != nil {
		return err
	}
	if _, err := r.verifyAndCache(ctx, quoteURL); err != nil {
		// Evict on a genuine verification failure (provider gone bad), but NOT when
		// our own context was cancelled (e.g. shutdown): that says nothing about the
		// provider and must not drop a still-good entry.
		if ctx.Err() == nil {
			r.quoteCache.del(quoteURL)
		}
		return err
	}
	return nil
}

// WarmOnce enumerates providers and (re)verifies each so the quote cache is hot,
// cutting first-request latency. It is a no-op unless quote verification is
// configured (WithQuoteVerification) and an EndpointResolver is supplied. Per
// provider it enumerates the address from the router catalog, resolves the
// serving endpoint from the on-chain registry, then runs the SAME verify+cache
// path a request uses (so the cache keys align); a failure evicts any stale
// entry. Individual failures are logged and skipped, never fatal to the sweep.
func (r *Router) WarmOnce(ctx context.Context, endpoints EndpointResolver) {
	if r.verifier == nil || endpoints == nil {
		return
	}
	addrs, err := r.listProviderAddrs(ctx)
	if err != nil {
		r.logger.Warn("warmer: list providers failed", "err", err)
		return
	}
	for _, addr := range addrs {
		if ctx.Err() != nil {
			return
		}
		info, err := endpoints.ServiceInfo(ctx, addr)
		if err != nil || info.URL == "" {
			r.logger.Warn("warmer: resolve endpoint failed", "provider", addr, "err", err)
			continue
		}
		if err := r.refreshQuote(ctx, info.URL); err != nil {
			r.logger.Warn("warmer: verify failed", "provider", addr, "endpoint", info.URL, "err", err)
		}
		// Warm the on-chain signer-grounding cache too (when configured), so the
		// first real request pays neither the DCAP verify nor the registry RPC.
		// Best-effort: the request path does the authoritative grounding.
		if r.registry != nil {
			if _, _, err := r.registry.AcknowledgedSigner(ctx, addr); err != nil {
				r.logger.Warn("warmer: signer lookup failed", "provider", addr, "err", err)
			}
		}
	}
}

// RunWarmer warms once immediately, then re-warms every interval until ctx is
// cancelled. interval should sit a bit under the quote TTL (refresh-ahead) so
// cached entries never expire between requests. It blocks; callers run it in a
// goroutine tied to the server lifecycle. A no-op (returns immediately) when
// verification is off, no resolver is given, or interval <= 0.
func (r *Router) RunWarmer(ctx context.Context, interval time.Duration, endpoints EndpointResolver) {
	if r.verifier == nil || endpoints == nil || interval <= 0 {
		return
	}
	r.WarmOnce(ctx, endpoints)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.WarmOnce(ctx, endpoints)
		}
	}
}
