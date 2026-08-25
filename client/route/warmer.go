package route

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
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
//
// The catalog is per-(provider, model), so a provider serving several models
// appears once per model — the same address (and endpoint) repeated. A quote is
// per-enclave, not per-model, so the returned list is de-duplicated by address
// (case-insensitively, since the catalog may use EIP-55 or lowercase) to avoid
// verifying the same provider once per model. First-seen order and casing are
// preserved so downstream on-chain lookups get the address as the router sent it.
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
	seen := make(map[string]bool, len(pl.Data))
	for _, p := range pl.Data {
		if p.Address == "" {
			continue
		}
		key := strings.ToLower(p.Address)
		if seen[key] {
			continue
		}
		seen[key] = true
		addrs = append(addrs, p.Address)
	}
	return addrs, nil
}

// refreshQuote forces a (singleflighted) re-verification of endpoint and updates
// the cache — bypassing the cache-hit short-circuit so a still-valid entry is
// actually refreshed. On failure it evicts any stale entry so a provider that has
// gone bad (TCB downgrade, unreachable, revoked) is not served from cache until
// its TTL lapses.
//
// It returns the whole verification result, not just the keys. The signer lets a
// caller check it against the chain the way a request would, rather than assuming a
// successful refresh means a usable provider; the facts are what the provider-identity
// record is built from, and this is the only place in a sweep that holds them (they
// are derived from the quote reply, which nothing downstream sees).
func (r *Router) refreshQuote(ctx context.Context, endpoint string) (quoteResult, error) {
	quoteURL, err := deriveQuoteURL(endpoint)
	if err != nil {
		return quoteResult{}, err
	}
	res, err := r.verifyAndCache(ctx, quoteURL)
	if err != nil {
		// Evict on a genuine verification failure (provider gone bad), but NOT when
		// our own context was cancelled (e.g. shutdown): that says nothing about the
		// provider and must not drop a still-good entry.
		if ctx.Err() == nil {
			r.quoteCache.del(quoteURL)
		}
		return quoteResult{}, err
	}
	return res, nil
}

// WarmState describes what the most recently completed warmer sweep found. It is
// the process's answer to "could I serve a sealed request right now?", which is a
// different question from "is my HTTP server up": a sweep that prepared nothing
// means every candidate a request materializes would fail, whatever the cause —
// the router catalog unreachable, provider quote endpoints down, or the chain RPC
// unreadable. A deployment gate (the blue/green standby probe) wants exactly this,
// so it never sends traffic to a side that cannot verify anybody.
type WarmState struct {
	// At is when the sweep finished. Zero means no sweep has completed yet — a
	// just-started process, which a caller should treat as not-ready rather than as
	// ready-by-default.
	At time.Time
	// Started is when the most recent sweep BEGAN, which may be after At if one is
	// running now. A staleness check must consider both: a sweep that is merely slow
	// is not a warmer that has stalled, and sweep duration grows with the provider
	// count — each one costs a DCAP verify plus a chain read, serially, and both get
	// slower exactly when the upstreams are unwell. Judging on At alone would call a
	// process not-ready for taking too long to re-confirm what it is still happily
	// serving from cache.
	Started time.Time
	// Ready counts providers the sweep prepared END TO END: endpoint resolved, quote
	// verified and cached, and (when on-chain grounding is configured) the signer
	// read from the chain. A provider counted here is one a request could actually
	// be sealed to.
	Ready int
	// Total is how many providers the router's catalog listed, so a caller can tell
	// "nobody is ready" from "there is nobody".
	Total int
}

// WarmState returns the outcome of the most recently completed sweep. Safe for
// concurrent use; the zero value means no sweep has finished yet.
func (r *Router) WarmState() WarmState {
	r.warmMu.Lock()
	defer r.warmMu.Unlock()
	return r.warmState
}

// beginSweep stamps the start of a sweep, leaving the previous sweep's result in
// place — that result stays the honest answer until this one produces a new one.
func (r *Router) beginSweep(at time.Time) {
	r.warmMu.Lock()
	r.warmState.Started = at
	r.warmMu.Unlock()
}

// finishSweep records what a completed sweep found, preserving Started.
func (r *Router) finishSweep(ready, total int) {
	r.warmMu.Lock()
	r.warmState.At = time.Now()
	r.warmState.Ready = ready
	r.warmState.Total = total
	r.warmMu.Unlock()
}

// WarmOnce enumerates providers and (re)verifies each so the quote cache is hot,
// cutting first-request latency. It is a no-op unless quote verification is
// configured (WithQuoteVerification) and an EndpointResolver is supplied. Per
// provider it enumerates the address from the router catalog, resolves the
// serving endpoint from the on-chain registry, then runs the SAME verify+cache
// path a request uses (so the cache keys align); a failure evicts any stale
// entry. Individual failures are logged and skipped, never fatal to the sweep.
//
// It also records a WarmState for the sweep, so a caller can ask whether this
// process is currently able to serve anything at all.
func (r *Router) WarmOnce(ctx context.Context, endpoints EndpointResolver) {
	if r.verifier == nil || endpoints == nil {
		return
	}
	r.beginSweep(time.Now())
	addrs, err := r.listProviderAddrs(ctx)
	if err != nil {
		if ctx.Err() != nil {
			// The enumeration failed because WE are shutting down, which says nothing
			// about this process's ability to serve. Leave the counters and the warm
			// state untouched, exactly as the per-provider loop below does — otherwise a
			// clean shutdown would publish "0 providers ready" on its way out and make a
			// healthy process look broken to anything reading readiness.
			return
		}
		metrics.WarmerSweep("list_failed")
		r.logger.Warn("warmer: list providers failed", "err", err)
		// A sweep that could not even enumerate providers prepared none of them, which
		// is the honest readiness answer — not "unknown", and certainly not "ready".
		// The gauge has to move with it: leaving it at the last sweep's count would
		// let the alert built on it stay green while /readyz reports not-ready, which
		// is the one combination guaranteed to waste an operator's time.
		metrics.WarmerReadyProviders(0)
		r.finishSweep(0, 0)
		return
	}
	ready := 0
	for _, addr := range addrs {
		if ctx.Err() != nil {
			// A cancelled sweep is neither a success nor a provider failure; leave the
			// sweep counters AND the warm state untouched, so a shutdown cannot make a
			// healthy process look unready on its way out.
			return
		}
		info, err := endpoints.ServiceInfo(ctx, addr)
		if err != nil || info.URL == "" {
			metrics.WarmerProviderRefresh("endpoint_failed")
			r.logger.Warn("warmer: resolve endpoint failed", "provider", addr, "err", err)
			continue
		}
		prepared := true
		verified, err := r.refreshQuote(ctx, info.URL)
		// Tracked apart from prepared, which the on-chain block below also lowers: only
		// the QUOTE's outcome decides whether a provider-identity record may be written
		// at all, and a provider that verified but failed its signer check is recorded
		// (with the verdict that failed it) exactly as the request path records one.
		quoteVerified := err == nil
		if err != nil {
			metrics.WarmerProviderRefresh("verify_failed")
			r.logger.Warn("warmer: verify failed", "provider", addr, "endpoint", info.URL, "err", err)
			prepared = false
		} else {
			metrics.WarmerProviderRefresh("ok")
		}
		quoteSigner := verified.signer
		// The on-chain verdict for the record, in the same vocabulary the request path
		// reports. Assigned per arm below rather than through onchainVerdictOf because a
		// sweep produces no groundingOutcome to translate: it never calls
		// groundSignerOnChain (no cached-reading-then-revalidate dance — see the comment
		// on the refresh below), so there is nothing for that function to map. The
		// conclusions are the ones it would reach from the same evidence.
		onchain := VerdictNotChecked
		// Refresh the on-chain signer-grounding cache too (when configured), so the
		// first real request pays neither the DCAP verify nor the registry RPC. This
		// uses RefreshSigner rather than an ordinary lookup on purpose: an ordinary
		// lookup is satisfied by a still-fresh entry and so would warm nothing, which
		// left the entry to expire on its own schedule — the sweep interval and the
		// registry TTL are independently phased, so whether a request found a warm
		// entry came down to luck. Forcing the read each sweep makes it a true
		// refresh-ahead (interval under TTL ⇒ always warm), and it costs one eth_call
		// per provider per sweep.
		//
		// Still best-effort: the request path does the authoritative grounding, and a
		// failure here only means the next request may pay the RPC itself (or, if the
		// chain is unreachable, fall back on the cache's grace window).
		if r.registry != nil {
			got, err := r.registry.RefreshSigner(ctx, addr)
			switch {
			case err != nil:
				metrics.WarmerSignerRefresh("failed")
				r.logger.Warn("warmer: signer refresh failed", "provider", addr, "err", err)
				// Unavailable, never a finding: OUR chain RPC having a bad minute must not
				// reach a panel as an accusation against the provider (see onchainVerdictOf
				// on why lookup_failed is the one outcome that must not collapse).
				onchain = VerdictUnavailable
				// Only enforce mode turns this into "a request could not use this provider".
				// Under warn the request path proceeds ungrounded, so calling the provider
				// unprepared here would make /readyz refuse a cutover to a side that is in
				// fact serving every request — reporting OUR chain RPC's problem as the
				// standby's.
				prepared = prepared && !r.onchainEnforce
			case !got.Acknowledged || (quoteSigner != "" && !signerAgrees(got, quoteSigner)):
				// The lookup worked and disagreed. Ask the same question a request asks,
				// rather than treating "the RPC answered" as success: an unacknowledged or
				// mismatched signer is a provider enforce would skip, so counting it ready
				// would send traffic to a side where every request fails.
				//
				// !Acknowledged is tested on its own, ahead of the comparison, because it
				// needs no quote to interpret: a chain that vouches for NOBODY fails hop 5
				// whatever the quote says. Folding it into signerAgrees alone made it
				// reachable only with a quote signer in hand, so an unacknowledged provider
				// whose quote refresh had also failed was counted "ok" — hiding the second,
				// independent reason that provider can never become ready behind the first.
				metrics.WarmerSignerRefresh("mismatch")
				r.logger.Warn("warmer: on-chain signer does not vouch for the quote-bound signer",
					"provider", addr, "quote_signer", quoteSigner,
					"onchain_signer", got.Address, "acknowledged", got.Acknowledged)
				// Both halves of this arm are VerdictNoMatch — the same collapse the request
				// path makes: an operator responds differently to "the chain vouches for
				// nobody" than to "it vouches for someone else", which is why the log line
				// above carries both, but to a reader asking "is this the provider the chain
				// vouches for?" the answer is no either way.
				onchain = VerdictNoMatch
				prepared = prepared && !r.onchainEnforce
			case quoteSigner == "":
				// The chain acknowledges someone, but refreshQuote failed above so there is
				// no quote-bound signer to compare it against. Its own bucket rather than
				// "ok": nothing was actually checked, and "ok" is the series an operator
				// reads as "agreement confirmed". prepared is already false from
				// verify_failed, which is the metric that says why.
				metrics.WarmerSignerRefresh("unchecked")
				// Unavailable for the same reason this is its own metric bucket: the
				// comparison did not happen. Not left at not_checked, which would claim this
				// deployment does not run the check when in fact it ran and could not
				// conclude. Normally this arm means the quote refresh failed and no record is
				// written at all, but it is not assumed: a verification that somehow bound no
				// signer would still be recorded, and "unavailable" is the honest verdict for
				// a comparison that had nothing to compare.
				onchain = VerdictUnavailable
			default:
				metrics.WarmerSignerRefresh("ok")
				onchain = VerdictPass
			}
		}
		// Record what these checks established, so a panel can name this provider —
		// its compose hash, its containers, the verdicts — before any request has been
		// sealed to it (see provideridentity.go). Gated on the quote alone: QuoteDCAP is
		// VerdictPass in every record that exists, so a provider whose quote did not
		// verify leaves none and the endpoint 404s for it rather than reporting a
		// failure. The on-chain verdict rides along whatever it turned out to be,
		// mirroring the request path, which records a candidate enforce mode REJECTS
		// rather than letting an older pass stand while the gateway refuses it.
		//
		// recordWarmed, not record: where a sweep and a served request verified DIFFERENT
		// endpoints for one address — the router advertising something other than what the
		// chain says — the served record wins, because it describes the enclave a user's
		// prompt actually went to. Same endpoint and the fresher verification replaces the
		// older one as usual. See identityStore.putWarmed.
		//
		// Skipped on a cancelled context, for the same reason the sweep counters are: a
		// cancellation is OURS, not the provider's. The signer refresh above returns
		// ctx.Err() when we are shutting down, which lands in its `failed` arm and would
		// stamp VerdictUnavailable over a perfectly good `pass` — publishing "we could
		// not check this provider" about a shutdown that checked nothing.
		if quoteVerified && ctx.Err() == nil {
			r.recordWarmedProviderIdentity(providerIdentityOf(addr, info.URL, verified, onchain))
		}
		if prepared {
			ready++
		}
	}
	// Re-checked HERE as well as at the top of the loop, because the loop can also be
	// left by finishing its LAST provider while the context is already cancelled — the
	// guard above never runs again, and the sweep would fall through to publish
	// "0 of N prepared" on its way out. That is the same false unready this function
	// takes care to avoid everywhere else (see the list_failed path and the loop
	// guard), and it lands on the metric an alert pages on plus the WarmState /readyz
	// answers from, so a concurrent probe during a deploy would see it too.
	if ctx.Err() != nil {
		return
	}
	// The sweep ran to completion (individual provider failures are counted above,
	// not fatal); stamp the liveness gauge so an alert can fire if sweeps stall.
	metrics.WarmerSweep("ok")
	metrics.WarmerSweepSucceeded()
	metrics.WarmerReadyProviders(ready)
	r.finishSweep(ready, len(addrs))
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
