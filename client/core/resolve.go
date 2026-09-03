package core

import (
	"context"
	"fmt"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Resolver decides, for a given request, which provider enclaves the client
// should seal to. It exists so the same client core serves both selection
// shapes without branching in the seal path:
//
//   - the route resolver (client/route), used by both shipped server forms —
//     the sidecar and the gateway — asks the 0G router per request which
//     providers to use and fetches the chosen provider's enc key from the broker;
//   - a static resolver returns one fixed provider, for a caller that already
//     holds a provider identity (tests, or a future verified-quote/direct-seal
//     path).
//
// Resolve returns an ordered list of Candidates — best first — so the client can
// fall back to the next provider when one fails (SPEC §4.4). It runs on the
// request path, before sealing, so an implementation that makes network calls
// (route mode) should honor ctx for cancellation/deadline. A failure should be
// returned as a staged *Error so the proxy maps it to a sensible HTTP status; a
// plain error is treated as an upstream (502) failure.
type Resolver interface {
	// Resolve picks the candidates for one request. ep describes the REQUEST, not
	// the resolver: a resolver that fronts the 0G Router talks to one host serving
	// every endpoint, so which providers to rank, which fields to withhold from the
	// control plane, and which upstream path to use are all per request.
	//
	// It takes the whole row rather than the service-type string it used to,
	// because the string is a lossy projection: /v1/chat/completions and
	// /v1/messages are both "chatbot", so a resolver handed the string cannot tell
	// which surface it is ranking for, and re-deriving the row from it returned
	// whichever chat row came first. Every question the resolver answers per
	// request — the api_format to preview under, the profile whose payload fields
	// must be withheld, the upstream path — is a field of the row the caller
	// already holds.
	Resolve(ctx context.Context, ep endpoint.Endpoint, req wire.Request) (Candidates, error)
}

// Candidates is an ordered list of provider candidates to seal to, best first.
// The client tries them in order, re-sealing to the next when one fails
// (SPEC §4.4: sealed ciphertext is bound to one enclave's key, so a fallback
// must re-seal, not re-route).
//
// Materializing a candidate into a Provider may fetch its enc key from the
// broker, so it is deferred to Provider(i): the happy path (the head succeeds)
// never fetches keys for the tail.
type Candidates interface {
	// Len is the number of candidates; >= 1 whenever Resolve returns no error.
	Len() int
	// Provider materializes the i-th candidate (0 <= i < Len), fetching its enc
	// key if it is not already cached. Returning an error for one candidate lets
	// the client skip it and try the next, so an implementation should stage its
	// error like Resolve.
	Provider(ctx context.Context, i int) (Provider, error)
}

// resolveBudget bounds the TOTAL time one Complete/CompleteStream call may spend
// on WASTED work while walking the candidate chain: materializing candidates, plus
// attempts that failed. Time inside the attempt that ultimately succeeds is not
// charged, because that call returns rather than walking any further.
//
// An earlier version charged materialization ONLY, on the reasoning that a long
// legitimate inference on the head candidate must not starve a later fallback of
// the budget it needs. That reasoning was wrong, and it left the walk with no bound
// at all — the thing this budget is named for. If the head's long inference
// SUCCEEDS there is no fallback to starve, because Complete returns; if it FAILS,
// those minutes were the caller's, spent on nothing, and are exactly what wants
// counting. Uncharged, a chain whose candidates each burn the full providerTimeout
// cost N × 10m30s, with N chosen by the untrusted router.
//
// The budget gates ENTRY to the next candidate and is never imposed on an attempt
// already running — cutting one would cut a completion that is streaming tokens to
// its caller. So the ceiling, stated the same way preview's is, is this budget plus
// one attempt: bounded, and one attempt's overrun rather than N. maxPreviewCandidates
// bounds N independently, so neither factor is left to the router. One consequence
// of gating entry rather than attempts: an attempt that runs to providerTimeout
// blows the budget by itself and the walk stops after it, which is intended — a
// caller already held ten minutes by one provider is not served by ten more.
//
// Sized to admit a TYPICAL cold materialization — a cache-miss quote verification
// (route bounds one at 60s) plus the chain read that grounds it (three eth_call
// attempts at 3s, ~10s with backoff) — so a request arriving before the warmer has
// swept still succeeds. It does NOT cover that path's own worst case, and the
// arithmetic is worth being explicit about rather than rounding away: a cold
// candidate that also triggers the signer-revalidation re-read and then the quote
// re-verification recovery can reach roughly 60 + 10 + 10 + 60 ≈ 140s on its own,
// and will be cut here. That is the deliberate trade — a ceiling only binds if it is
// lower than the worst case it bounds — and it is survivable because the expensive
// half is singleflighted under a context detached from any one caller: the
// verification it interrupts keeps running and lands in the cache, so the next
// request finds it warm instead of repeating the wait.
//
// The first candidate always gets the whole budget (spent starts at zero), so this
// can never refuse to try anybody: at worst it stops the walk after someone has
// been tried.
const resolveBudget = 90 * time.Second

// candidateWalk meters one walk down a Candidates chain, charging every
// materialization and every failed attempt against its budget (see resolveBudget).
// It is not safe for concurrent use: one walk belongs to one
// Complete/CompleteStream call.
//
// budget is carried per walk rather than read from the constant so a test can scale
// it down — exercising the exhaustion path takes a full budget of wall clock
// otherwise. Zero means resolveBudget.
type candidateWalk struct {
	spent  time.Duration
	budget time.Duration
}

// limit is the walk's budget, defaulted.
func (w *candidateWalk) limit() time.Duration {
	if w.budget > 0 {
		return w.budget
	}
	return resolveBudget
}

// provider materializes candidate i under whatever is left of the budget, charging
// what it takes. A failed ATTEMPT against a materialized provider is charged too,
// by the caller via charge() — see resolveBudget for why leaving it out left the
// walk unbounded.
//
// A caller that gets an error checks exhausted() to tell "this candidate failed"
// from "there is nothing left to try one with".
func (w *candidateWalk) provider(ctx context.Context, cands Candidates, i int) (Provider, error) {
	remaining := w.limit() - w.spent
	if remaining <= 0 {
		return Provider{}, &Error{Stage: StageUpstream, Err: fmt.Errorf(
			"provider selection budget (%s) spent before candidate %d could be prepared", w.limit(), i)}
	}
	// Read the clock BEFORE deriving the deadline, and derive it FROM that reading.
	// Taken the other way round, any scheduling delay between the two lands outside
	// the measurement: the deadline still ends the materialization, but spent comes
	// back short of remaining and exhausted() — the only judge at this boundary —
	// reads false. A 5ms preemption injected between the two lines is enough
	// (spent=45ms against a 50ms limit), and under parallel load it showed up as a
	// ~1% flake. Anchoring both to one reading makes spent >= remaining hold
	// unconditionally once the deadline fires.
	start := time.Now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(remaining))
	defer cancel()
	p, err := cands.Provider(ctx, i)
	w.spent += time.Since(start)
	return p, err
}

// charge books time the walk spent on work that came to nothing — a failed attempt
// against a materialized provider. Materialization charges itself; this is the other
// half, and without it the budget bounded only the cheaper of the two.
func (w *candidateWalk) charge(d time.Duration) { w.spent += d }

// exhausted reports that the budget is gone, so continuing down the chain would
// only reproduce the same failure once per remaining candidate.
func (w *candidateWalk) exhausted() bool { return w.spent >= w.limit() }

// staticResolver always returns the same single provider, ignoring the request —
// the low-level case for a caller that already holds a provider identity. It
// backs core.New and is used mainly by tests and any direct-seal-to-a-known-
// provider caller; the shipped server forms route instead (client/route).
type staticResolver struct{ provider Provider }

func (s staticResolver) Resolve(context.Context, endpoint.Endpoint, wire.Request) (Candidates, error) {
	return staticCandidates{s.provider}, nil
}

// staticCandidates is a fixed candidate list — no lazy materialization, no
// fallback beyond the providers it already holds. A one-element list backs the
// static resolver.
type staticCandidates []Provider

func (s staticCandidates) Len() int { return len(s) }

func (s staticCandidates) Provider(_ context.Context, i int) (Provider, error) {
	return s[i], nil
}
