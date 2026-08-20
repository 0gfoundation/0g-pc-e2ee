package core

import (
	"context"
	"fmt"
	"time"

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
	Resolve(ctx context.Context, req wire.Request) (Candidates, error)
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
// MATERIALIZING candidates, summed across the whole chain.
//
// Materializing ONE candidate is already bounded by the resolver — route caps a
// DCAP quote verification at a minute and a chain read at a few seconds — but the
// NUMBER of candidates is not: the list comes from the untrusted router, and the
// client walks it serially, re-sealing to each in turn. So a chain of unreachable
// providers multiplies that per-candidate bound by however many the router chose
// to send, and the caller waits through all of them before seeing an error. This
// is the ceiling on that product; nothing else imposes one.
//
// Sized to admit a TYPICAL cold materialization — a cache-miss quote verification
// (route bounds one at 60s) plus the chain read that grounds it (three eth_call
// attempts at 3s, ~10s with backoff) — so a request arriving before the warmer has
// swept still succeeds.
//
// It does NOT cover that path's own worst case, and the arithmetic is worth being
// explicit about rather than rounding away: a cold candidate that also triggers the
// signer-revalidation re-read and then the quote re-verification recovery can reach
// roughly 60 + 10 + 10 + 60 ≈ 140s on its own. Such a candidate will be cut here.
// That is the deliberate trade — a ceiling only binds if it is lower than the worst
// case it is bounding — and it is survivable because the expensive half is
// singleflighted under a context detached from any one caller: the verification it
// interrupts keeps running and lands in the cache, so the next request finds it
// warm instead of repeating the wait.
//
// The first candidate always gets the whole budget (spent starts at zero), so this
// can never refuse to try anybody: at worst it stops the walk after someone has
// been tried.
const resolveBudget = 90 * time.Second

// candidateWalk meters one walk down a Candidates chain, charging each
// materialization against its budget. It is not safe for concurrent use: one walk
// belongs to one Complete/CompleteStream call.
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
// what it takes. Time spent on the ATTEMPT against a materialized provider is
// deliberately not charged — only materialization is — so a long, legitimate
// inference on the head candidate cannot exhaust the budget a later fallback needs.
//
// A caller that gets an error checks exhausted() to tell "this candidate failed"
// from "there is nothing left to try one with".
func (w *candidateWalk) provider(ctx context.Context, cands Candidates, i int) (Provider, error) {
	remaining := w.limit() - w.spent
	if remaining <= 0 {
		return Provider{}, &Error{Stage: StageUpstream, Err: fmt.Errorf(
			"provider selection budget (%s) spent before candidate %d could be prepared", w.limit(), i)}
	}
	ctx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	start := time.Now()
	p, err := cands.Provider(ctx, i)
	w.spent += time.Since(start)
	return p, err
}

// exhausted reports that the budget is gone, so continuing down the chain would
// only reproduce the same failure once per remaining candidate.
func (w *candidateWalk) exhausted() bool { return w.spent >= w.limit() }

// staticResolver always returns the same single provider, ignoring the request —
// the low-level case for a caller that already holds a provider identity. It
// backs core.New and is used mainly by tests and any direct-seal-to-a-known-
// provider caller; the shipped server forms route instead (client/route).
type staticResolver struct{ provider Provider }

func (s staticResolver) Resolve(context.Context, wire.Request) (Candidates, error) {
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
