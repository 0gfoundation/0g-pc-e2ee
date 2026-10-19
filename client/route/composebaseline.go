package route

// composebaseline.go holds the manifest a provider's CVM booted against the deployment
// recorded for that provider — the comparison pcverify -provider makes
// (compose.CheckReview against client/evidence/compose/brokercompose.json), made here for
// every provider this process verifies.
//
// WHY. Hop 3 pins the guest OS and says nothing about the containers inside it. The
// compose hash in the quote pins WHICH manifest booted; the baseline says whether that
// manifest is one that was reviewed and recorded for this provider. Together with the
// runtime check (runtimerelease.go) it covers what runs: the manifest for what booted,
// RTMR3 for what the controller swapped in since.
//
// ONLY THE BASELINE. The compose review's findings (Blocking / Justify / Note) are not
// recorded here: they are heuristics about a manifest we did not write, reported by
// pcverify and never a gate (composebaseline.go in evidence/compose says why). A verdict
// field is read as a verdict, so only the comparison that adjudicates gets one.
//
// OBSERVE ONLY, like the runtime check: the verdict is recorded
// (ProviderIdentity.ComposeBaseline), counted and logged, and nothing on the request path
// acts on it.
//
// WHERE IT RUNS. The manifest is loaded once per quote verification, with the quote
// (verifyQuoteAt) — the expensive step, compose-go's loader, and the one that does not
// depend on who the provider is. The comparison needs the provider's address, which the
// quote cache (keyed by endpoint) does not have, so it runs where the address is known —
// the request path and every warmer sweep — and is judged again whenever a record is
// read, since the broker builds it names are judged in the background (releaseJudge) and
// their verdicts can land later. It is OBSERVED (counted and logged) once per
// verification and provider, not once per request: see observation.

import (
	"strings"
	"sync"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence/compose"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// WithComposeBaseline makes the Router compare each verified provider's manifest against
// the deployment b records for (contract, provider address). contract is the
// InferenceServing contract the providers are registered in — the same one on-chain
// grounding reads — since a recorded deployment is keyed by both.
//
// It is meaningful only with WithQuoteVerification: the manifest is the app-compose the
// quote reply carries, accepted only when it hashes to the verified quote's compose
// hash. The broker builds the baseline lets move are judged by WithReleaseVerifier's
// verifier; without one, a deployment that records such a service can only come out
// unavailable.
func WithComposeBaseline(b compose.ComposeBaseline, contract string) Option {
	return func(r *Router) {
		r.baseline = &composeBaseline{b: b, contract: contract}
	}
}

type composeBaseline struct {
	b        compose.ComposeBaseline
	contract string
}

// manifestFacts is what one quote verification read of the provider's manifest, kept with
// the other quote facts so a record — and a cache hit — can be compared again later.
type manifestFacts struct {
	// review is the authenticated manifest, loaded as docker compose loads it; nil when
	// there was none to load (err says why).
	review *compose.ComposeReview
	err    string
	// observed is shared by every holder of this verification's facts — each request
	// that joined it through the singleflight, every later cache hit, and a warmer sweep
	// that joined it — and says which providers it has been observed for.
	observed *observation
}

// observation records which providers one verification has been observed for, so that
// observeBaseline counts and logs it once per verification and provider however many
// requests share it.
//
// Per provider, not just per verification: one endpoint can serve several registrations
// (cn-39 and cn-40 are one CVM), each with its own recorded deployment, and a token per
// verification alone would observe whichever address happened to come first.
//
// Per verification, not per request: a request is not evidence. "Is this the request
// that verified?" cannot be answered from the request's side — every caller that joins
// a verification through the singleflight sees a cache miss — so the answer lives with
// the verification.
type observation struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newObservation() *observation { return &observation{seen: map[string]bool{}} }

// first reports whether address has not been observed for this verification yet, and
// marks it. A nil observation (facts no verification produced) always reports true.
func (o *observation) first(address string) bool {
	if o == nil {
		return true
	}
	key := chain.ProviderKey(address)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen[key] {
		return false
	}
	o.seen[key] = true
	return true
}

// readManifest loads the reply's app-compose for the baseline, after the hash gate. It
// returns nothing to compare when the Router has no baseline, so a deployment without one
// pays nothing for compose-go.
func (r *Router) readManifest(appCompose []byte, composeHash [attest.ComposeHashLen]byte, haveHash bool,
	quoteURL string) manifestFacts {
	f := manifestFacts{observed: newObservation()}
	switch {
	case r.baseline == nil:
	case !haveHash:
		f.err = "the quote's mr_config_id does not expose a compose hash, so no manifest is authenticated"
	case len(appCompose) == 0:
		f.err = "the quote reply carries no app-compose"
	default:
		// No release verifier for the review itself: its findings are not recorded here,
		// and the one thing it would judge builds for (the controller exception) is a
		// finding.
		review, err := r.reviewManifest(appCompose, composeHash, quoteURL)
		if err != nil {
			f.err = err.Error()
		} else {
			f.review = &review
		}
	}
	return f
}

// baselineVerdict is the judgement of one manifest against one provider's record.
type baselineVerdict struct {
	verdict Verdict
	// deployment names the recorded deployment the manifest was compared against, or ""
	// when none is recorded for the provider.
	deployment string
	// why says what decided a verdict other than a pass, for the log.
	why []string
}

// judgeBaseline compares f against the deployment recorded for address. start says
// whether a broker build with no release verdict yet may be sent for one (see
// judgeRuntime).
//
//   - pass: the manifest is the recorded deployment — every service and top-level
//     section, with any broker build the record lets move an accepted release.
//   - no_match: it is not — a service or section differs, is missing or is extra, a
//     broker build is not a release, or docker compose refuses the manifest.
//   - no_baseline: no deployment is recorded for this provider, so nothing was compared.
//     Not a finding: a deployment nobody reviewed is unverified, not refuted.
//   - unavailable: the comparison could not run or finish — no authenticated manifest,
//     one this build does not read, or a broker build whose provenance has not been (or
//     could not be) checked.
//   - not_checked: this process was not given a baseline.
func (r *Router) judgeBaseline(address string, f manifestFacts, start bool) baselineVerdict {
	switch {
	case r.baseline == nil:
		return baselineVerdict{verdict: VerdictNotChecked}
	case f.review == nil:
		return baselineVerdict{verdict: VerdictUnavailable, why: []string{f.err}}
	}
	var rels judgedReleases
	if r.releases != nil {
		rels = judgedReleases{j: r.releases, start: start}
	}
	c := compose.CheckReview(r.baseline.b, rels.verifier(), r.baseline.contract, address, *f.review)
	v := baselineVerdict{deployment: c.Deployment}
	switch {
	case !c.Compared():
		v.verdict = VerdictNoBaseline
	case len(c.Mismatches) > 0:
		v.verdict, v.why = VerdictNoMatch, mismatchReasons(c.Mismatches)
	case len(c.Unverified) > 0:
		v.verdict, v.why = VerdictUnavailable, mismatchReasons(c.Unverified)
	default:
		v.verdict = VerdictPass
	}
	return v
}

// observeBaseline judges a provider's manifest the first time a verification is used for
// that provider, sending broker builds with no verdict for one, and counts and logs the
// outcome. Every later use of the same verification for the same provider — a request
// that joined it, a cache hit — is a no-op, and observeBaseline reports whether it
// observed.
func (r *Router) observeBaseline(address string, f manifestFacts) bool {
	if !f.observed.first(address) {
		return false
	}
	v := r.judgeBaseline(address, f, true)
	metrics.ComposeBaseline(string(v.verdict))
	switch v.verdict {
	case VerdictNoMatch:
		r.logger.Warn("provider's manifest is not the deployment recorded for it (observed, not enforced)",
			"provider", address, "deployment", v.deployment, "why", strings.Join(v.why, "; "))
	case VerdictUnavailable:
		r.logger.Debug("provider's manifest could not be compared against its recorded deployment",
			"provider", address, "deployment", v.deployment, "why", strings.Join(v.why, "; "))
	}
	return true
}

func mismatchReasons(ms []compose.ComposeMismatch) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		s := m.Reason
		if m.Service != "" {
			s = m.Service + ": " + s
		}
		if m.Diff != "" {
			s += " (" + m.Diff + ")"
		}
		out = append(out, s)
	}
	return out
}
