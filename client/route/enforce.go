package route

// enforce.go turns the provider checks into a gate: with WithProviderEnforce, a provider
// is sealed to only when both judgements of what it runs pass — the manifest it booted
// is the deployment recorded for it (composebaseline.go) and the broker build it runs
// now is an accepted release whose keys are the quote's (runtimerelease.go).
//
// TOGETHER OR NOT AT ALL. Each check alone passes the providers the other one judges: a
// provider that never swapped its broker has no runtime image record, so the runtime
// check has nothing to say about it, and the manifest says nothing about what the
// controller swapped in since boot. So there is one switch for both, and a runtime
// not_checked — no runtime image record, the manifest's pin runs — passes only because
// the baseline then judges that pin.
//
// FAIL-CLOSED, as -onchain-enforce is. Anything but a pass refuses the candidate:
// no_match, and equally no_baseline (nobody recorded this provider) and unavailable (a
// check that did not run). There is deliberately no knob to relax the second kind — a
// gate that lapses whenever the registry or Sigstore's TUF has a bad minute is not one
// anything may call enforced. What softens it is caching: an accepted release is
// judged once for the life of the process, so only a build never seen before depends
// on the registry answering, and that wait is bounded (providerEnforceWait).
//
// The address the baseline is keyed by comes from the router's preview, which is
// untrusted; it is the on-chain check that binds it to this enclave's signer. So the
// binaries refuse this switch without -onchain-enforce (proxycli), and it means nothing
// in direct-broker mode, where there is no address at all.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
)

// WithProviderEnforce makes the Router refuse a candidate whose provider checks do not
// both pass (see the file comment). It is meaningful only with WithQuoteVerification,
// WithReleaseVerifier and WithComposeBaseline, and with on-chain enforcement binding
// the provider's address; without the release verifier or the baseline every candidate
// is refused, which is the fail-closed reading of a check that cannot run.
func WithProviderEnforce(enforce bool) Option {
	return func(r *Router) { r.providerEnforce = enforce }
}

// providerEnforceWait bounds how long enforcement waits for the release verdicts a
// judgement is missing — a build seen for the first time, whose provenance the
// registry has not been asked for yet. Past it the check did not run, and the candidate
// is refused; the check carries on in the background, so the next request finds it.
const providerEnforceWait = 15 * time.Second

// enforceWait is providerEnforceWait, or a test's shorter bound.
func (r *Router) enforceWait() time.Duration {
	if r.providerEnforceWaitTO > 0 {
		return r.providerEnforceWaitTO
	}
	return providerEnforceWait
}

// providerPasses judges whether a verified provider passes both checks, waiting, within
// ctx and enforceWait, for any release verdict the two judgements are missing. It
// returns why it does not pass, one entry per check that failed — empty is a pass — and
// counts and logs nothing: the request path refuses on it (refuseProvider), and a
// warmer sweep only lowers readiness.
func (r *Router) providerPasses(ctx context.Context, address string, facts quoteFacts) (failed map[string]string,
	rt runtimeVerdict, bl baselineVerdict) {
	var missing [][2]string
	r.judgeRuntime(facts.runtime, lookup{start: true, missing: &missing})
	r.judgeBaseline(address, facts.manifest, lookup{start: true, missing: &missing})
	if len(missing) > 0 && r.releases != nil {
		wctx, cancel := context.WithTimeout(ctx, r.enforceWait())
		for _, b := range missing {
			r.releases.await(wctx, b[0], b[1])
		}
		cancel()
	}

	rt = r.judgeRuntime(facts.runtime, lookup{})
	bl = r.judgeBaseline(address, facts.manifest, lookup{})
	failed = map[string]string{}
	// not_checked from the runtime check is a pass only with a release verifier: then it
	// means no runtime image record, and the baseline below judges the pinned image.
	// Without one it means the check never ran.
	if !(rt.verdict == VerdictPass || rt.verdict == VerdictNotChecked && r.releases != nil) {
		failed["runtime_release"] = fmt.Sprintf("runtime_release %s (%s)", rt.verdict, strings.Join(rt.why, "; "))
	}
	if bl.verdict != VerdictPass {
		failed["compose_baseline"] = fmt.Sprintf("compose_baseline %s (%s)", bl.verdict, strings.Join(bl.why, "; "))
	}
	return failed, rt, bl
}

// refuseProvider is the request path's gate: nil when the provider passes, otherwise the
// error that refuses the candidate — counted by check and logged at warn.
func (r *Router) refuseProvider(ctx context.Context, address string, facts quoteFacts) error {
	failed, rt, bl := r.providerPasses(ctx, address, facts)
	if len(failed) == 0 {
		return nil
	}
	why := make([]string, 0, len(failed))
	for _, check := range []string{"runtime_release", "compose_baseline"} {
		if f, ok := failed[check]; ok {
			metrics.ProviderEnforceRefusal(check)
			why = append(why, f)
		}
	}
	r.logger.Warn("provider refused: what it runs did not pass the provider checks (provider enforce)",
		"provider", address, "running", rt.running, "deployment", bl.deployment, "why", strings.Join(why, "; "))
	return upstream(0, fmt.Errorf("provider %s refused (provider enforce): %s", address, strings.Join(why, "; ")))
}
