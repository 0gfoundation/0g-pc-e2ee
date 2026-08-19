package route

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
)

type stubRegistry struct {
	signer string
	ack    bool
	stale  bool
	// cached marks a reading that came from the cache but is still within its TTL —
	// the case a naive "only re-read when Stale" rule misses, since a within-TTL
	// entry can still predate a rotation.
	cached bool
	err    error

	// refresh, when set, is what a live RefreshSigner returns instead of the
	// cached-shaped fields above — the shape of a benign rotation, where the stale
	// entry disagrees but a fresh read agrees.
	refresh    *chain.Signer
	refreshErr error

	lookups  int
	refreshs int
}

func (s *stubRegistry) AcknowledgedSigner(context.Context, string) (chain.Signer, error) {
	s.lookups++
	if s.err != nil {
		return chain.Signer{}, s.err
	}
	return chain.Signer{
		Address: s.signer, Acknowledged: s.ack,
		Stale: s.stale, Cached: s.cached || s.stale, // Stale implies Cached
	}, nil
}

func (s *stubRegistry) RefreshSigner(ctx context.Context, providerAddr string) (chain.Signer, error) {
	s.refreshs++
	if s.refreshErr != nil {
		return chain.Signer{}, s.refreshErr
	}
	if s.refresh != nil {
		return *s.refresh, nil
	}
	return s.AcknowledgedSigner(ctx, providerAddr)
}

func newOnChainRouter(reg *stubRegistry, enforce bool) *Router {
	return &Router{
		registry:       reg,
		onchainEnforce: enforce,
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

const (
	// Mixed case on purpose. The router returns EIP-55 checksummed addresses, so an
	// all-lowercase fixture is a spelling the production path rarely sees — and every
	// key derived from this address is canonicalized, so a lowercase fixture cannot
	// tell a canonicalized key from a raw one. That blind spot hid a limiter whose
	// read and write used different keys.
	ocProvider = "0xAaBbCcDdEeFf00112233445566778899AaBbCcDd"
	ocSigner   = "0x99887766554433221100ffeeddccbbaa99887766"
	ocOther    = "0x0000000000000000000000000000000000000001"
)

func TestGroundSignerOnChain_Match(t *testing.T) {
	// A matching, acknowledged signer passes in both modes.
	for _, enforce := range []bool{false, true} {
		r := newOnChainRouter(&stubRegistry{signer: ocSigner, ack: true}, enforce)
		outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
		if err != nil {
			t.Errorf("enforce=%v: match should pass, got %v", enforce, err)
		}
		if outcome.outcome != groundingOK {
			t.Errorf("enforce=%v: outcome = %s, want %s", enforce, outcome.outcome, groundingOK)
		}
	}
}

func TestGroundSignerOnChain_MatchCaseInsensitive(t *testing.T) {
	// Address comparison must be case-insensitive (EIP-55 vs lowercase).
	r := newOnChainRouter(&stubRegistry{signer: "0x99887766554433221100FFEEDDCCBBAA99887766", ack: true}, true)
	if _, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err != nil {
		t.Errorf("case-insensitive match should pass, got %v", err)
	}
}

// A verdict about the PROVIDER is fail-closed under enforce.
func TestGroundSignerOnChain_VerdictsFailClosedUnderEnforce(t *testing.T) {
	cases := []struct {
		name string
		reg  stubRegistry
		want groundingOutcome
	}{
		{"mismatch", stubRegistry{signer: ocOther, ack: true}, groundingMismatch},
		{"unacknowledged", stubRegistry{signer: ocSigner, ack: false}, groundingNotAcknowledged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := tc.reg
			rEnforce := newOnChainRouter(&reg, true)
			outcome, err := rEnforce.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
			if err == nil {
				t.Errorf("enforce: %s should fail-closed, got nil", tc.name)
			}
			if outcome.outcome != tc.want {
				t.Errorf("outcome = %s, want %s", outcome.outcome, tc.want)
			}
			// warn: observe-only (proceed).
			reg2 := tc.reg
			rWarn := newOnChainRouter(&reg2, false)
			if _, err := rWarn.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err != nil {
				t.Errorf("warn: %s should proceed, got %v", tc.name, err)
			}
		})
	}
}

// Under enforce, a lookup failure is fail-closed by default: "enforce" should mean
// the chain was actually read, not merely consulted. It is still reported as
// lookup_failed rather than as a verdict, so a chain problem never reads as a
// provider accusation.
func TestGroundSignerOnChain_LookupFailureFailsClosedUnderEnforce(t *testing.T) {
	reg := &stubRegistry{err: errors.New("rpc down")}
	r := newOnChainRouter(reg, true)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err == nil {
		t.Error("enforce: an unreadable chain should fail-closed by default")
	}
	if outcome.outcome != groundingLookupFailed {
		t.Errorf("outcome = %s, want %s (not a verdict about the provider)", outcome.outcome, groundingLookupFailed)
	}
}

// Warn mode proceeds on a lookup failure like it does on every other negative.
func TestGroundSignerOnChain_LookupFailureProceedsUnderWarn(t *testing.T) {
	reg := &stubRegistry{err: errors.New("rpc down")}
	r := newOnChainRouter(reg, false)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err != nil {
		t.Errorf("warn: a lookup failure should proceed, got %v", err)
	}
	if outcome.outcome != groundingLookupFailed {
		t.Errorf("outcome = %s, want %s", outcome.outcome, groundingLookupFailed)
	}
}

// The class split buys attribution, not leniency: a lookup failure is fail-closed
// like any other negative under enforce, but must never be recorded as a verdict
// about the provider — our RPC's bad day is not an accusation.
func TestGroundSignerOnChain_LookupFailureIsNotReportedAsAVerdict(t *testing.T) {
	reg := &stubRegistry{err: errors.New("rpc down")}
	r := newOnChainRouter(reg, true)
	outcome, _ := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if outcome.outcome == groundingMismatch || outcome.outcome == groundingNotAcknowledged {
		t.Errorf("outcome = %s: a chain-RPC failure must not be attributed to the provider", outcome.outcome)
	}
}

// A stale entry may CONFIRM a match without a live re-read: the value agrees, so
// there is nothing to refute.
func TestGroundSignerOnChain_StaleMatchNeedsNoRevalidation(t *testing.T) {
	reg := &stubRegistry{signer: ocSigner, ack: true, stale: true}
	r := newOnChainRouter(reg, true)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err != nil {
		t.Fatalf("a stale match should pass, got %v", err)
	}
	if outcome.outcome != groundingOKStale {
		t.Errorf("outcome = %s, want %s", outcome.outcome, groundingOKStale)
	}
	if reg.refreshs != 0 {
		t.Errorf("refreshed %d times, want 0 (nothing to refute)", reg.refreshs)
	}
}

// The core of the asymmetry: a stale entry must never CONDEMN a provider. This is
// the benign-rotation shape — a broker upgrade rotated the signer, the stale
// entry still names the old one, and a live read agrees with the quote.
func TestGroundSignerOnChain_StaleMismatchRevalidatesAndPasses(t *testing.T) {
	reg := &stubRegistry{
		signer:  ocOther, // stale entry: the pre-rotation signer
		ack:     true,
		stale:   true,
		refresh: &chain.Signer{Address: ocSigner, Acknowledged: true},
	}
	r := newOnChainRouter(reg, true)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err != nil {
		t.Fatalf("a stale disagreement that a live read resolves must not reject: %v", err)
	}
	if outcome.outcome != groundingOK {
		t.Errorf("outcome = %s, want %s (the fresh read is not stale)", outcome.outcome, groundingOK)
	}
	if reg.refreshs != 1 {
		t.Errorf("refreshed %d times, want exactly 1", reg.refreshs)
	}
}

// A genuine mismatch still fails after revalidation — the guard must not become a
// way to launder a real disagreement.
func TestGroundSignerOnChain_StaleMismatchSurvivesRevalidation(t *testing.T) {
	reg := &stubRegistry{
		signer:  ocOther,
		ack:     true,
		stale:   true,
		refresh: &chain.Signer{Address: ocOther, Acknowledged: true},
	}
	r := newOnChainRouter(reg, true)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err == nil {
		t.Error("a mismatch confirmed by a live read should fail-closed")
	}
	if outcome.outcome != groundingMismatch {
		t.Errorf("outcome = %s, want %s", outcome.outcome, groundingMismatch)
	}
}

// If the revalidation itself cannot reach the chain, we have no fresh evidence.
// The stale entry disagrees, so we cannot confirm; it is stale, so we may not
// condemn. That is a lookup failure, not a mismatch verdict — and under enforce it
// is fail-closed as such, without ever being recorded as an accusation against the
// provider.
func TestGroundSignerOnChain_StaleMismatchWithFailedRevalidation(t *testing.T) {
	newReg := func() *stubRegistry {
		return &stubRegistry{
			signer:     ocOther,
			ack:        true,
			stale:      true,
			refreshErr: errors.New("rpc down"),
		}
	}
	r := newOnChainRouter(newReg(), true)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if outcome.outcome != groundingLookupFailed {
		t.Errorf("outcome = %s, want %s (no fresh evidence is not a verdict)", outcome.outcome, groundingLookupFailed)
	}
	if err == nil {
		t.Error("enforce: no fresh evidence should fail-closed")
	}

	// Warn mode proceeds, as it does on every negative.
	rWarn := newOnChainRouter(newReg(), false)
	if _, err := rWarn.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err != nil {
		t.Errorf("warn: should proceed, got %v", err)
	}
}

// "Within its TTL" is not "true right now": a cached entry can be minutes old and
// still predate a rotation. Ruling on it would reject a healthy provider for as
// long as the entry lives, so a disagreement with ANY cached reading gets a live
// re-read — not only one whose TTL happened to lapse.
func TestGroundSignerOnChain_FreshCachedMismatchAlsoRevalidates(t *testing.T) {
	reg := &stubRegistry{
		signer:  ocOther, // cached, within TTL, but pre-rotation
		ack:     true,
		cached:  true,
		refresh: &chain.Signer{Address: ocSigner, Acknowledged: true},
	}
	r := newOnChainRouter(reg, true)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err != nil {
		t.Fatalf("a cached disagreement a live read resolves must not reject: %v", err)
	}
	if outcome.outcome != groundingOK {
		t.Errorf("outcome = %s, want %s", outcome.outcome, groundingOK)
	}
	if reg.refreshs != 1 {
		t.Errorf("refreshed %d times, want 1", reg.refreshs)
	}
}

// A reading taken live needs no second opinion: it IS the fresh evidence, so a
// disagreement is a verdict straight away.
func TestGroundSignerOnChain_LiveMismatchNeedsNoRevalidation(t *testing.T) {
	reg := &stubRegistry{signer: ocOther, ack: true} // not cached
	r := newOnChainRouter(reg, true)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err == nil {
		t.Error("a live mismatch should fail-closed")
	}
	if outcome.outcome != groundingMismatch {
		t.Errorf("outcome = %s, want %s", outcome.outcome, groundingMismatch)
	}
	if reg.refreshs != 0 {
		t.Errorf("refreshed %d times, want 0 (the reading was already live)", reg.refreshs)
	}
}

// A provider that keeps disagreeing must not turn the re-read into a chain RPC
// per request: the rate limit is what makes "prefer evidence over a verdict"
// affordable rather than a lever to pull.
func TestGroundSignerOnChain_RevalidationIsRateLimited(t *testing.T) {
	reg := &stubRegistry{
		signer:  ocOther,
		ack:     true,
		cached:  true,
		refresh: &chain.Signer{Address: ocOther, Acknowledged: true}, // still disagrees
	}
	r := newOnChainRouter(reg, true)
	for i := 0; i < 5; i++ {
		if _, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err == nil {
			t.Fatalf("round %d: want fail-closed", i)
		}
	}
	if reg.refreshs != 1 {
		t.Errorf("refreshed %d times across 5 requests, want 1 (rate-limited)", reg.refreshs)
	}
}

// One revalidation is one count. The failure branch used to record its own
// lookup_failed on top of the caller's, so a single failed re-read showed up
// twice — and the comment right beside it claimed the opposite, which is how it
// survived: the rule ("the caller records one revalidation") was stated as
// unconditional while one branch quietly broke it.
func TestGroundSignerOnChain_FailedRevalidationCountedOnce(t *testing.T) {
	const series = `zg_gateway_onchain_revalidations_total{result="lookup_failed"}`
	before := metricValue(t, series)

	reg := &stubRegistry{
		signer:     ocOther,
		ack:        true,
		cached:     true,
		refreshErr: errors.New("rpc down"),
	}
	r := newOnChainRouter(reg, true)
	outcome, _ := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if outcome.outcome != groundingLookupFailed || !outcome.revalidated {
		t.Fatalf("setup: got %+v, want a revalidated lookup_failed", outcome)
	}
	// The caller records; this test drives groundSignerOnChain directly, so emit the
	// caller's count the same way Provider does.
	metrics.OnChainRevalidation(revalidationResult(outcome.outcome))

	if delta := metricValue(t, series) - before; delta != 1 {
		t.Errorf("recorded %v revalidations for one re-read, want 1", delta)
	}
}

// A re-read that failed says nothing about the provider, so it must not spend the
// whole window. Otherwise a rotation that coincides with one RPC blip is judged a
// mismatch for the rest of that window even after the chain recovers: the cached
// entry still disagrees and nothing is allowed to look again — filing our own
// outage under the metric documented as an accusation.
func TestGroundSignerOnChain_FailedRevalidationDoesNotBurnTheWindow(t *testing.T) {
	clock := time.Unix(1000, 0)
	reg := &stubRegistry{
		signer:     ocOther, // cached, pre-rotation
		ack:        true,
		cached:     true,
		refreshErr: errors.New("rpc down"),
	}
	r := newOnChainRouter(reg, true)
	r.signerRevalidate.now = func() time.Time { return clock }

	// t0: the chain is unreachable, so the disagreement is unresolved.
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err == nil || outcome.outcome != groundingLookupFailed {
		t.Fatalf("t0: got (%+v, %v), want a fail-closed lookup_failed", outcome, err)
	}

	// The chain comes back moments later, agreeing with the rotated quote.
	reg.refreshErr = nil
	reg.refresh = &chain.Signer{Address: ocSigner, Acknowledged: true}
	clock = clock.Add(reverifyFailureBackoff + time.Second)

	outcome, err = r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err != nil {
		t.Fatalf("after recovery: want the provider accepted, got %v", err)
	}
	if outcome.outcome != groundingOK {
		t.Errorf("outcome = %s, want %s — the blip should not have cost the window",
			outcome.outcome, groundingOK)
	}
}

// The window still holds for a re-read that CONCLUDED something: a provider that
// really does keep disagreeing must not get a chain RPC per request just because
// the previous attempt succeeded in refuting it.
func TestGroundSignerOnChain_ConcludedRevalidationKeepsTheWindow(t *testing.T) {
	clock := time.Unix(1000, 0)
	reg := &stubRegistry{
		signer:  ocOther,
		ack:     true,
		cached:  true,
		refresh: &chain.Signer{Address: ocOther, Acknowledged: true}, // still disagrees
	}
	r := newOnChainRouter(reg, true)
	r.signerRevalidate.now = func() time.Time { return clock }

	if _, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err == nil {
		t.Fatal("want fail-closed")
	}
	clock = clock.Add(reverifyFailureBackoff + time.Second) // past the FAILURE backoff...
	if _, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err == nil {
		t.Fatal("want fail-closed")
	}
	if reg.refreshs != 1 {
		t.Errorf("refreshed %d times, want 1 (a conclusive re-read holds the full window)", reg.refreshs)
	}
}

// The rate limiter's key comes from the untrusted router, and every comparison on
// a provider address elsewhere is case-insensitive. Keyed on the raw spelling, the
// same provider capitalized differently was a NEW key with a fresh allowance — so
// the party choosing the spelling could step around the limit, and each step is a
// live RefreshSigner: an eth_call that bypasses chain.FailureCooldown, against the
// one chain RPC endpoint this deployment has. The trigger needs no compromised
// enclave, just a preview pairing provider A's address with provider B's endpoint.
func TestGroundSignerOnChain_RevalidationLimitSurvivesCaseTricks(t *testing.T) {
	reg := &stubRegistry{
		signer:  ocOther,
		ack:     true,
		cached:  true,
		refresh: &chain.Signer{Address: ocOther, Acknowledged: true}, // keeps disagreeing
	}
	r := newOnChainRouter(reg, true)

	spellings := []string{
		ocProvider,
		strings.ToUpper("0x") + strings.ToUpper(ocProvider[2:]), // shouted
		strings.ToLower(ocProvider),                             // the canonical key itself
		"  " + ocProvider + "  ",                                // padded
	}
	for i, addr := range spellings {
		if _, err := r.groundSignerOnChain(context.Background(), addr, ocSigner); err == nil {
			t.Fatalf("spelling %d: want fail-closed", i)
		}
	}
	if reg.refreshs != 1 {
		t.Errorf("refreshed %d times across %d spellings of one address, want 1",
			reg.refreshs, len(spellings))
	}
}
