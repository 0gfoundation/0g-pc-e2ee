package route

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
)

type stubRegistry struct {
	signer string
	ack    bool
	stale  bool
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
	return chain.Signer{Address: s.signer, Acknowledged: s.ack, Stale: s.stale}, nil
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
	ocProvider = "0xaabbccddeeff00112233445566778899aabbccdd"
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
		if outcome != groundingOK {
			t.Errorf("enforce=%v: outcome = %s, want %s", enforce, outcome, groundingOK)
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
			if outcome != tc.want {
				t.Errorf("outcome = %s, want %s", outcome, tc.want)
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
	if outcome != groundingLookupFailed {
		t.Errorf("outcome = %s, want %s (not a verdict about the provider)", outcome, groundingLookupFailed)
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
	if outcome != groundingLookupFailed {
		t.Errorf("outcome = %s, want %s", outcome, groundingLookupFailed)
	}
}

// The class split buys attribution, not leniency: a lookup failure is fail-closed
// like any other negative under enforce, but must never be recorded as a verdict
// about the provider — our RPC's bad day is not an accusation.
func TestGroundSignerOnChain_LookupFailureIsNotReportedAsAVerdict(t *testing.T) {
	reg := &stubRegistry{err: errors.New("rpc down")}
	r := newOnChainRouter(reg, true)
	outcome, _ := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if outcome == groundingMismatch || outcome == groundingNotAcknowledged {
		t.Errorf("outcome = %s: a chain-RPC failure must not be attributed to the provider", outcome)
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
	if outcome != groundingOKStale {
		t.Errorf("outcome = %s, want %s", outcome, groundingOKStale)
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
	if outcome != groundingOK {
		t.Errorf("outcome = %s, want %s (the fresh read is not stale)", outcome, groundingOK)
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
	if outcome != groundingMismatch {
		t.Errorf("outcome = %s, want %s", outcome, groundingMismatch)
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
	if outcome != groundingLookupFailed {
		t.Errorf("outcome = %s, want %s (no fresh evidence is not a verdict)", outcome, groundingLookupFailed)
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
