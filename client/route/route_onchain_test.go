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

// A lookup failure says nothing about the provider. Under enforce it must still
// proceed by default, because the lookup is on the request path for every
// candidate: failing it would turn a chain-RPC outage into a total outage.
func TestGroundSignerOnChain_LookupFailureDegradesByDefault(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		reg := &stubRegistry{err: errors.New("rpc down")}
		r := newOnChainRouter(reg, enforce)
		outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
		if err != nil {
			t.Errorf("enforce=%v: a lookup failure should proceed ungrounded, got %v", enforce, err)
		}
		if outcome != groundingLookupFailed {
			t.Errorf("enforce=%v: outcome = %s, want %s", enforce, outcome, groundingLookupFailed)
		}
	}
}

// ...unless the operator explicitly asks for the strict reading.
func TestGroundSignerOnChain_LookupFailureFailsClosedWhenRequired(t *testing.T) {
	reg := &stubRegistry{err: errors.New("rpc down")}
	r := newOnChainRouter(reg, true)
	r.onchainRequireLookup = true
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if err == nil {
		t.Error("with require-lookup, a lookup failure should fail-closed")
	}
	if outcome != groundingLookupFailed {
		t.Errorf("outcome = %s, want %s", outcome, groundingLookupFailed)
	}
	// Warn mode stays observe-only regardless of the strict knob.
	reg2 := &stubRegistry{err: errors.New("rpc down")}
	rWarn := newOnChainRouter(reg2, false)
	rWarn.onchainRequireLookup = true
	if _, err := rWarn.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err != nil {
		t.Errorf("warn mode should stay observe-only, got %v", err)
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

// If the revalidation itself cannot reach the chain, we have no fresh evidence —
// so the result is a lookup failure, not a mismatch verdict.
func TestGroundSignerOnChain_StaleMismatchWithFailedRevalidation(t *testing.T) {
	reg := &stubRegistry{
		signer:     ocOther,
		ack:        true,
		stale:      true,
		refreshErr: errors.New("rpc down"),
	}
	r := newOnChainRouter(reg, true)
	outcome, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
	if outcome != groundingLookupFailed {
		t.Errorf("outcome = %s, want %s (no fresh evidence is not a verdict)", outcome, groundingLookupFailed)
	}
	if err != nil {
		t.Errorf("without require-lookup this should proceed ungrounded, got %v", err)
	}
}
