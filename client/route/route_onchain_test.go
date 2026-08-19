package route

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

type stubRegistry struct {
	signer string
	ack    bool
	err    error
}

func (s stubRegistry) AcknowledgedSigner(context.Context, string) (string, bool, error) {
	return s.signer, s.ack, s.err
}

func newOnChainRouter(reg stubRegistry, enforce bool) *Router {
	return &Router{
		registry:       reg,
		onchainEnforce: enforce,
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

const (
	ocProvider = "0xaabbccddeeff00112233445566778899aabbccdd"
	ocSigner   = "0x99887766554433221100ffeeddccbbaa99887766"
)

func TestGroundSignerOnChain_Match(t *testing.T) {
	// A matching, acknowledged signer passes in both modes.
	for _, enforce := range []bool{false, true} {
		r := newOnChainRouter(stubRegistry{signer: ocSigner, ack: true}, enforce)
		verdict, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
		if err != nil {
			t.Errorf("enforce=%v: match should pass, got %v", enforce, err)
		}
		if verdict != VerdictPass {
			t.Errorf("enforce=%v: verdict = %q, want %q", enforce, verdict, VerdictPass)
		}
	}
}

func TestGroundSignerOnChain_MatchCaseInsensitive(t *testing.T) {
	// Address comparison must be case-insensitive (EIP-55 vs lowercase).
	r := newOnChainRouter(stubRegistry{signer: "0x99887766554433221100FFEEDDCCBBAA99887766", ack: true}, true)
	if _, err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err != nil {
		t.Errorf("case-insensitive match should pass, got %v", err)
	}
}

func TestGroundSignerOnChain_Negatives(t *testing.T) {
	cases := []struct {
		name string
		reg  stubRegistry
		// want is the verdict the check reached. A negative ANSWER (mismatch,
		// unacknowledged) is a finding about the provider; a lookup that could not be
		// made is not, and reporting it as one would accuse every provider whenever the
		// chain RPC is down.
		want Verdict
	}{
		{"mismatch", stubRegistry{signer: "0x0000000000000000000000000000000000000001", ack: true}, VerdictNoMatch},
		{"unacknowledged", stubRegistry{signer: testSigner, ack: false}, VerdictNoMatch},
		{"rpc error", stubRegistry{err: errors.New("rpc down")}, VerdictUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// enforce: fail-closed (candidate skipped).
			rEnforce := newOnChainRouter(tc.reg, true)
			verdict, err := rEnforce.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
			if err == nil {
				t.Errorf("enforce: %s should fail-closed, got nil", tc.name)
			}
			if verdict != tc.want {
				t.Errorf("enforce: verdict = %q, want %q", verdict, tc.want)
			}
			// warn: observe-only for the sealing decision, but the verdict is still
			// reported — that is what keeps warn mode from being invisible.
			rWarn := newOnChainRouter(tc.reg, false)
			verdict, err = rWarn.groundSignerOnChain(context.Background(), ocProvider, ocSigner)
			if err != nil {
				t.Errorf("warn: %s should proceed, got %v", tc.name, err)
			}
			if verdict != tc.want {
				t.Errorf("warn: verdict = %q, want %q", verdict, tc.want)
			}
		})
	}
}
