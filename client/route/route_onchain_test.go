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
		if err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err != nil {
			t.Errorf("enforce=%v: match should pass, got %v", enforce, err)
		}
	}
}

func TestGroundSignerOnChain_MatchCaseInsensitive(t *testing.T) {
	// Address comparison must be case-insensitive (EIP-55 vs lowercase).
	r := newOnChainRouter(stubRegistry{signer: "0x99887766554433221100FFEEDDCCBBAA99887766", ack: true}, true)
	if err := r.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err != nil {
		t.Errorf("case-insensitive match should pass, got %v", err)
	}
}

func TestGroundSignerOnChain_Negatives(t *testing.T) {
	cases := []struct {
		name string
		reg  stubRegistry
	}{
		{"mismatch", stubRegistry{signer: "0x0000000000000000000000000000000000000001", ack: true}},
		{"unacknowledged", stubRegistry{signer: testSigner, ack: false}},
		{"rpc error", stubRegistry{err: errors.New("rpc down")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// enforce: fail-closed (candidate skipped).
			rEnforce := newOnChainRouter(tc.reg, true)
			if err := rEnforce.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err == nil {
				t.Errorf("enforce: %s should fail-closed, got nil", tc.name)
			}
			// warn: observe-only (proceed).
			rWarn := newOnChainRouter(tc.reg, false)
			if err := rWarn.groundSignerOnChain(context.Background(), ocProvider, ocSigner); err != nil {
				t.Errorf("warn: %s should proceed, got %v", tc.name, err)
			}
		})
	}
}
