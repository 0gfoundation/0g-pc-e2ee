package route

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A candidate this gateway's own verification refused is marked
// core.ErrProviderRefused, so the walk never answers it with plaintext under
// preferred; a failure that says nothing about the provider is not. The message
// stays the verifier's own.
func TestRefusal_MarksVerdictsOnly(t *testing.T) {
	provider := func(r *Router) error {
		t.Helper()
		cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		_, err = cands.Provider(context.Background(), 0)
		return err
	}
	verifier := func(served attest.Measurement) *attest.Verifier {
		return attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(qvMeasurement(0xaa))}},
			attest.WithQuoteParser(qvParser(served, qvReportData(t))))
	}

	t.Run("a quote that does not verify is refused", func(t *testing.T) {
		err := provider(New(qvServer(t, 0).URL, WithQuoteVerification(verifier(qvMeasurement(0xbb)), nil)))
		if !errors.Is(err, core.ErrProviderRefused) || !errors.Is(err, attest.ErrUntrustedMeasurement) {
			t.Fatalf("err = %v, want a refusal wrapping ErrUntrustedMeasurement", err)
		}
	})
	t.Run("a quote that could not be fetched is not", func(t *testing.T) {
		err := provider(New(qvServer(t, http.StatusServiceUnavailable).URL, WithQuoteVerification(verifier(qvMeasurement(0xaa)), nil)))
		if err == nil || errors.Is(err, core.ErrProviderRefused) {
			t.Fatalf("err = %v, want an error that is not a refusal", err)
		}
	})
	t.Run("the provider checks refusing is refused", func(t *testing.T) {
		err := rtServe(enRouter(t, blTestnetProvider, blTestnetContract, "testnet-rehearsal-v0.5.4", nil))
		if !errors.Is(err, core.ErrProviderRefused) {
			t.Fatalf("err = %v, want a refusal", err)
		}
	})
}

func TestRefusal_OnChain(t *testing.T) {
	for name, tc := range map[string]struct {
		reg     stubRegistry
		refused bool
	}{
		"mismatch":       {stubRegistry{signer: ocOther, ack: true}, true},
		"unacknowledged": {stubRegistry{signer: ocSigner, ack: false}, true},
		"lookup failed":  {stubRegistry{err: errors.New("rpc down")}, false},
	} {
		reg := tc.reg
		_, err := newOnChainRouter(&reg, true).groundSignerOnChain(context.Background(), ocProvider, ocSigner)
		if err == nil || errors.Is(err, core.ErrProviderRefused) != tc.refused {
			t.Errorf("%s: err = %v, refused want %v", name, err, tc.refused)
		}
	}
}

func TestRefusal_KeepsTheMessage(t *testing.T) {
	inner := errors.New("provider quote: bad signature")
	if err := upstream(0, refusal(inner)); !errors.Is(err, inner) || !errors.Is(err, core.ErrProviderRefused) {
		t.Fatalf("err = %v, want both the cause and the mark", err)
	}
	if got := refusal(inner).Error(); got != inner.Error() {
		t.Errorf("message = %q, want %q", got, inner.Error())
	}
}
