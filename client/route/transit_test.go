package route

import (
	"context"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
)

// The preview's encrypted_transit is read (case-folded) and carried on the
// candidates — for core to honour its required — but never turns into anything
// that skips sealing: an off from the router resolves candidates like any other.
func TestResolve_EncryptedTransit(t *testing.T) {
	router := newMockRouter(t, newMockBroker(t))
	r := New(router.srv.URL)

	for raw, want := range map[string]string{"Off": core.TransitOff, "required": core.TransitRequired, "preferred": core.TransitPreferred, "": ""} {
		router.transit = raw
		cands, err := r.Resolve(core.WithPlaintextPermitted(context.Background()), endpoint.Chat, chatReq())
		if err != nil || cands.Len() == 0 {
			t.Fatalf("%q: Resolve = %v; want candidates", raw, err)
		}
		if tc, ok := cands.(core.TransitCandidates); !ok || tc.EncryptedTransit() != want {
			t.Errorf("%q: candidates carry %v, want %q", raw, cands, want)
		}
		if got, _ := r.EncryptedTransit(context.Background(), endpoint.Chat, chatReq()); got != want {
			t.Errorf("EncryptedTransit = %q, want %q", got, want)
		}
	}
}

// A value this build does not know is read as required (fail closed, never a
// downgrade) and counted; nothing else leaves the four known strings.
func TestNormalizeTransit(t *testing.T) {
	for in, want := range map[string]string{
		"": "", " Off ": core.TransitOff, "PREFERRED": core.TransitPreferred, "required": core.TransitRequired,
		"required_strict": core.TransitRequired, "sometimes": core.TransitRequired,
	} {
		if got := normalizeTransit(in); got != want {
			t.Errorf("normalizeTransit(%q) = %q, want %q", in, got, want)
		}
	}

	const series = `zg_gateway_encrypted_transit_unknown_total`
	before := metricValue(t, series)
	router := newMockRouter(t, newMockBroker(t))
	router.transit = "required_strict"
	got, err := New(router.srv.URL).EncryptedTransit(context.Background(), endpoint.Chat, chatReq())
	if err != nil || got != core.TransitRequired {
		t.Fatalf("EncryptedTransit = %q, %v; want required", got, err)
	}
	if d := metricValue(t, series) - before; d != 1 {
		t.Errorf("%s delta = %v, want 1", series, d)
	}
}
