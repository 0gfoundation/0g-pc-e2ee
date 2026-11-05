package route

import (
	"context"
	"errors"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
)

// The preview's encrypted_transit is read (case-folded), and off turns into
// core.ErrEncryptedTransitOff only for a caller with a cleartext path.
func TestResolve_EncryptedTransit(t *testing.T) {
	router := newMockRouter(t, newMockBroker(t))
	r := New(router.srv.URL)

	router.transit = "Off"
	if got, err := r.EncryptedTransit(context.Background(), endpoint.Chat, chatReq()); err != nil || got != core.TransitOff {
		t.Fatalf("EncryptedTransit = %q, %v; want off", got, err)
	}
	_, err := r.Resolve(core.WithCleartextFallback(context.Background()), endpoint.Chat, chatReq())
	if !errors.Is(err, core.ErrEncryptedTransitOff) {
		t.Fatalf("off with a cleartext path: err = %v, want ErrEncryptedTransitOff", err)
	}
	cands, err := r.Resolve(context.Background(), endpoint.Chat, chatReq())
	if err != nil || cands.Len() == 0 {
		t.Fatalf("off without a cleartext path must still resolve candidates: %v", err)
	}

	for _, v := range []string{"required", "preferred", ""} {
		router.transit = v
		cands, err := r.Resolve(core.WithCleartextFallback(context.Background()), endpoint.Chat, chatReq())
		if err != nil || cands.Len() == 0 {
			t.Fatalf("%q: Resolve = %v; want candidates", v, err)
		}
		if tc, ok := cands.(core.TransitCandidates); !ok || tc.EncryptedTransit() != v {
			t.Errorf("%q: candidates do not carry the policy for core's preferred downgrade", v)
		}
		if got, _ := r.EncryptedTransit(context.Background(), endpoint.Chat, chatReq()); got != v {
			t.Errorf("EncryptedTransit = %q, want %q", got, v)
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
