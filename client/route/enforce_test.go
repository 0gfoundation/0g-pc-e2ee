package route

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence/compose"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// enRouter serves a real /v1/quote reply at address and returns a Router comparing it
// against the shipped baseline on contract, with provider enforce on unless off.
func enRouter(t *testing.T, address, contract, vector string, rels evidence.ReleaseVerifier,
	extra ...Option) *Router {
	t.Helper()
	r, _ := enRouterURL(t, address, contract, vector, rels, extra...)
	return r
}

// enRouterURL is enRouter, also returning the provider's URL.
func enRouterURL(t *testing.T, address, contract, vector string, rels evidence.ReleaseVerifier,
	extra ...Option) (*Router, string) {
	t.Helper()
	b, err := compose.BuiltinComposeBaseline()
	if err != nil {
		t.Fatal(err)
	}
	opts := append([]Option{WithComposeBaseline(b, contract), WithProviderEnforce(true)}, extra...)
	r, srv := rtRouterAt(t, address, rtVector(t, vector, nil), rels, opts...)
	return r, srv.URL
}

// The gate on the live vectors: testnet's rehearsal CVM runs the deployment recorded for
// it on v0.5.4, so it is sealed to; cn-20 is neither on a release nor on its recorded
// deployment; a provider nobody recorded is refused though its build is a release —
// no_baseline is not a pass; and cn-1, which never swapped (runtime not_checked), is
// refused by the baseline alone.
func TestProviderEnforce_Gate(t *testing.T) {
	for _, tc := range []struct {
		name, address, contract, vector string
		refused                         []string // the checks named in the refusal
	}{
		{"testnet on its record", blTestnetProvider, blTestnetContract, "testnet-rehearsal-v0.5.4", nil},
		{"cn-20", blCN20Provider, blMainnetContract, "cn20-2026-10-16", []string{"runtime_release no_match",
			"compose_baseline no_match"}},
		{"testnet build, nobody's record", "0x00000000000000000000000000000000000000aa", blTestnetContract,
			"testnet-rehearsal-v0.5.4", []string{"compose_baseline no_baseline"}},
		{"cn-1, never swapped", "0x00000000000000000000000000000000000000bb", blMainnetContract, "cn1-2026-10-16",
			[]string{"compose_baseline no_baseline"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := enRouter(t, tc.address, tc.contract, tc.vector, fleetStub())
			err := rtServe(r)
			if len(tc.refused) == 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("sealed to a provider that does not pass")
			}
			for _, want := range tc.refused {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not name %q", err, want)
				}
			}
			for _, check := range []string{"runtime_release", "compose_baseline"} {
				named := false
				for _, want := range tc.refused {
					named = named || strings.HasPrefix(want, check)
				}
				if !named && strings.Contains(err.Error(), check) {
					t.Errorf("refusal %q names %s, which passed", err, check)
				}
			}
			// Refused, and still reported with the verdicts that refused it.
			if _, ok := r.ProviderIdentity(tc.address); !ok {
				t.Error("a refused provider left no record")
			}
		})
	}
}

// Off by default: the same provider enforce refuses is sealed to.
func TestProviderEnforce_OffSealsAnyway(t *testing.T) {
	r := enRouter(t, blCN20Provider, blMainnetContract, "cn20-2026-10-16", fleetStub(), WithProviderEnforce(false))
	if err := rtServe(r); err != nil {
		t.Fatalf("refused with enforce off: %v", err)
	}
}

// A build seen for the first time is waited for, not refused for being new; a verdict
// that does not come within the bound is a check that did not run, and refuses — and
// the check carries on, so the next request finds it.
func TestProviderEnforce_WaitsForTheReleaseVerdict(t *testing.T) {
	rels := fleetStub()
	rels.gate = make(chan struct{})
	r := enRouter(t, blTestnetProvider, blTestnetContract, "testnet-rehearsal-v0.5.4", rels)
	go func() { time.Sleep(100 * time.Millisecond); close(rels.gate) }()
	if err := rtServe(r); err != nil {
		t.Fatalf("a new build that answered within the bound was refused: %v", err)
	}

	rels = fleetStub()
	rels.gate = make(chan struct{})
	r = enRouter(t, blTestnetProvider, blTestnetContract, "testnet-rehearsal-v0.5.4", rels,
		func(r *Router) { r.providerEnforceWaitTO = 50 * time.Millisecond })
	err := rtServe(r)
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("a verdict that never came: %v", err)
	}
	close(rels.gate)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err = rtServe(r); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still refused after the verdict landed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Without a release verifier nothing can pass, and nothing does.
func TestProviderEnforce_NoReleaseVerifierRefusesEverything(t *testing.T) {
	r := enRouter(t, blTestnetProvider, blTestnetContract, "testnet-rehearsal-v0.5.4", nil)
	err := rtServe(r)
	if err == nil || !strings.Contains(err.Error(), "runtime_release not_checked") {
		t.Fatalf("got %v", err)
	}
}

// A provider a request would refuse is not ready: the warmer counts it out, as it does
// one the on-chain registry does not vouch for under that enforce.
func TestProviderEnforce_WarmerReadiness(t *testing.T) {
	for _, tc := range []struct {
		name, address, contract, vector string
		ready                           int
	}{
		{"passes", blTestnetProvider, blTestnetContract, "testnet-rehearsal-v0.5.4", 1},
		{"refused", blCN20Provider, blMainnetContract, "cn20-2026-10-16", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := attest.DecodeQuoteResponse(rtVector(t, tc.vector, nil))
			if err != nil {
				t.Fatal(err)
			}
			qb, err := attest.ParseTDXQuoteBody(raw)
			if err != nil {
				t.Fatal(err)
			}
			rd, err := attest.ParseReportData(qb.ReportData[:])
			if err != nil {
				t.Fatal(err)
			}
			r, url := enRouterURL(t, tc.address, tc.contract, tc.vector, fleetStub(),
				WithOnChainVerification(&stubRegistry{signer: rd.SignerAddr, ack: true}, true, discardLogger()))
			r.WarmOnce(context.Background(), fakeResolver{url: url})
			if got := r.WarmState(); got.Total != 1 || got.Ready != tc.ready {
				t.Fatalf("ready %d of %d, want %d of 1", got.Ready, got.Total, tc.ready)
			}
		})
	}
}
