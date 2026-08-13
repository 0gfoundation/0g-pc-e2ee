package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

type stubService struct {
	info chain.ServiceInfo
	err  error
}

func (s stubService) ServiceInfo(context.Context, string) (chain.ServiceInfo, error) {
	return s.info, s.err
}

type stubQuote struct {
	v   attest.Verified
	err error
}

func (s stubQuote) FetchAndVerify(context.Context, string) (attest.Verified, error) {
	return s.v, s.err
}

const (
	prov   = "0xaabbccddeeff00112233445566778899aabbccdd"
	signer = "0x99887766554433221100ffeeddccbbaa99887766"
)

// On-chain-only (qc == nil): the earlier tool's behavior.
func TestReport_OnChainOnly(t *testing.T) {
	cases := []struct {
		name         string
		svc          stubService
		expectSigner string
		wantCode     int
	}{
		{"acknowledged", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: true}}, "", 0},
		{"expected matches", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: true}}, strings.ToUpper(signer), 0},
		{"expected mismatch", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: true}}, "0x0000000000000000000000000000000000000001", 1},
		{"unacknowledged", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: false}}, "", 1},
		{"lookup error", stubService{err: errors.New("rpc down")}, "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := report(context.Background(), &out, tc.svc, nil, prov, "0xcontract", "", tc.expectSigner)
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d\n%s", code, tc.wantCode, out.String())
			}
		})
	}
}

// With a quote checker: full chain including hop-5 cross-check.
func TestReport_WithQuote(t *testing.T) {
	acked := chain.ServiceInfo{URL: "https://prov.example/v1", Signer: signer, Acknowledged: true}
	cases := []struct {
		name     string
		svc      stubService
		qc       stubQuote
		wantCode int
		contains string
	}{
		{"all pass", stubService{info: acked}, stubQuote{v: attest.Verified{SignerAddr: signer}}, 0, "PASS"},
		{"quote signer mismatch", stubService{info: acked},
			stubQuote{v: attest.Verified{SignerAddr: "0x0000000000000000000000000000000000000002"}}, 1, "FAIL"},
		{"quote fetch/verify error", stubService{info: acked}, stubQuote{err: errors.New("not a genuine TDX quote")}, 1, "FAIL"},
		{"no endpoint on chain", stubService{info: chain.ServiceInfo{Signer: signer, Acknowledged: true}},
			stubQuote{v: attest.Verified{SignerAddr: signer}}, 1, "no endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := report(context.Background(), &out, tc.svc, tc.qc, prov, "0xcontract", "", "")
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d\n%s", code, tc.wantCode, out.String())
			}
			if !strings.Contains(out.String(), tc.contains) {
				t.Errorf("output missing %q:\n%s", tc.contains, out.String())
			}
		})
	}
}

// Provider mode is where the audited boot chains have to come FROM: the allowlist is
// empty, so the only way a first entry ever gets recorded is by reading it off a run
// against a provider. That makes printing all three pinned registers the point of the
// step, not decoration — MRTD alone said a check had not happened without letting
// anyone do something about it.
func TestReport_PrintsTheBootChainInAllowlistShape(t *testing.T) {
	var m attest.Measurement
	for i := range m.MRTD {
		m.MRTD[i], m.RTMR1[i], m.RTMR2[i] = 0x3f, 0xaa, 0x5d
		m.RTMR0[i], m.RTMR3[i] = 0x01, 0x77
	}
	acked := chain.ServiceInfo{URL: "https://prov.example/v1", Signer: signer, Acknowledged: true}

	var out bytes.Buffer
	code := report(context.Background(), &out, stubService{info: acked},
		stubQuote{v: attest.Verified{SignerAddr: signer, Measurement: m}}, prov, "0xcontract", "", "")
	// An unconfigured allowlist is not a verdict on the provider, so the run still
	// passes on the hops it did check.
	if code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out.String())
	}
	got := out.String()

	for _, want := range []string{
		"- boot chain",                 // not compared, and not dressed up as a ✓
		"no allowlist configured",      // says why, so nobody reads it as a pass
		strings.Repeat("3f", 48),       // mrtd
		strings.Repeat("aa", 48),       // rtmr1
		strings.Repeat("5d", 48),       // rtmr2
		"rtmr0 (vm shape, not pinned)", // shown, labelled as not compared
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// RTMR3 must NOT be offered: it carries per-instance events, so pasting it into an
	// entry is exactly the mistake that kept this allowlist unfillable.
	if strings.Contains(got, strings.Repeat("77", 48)) {
		t.Errorf("RTMR3 must not be printed as an allowlist value:\n%s", got)
	}
}

// A configured allowlist that the provider misses is a finding, and must fail the run
// rather than print observed registers and pass. Guards the branch that only becomes
// reachable once providerBootChains is populated.
func TestReport_BootChainMismatchFails(t *testing.T) {
	restore := providerBootChains
	providerBootChains = []attest.BootChain{attest.BootChainOf(attest.Measurement{})}
	t.Cleanup(func() { providerBootChains = restore })

	acked := chain.ServiceInfo{URL: "https://prov.example/v1", Signer: signer, Acknowledged: true}
	var out bytes.Buffer
	// MeasurementTrusted false with a non-empty allowlist: the provider's image is not
	// one that was audited.
	code := report(context.Background(), &out, stubService{info: acked},
		stubQuote{v: attest.Verified{SignerAddr: signer}}, prov, "0xcontract", "", "")
	if code != 1 {
		t.Errorf("code = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "matches no audited image") {
		t.Errorf("output must name the mismatch:\n%s", out.String())
	}
}

// -endpoint overrides the on-chain URL.
func TestReport_EndpointOverride(t *testing.T) {
	var out bytes.Buffer
	svc := stubService{info: chain.ServiceInfo{URL: "https://from-chain/v1", Signer: signer, Acknowledged: true}}
	code := report(context.Background(), &out, svc, stubQuote{v: attest.Verified{SignerAddr: signer}}, prov, "0xc", "https://override/v1", "")
	if code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "https://override/v1 (from -endpoint)") {
		t.Errorf("expected endpoint override in output:\n%s", out.String())
	}
}

func TestRun_MissingProvider(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), &out, []string{"-no-quote", "-chain-rpc-url", "http://127.0.0.1:0"}); code != 2 {
		t.Errorf("missing -provider: exit = %d, want 2", code)
	}
}

func TestQuoteURLFromEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://h/v1":                  "https://h/v1/quote?legacy=false",
		"https://h":                     "https://h/v1/quote?legacy=false",
		"https://h/v1/chat/completions": "https://h/v1/quote?legacy=false",
		"http://h:8080/":                "http://h:8080/v1/quote?legacy=false",
	}
	for in, want := range cases {
		got, err := quoteURLFromEndpoint(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "ftp://h", "not a url", "https://"} {
		if _, err := quoteURLFromEndpoint(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
