package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

type stubEvidence struct {
	rep evidence.Report
	err error
}

func (s stubEvidence) Check(context.Context, string) (evidence.Report, error) {
	return s.rep, s.err
}

// passing is the report shape of a fully successful run, which each case below
// then breaks in one place.
func passing() evidence.Report {
	return evidence.Report{
		Domain: "pc-gateway.test",
		Files: []evidence.FileCheck{
			{Name: "acme-account.json"},
			{Name: "cert-pc-gateway.test.pem"},
		},
		CertMatch: evidence.CertExact,
		// A representative note; the real strings live in client/evidence.
		Note: "code identity is only as strong as the image pinning inside the compose text",
	}
}

func TestReportGateway(t *testing.T) {
	digestMismatch := passing()
	digestMismatch.Files[0].Got = [32]byte{0xaa}

	fetchFailed := passing()
	fetchFailed.Files[1].Err = errors.New("GET /evidences/… returned 404 Not Found")

	noManifest := passing()
	noManifest.ManifestErr = errors.New("fetch sha256sum.txt: connection refused")

	badQuote := passing()
	badQuote.QuoteErr = errors.New("not a genuine TDX quote")
	badQuote.BindingErr = errors.New("not checked: the quote did not verify")

	notBound := passing()
	notBound.BindingErr = errors.New("manifest digest aa…, quote binds bb…")

	certMismatch := passing()
	certMismatch.CertMatch = evidence.CertMismatch

	stale := passing()
	stale.CertMatch = evidence.CertSameKeyDifferentCert

	certUncheckable := passing()
	certUncheckable.CertErr = errors.New("TLS handshake with pc-gateway.test: i/o timeout")

	untrusted := passing()
	untrusted.ChainTrustErr = errors.New("x509: certificate signed by unknown authority")

	cases := []struct {
		name           string
		rep            evidence.Report
		allowUntrusted bool
		wantCode       int
		contains       string
	}{
		{name: "all pass", rep: passing(), wantCode: 0, contains: "PASS"},
		{name: "digest mismatch", rep: digestMismatch, wantCode: 1, contains: "manifest says"},
		{name: "file unfetchable", rep: fetchFailed, wantCode: 1, contains: "404"},
		{name: "no manifest", rep: noManifest, wantCode: 1, contains: "connection refused"},
		{name: "quote not genuine", rep: badQuote, wantCode: 1, contains: "not a genuine TDX quote"},
		{name: "binding mismatch", rep: notBound, wantCode: 1, contains: "quote binds"},
		{name: "served cert not in bundle", rep: certMismatch, wantCode: 1, contains: "not in the bundle"},
		{name: "stale evidence", rep: stale, wantCode: 1, contains: "stale evidence"},
		{name: "cert uncheckable", rep: certUncheckable, wantCode: 1, contains: "i/o timeout"},
		// Chain trust is its own axis: a failure fails the run by default, and only
		// -allow-untrusted-cert downgrades it. No attestation check moves either way.
		{name: "untrusted chain fails by default", rep: untrusted, wantCode: 1, contains: "unknown authority"},
		{name: "untrusted chain allowed", rep: untrusted, allowUntrusted: true, wantCode: 0, contains: "-allow-untrusted-cert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := reportGateway(context.Background(), &out, stubEvidence{rep: tc.rep}, "pc-gateway.test", tc.allowUntrusted, expectSource{})
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d\n%s", code, tc.wantCode, out.String())
			}
			if !strings.Contains(out.String(), tc.contains) {
				t.Errorf("output missing %q:\n%s", tc.contains, out.String())
			}
		})
	}
}

// Waiving chain trust must not print a bare PASS: it narrows the claim (an
// interceptor with its own attested CVM would satisfy everything else), so the
// caveat has to be on screen.
func TestReportGateway_WaivedTrustWarns(t *testing.T) {
	rep := passing()
	rep.ChainTrustErr = errors.New("x509: certificate signed by unknown authority")

	var out bytes.Buffer
	if code := reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", true, expectSource{}); code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out.String())
	}
	for _, want := range []string{"warning", "waived", "does NOT establish"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

// …and a run whose trust actually validates must NOT print that warning.
func TestReportGateway_TrustedRunHasNoWarning(t *testing.T) {
	var out bytes.Buffer
	if code := reportGateway(context.Background(), &out, stubEvidence{rep: passing()}, "pc-gateway.test", true, expectSource{}); code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "warning") {
		t.Errorf("-allow-untrusted-cert must not warn when trust validated anyway:\n%s", out.String())
	}
}

// A pass must never read as full attestation: whatever the report's note says was out
// of scope has to reach the screen.
func TestReportGateway_PassStatesItsCaveats(t *testing.T) {
	rep := passing()
	rep.Note = "the OS image is NOT pinned, so nothing establishes that the guest enforced " +
		"the compose-hash binding — treat code identity as strong evidence, not proof"

	var out bytes.Buffer
	if code := reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", false, expectSource{}); code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "not proof") {
		t.Errorf("a passing report must still surface its caveats:\n%s", out.String())
	}
}

// An unpinned OS image is reported as advisory, and a mismatch as a failure — the exit
// code follows OSImageCheck.OK, so the two must not look alike on screen either.
func TestReportGateway_OSImage(t *testing.T) {
	unpinned := passing()
	unpinned.OSImage = evidence.OSImageCheck{Configured: false}

	mismatch := passing()
	mismatch.OSImage = evidence.OSImageCheck{Configured: true,
		Err: errors.New("MRTD/RTMR0-2 match no allowlisted OS image (dstack-nvidia-0.5.4.1)")}

	matched := passing()
	matched.OSImage = evidence.OSImageCheck{Configured: true, Matched: "dstack-nvidia-0.5.4.1 (1 vCPU)"}

	cases := []struct {
		name     string
		rep      evidence.Report
		wantCode int
		contains string
	}{
		{"not pinned is advisory", unpinned, 0, "not pinned"},
		{"mismatch fails", mismatch, 1, "no allowlisted OS image"},
		{"match names the image", matched, 0, "dstack-nvidia-0.5.4.1 (1 vCPU)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := reportGateway(context.Background(), &out, stubEvidence{rep: tc.rep},
				"pc-gateway.test", false, expectSource{})
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d\n%s", code, tc.wantCode, out.String())
			}
			if !strings.Contains(out.String(), tc.contains) {
				t.Errorf("output missing %q:\n%s", tc.contains, out.String())
			}
		})
	}
	// The observed registers appear where they are actionable, and not otherwise.
	var out bytes.Buffer
	reportGateway(context.Background(), &out, stubEvidence{rep: matched}, "pc-gateway.test", false, expectSource{})
	if strings.Contains(out.String(), "observed mrtd") {
		t.Errorf("a clean match should not dump registers:\n%s", out.String())
	}
}

// An unusable domain is a caller error (exit 2), not a failed check (exit 1).
func TestReportGateway_CheckerError(t *testing.T) {
	var out bytes.Buffer
	code := reportGateway(context.Background(), &out, stubEvidence{err: errors.New("evidence: empty domain")}, "", false, expectSource{})
	if code != 2 {
		t.Errorf("code = %d, want 2\n%s", code, out.String())
	}
}

func TestRun_ModeSelection(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"neither mode", []string{}, 2},
		{"both modes", []string{"-provider", prov, "-gateway", "pc-gateway.test"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(context.Background(), &out, tc.args); code != tc.want {
				t.Errorf("exit = %d, want %d\n%s", code, tc.want, out.String())
			}
		})
	}
}

// -pccs-url is shared, not gateway-only: both modes verify a quote, so both must
// accept being pointed at a PCCS mirror. A flag-parse rejection would surface as
// exit 2; neither case here may produce that.
func TestRun_PCCSURLAppliesToBothModes(t *testing.T) {
	const mirror = "https://pccs.phala.network"
	cases := []struct {
		name string
		args []string
	}{
		// -no-quote keeps this off the network: the flag still has to parse, and the
		// chain lookup against a dead RPC is what decides the exit code.
		{"provider mode", []string{"-provider", prov, "-no-quote", "-pccs-url", mirror,
			"-chain-rpc-url", "http://127.0.0.1:0", "-timeout", "2s"}},
		// -releases 0 keeps this off GitHub; the default lookup is covered separately.
		{"gateway mode", []string{"-gateway", "gateway.invalid", "-pccs-url", mirror, "-timeout", "2s", "-releases", "0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(context.Background(), &out, tc.args); code == 2 {
				t.Errorf("-pccs-url was rejected in %s:\n%s", tc.name, out.String())
			}
		})
	}
}

// The gateway mode must not touch the chain: it takes no chain flags and a
// nonsense RPC URL is irrelevant to it. Pointed at a domain that does not
// resolve, it must still fail as a *check* (exit 1), not as a setup error.
func TestRun_GatewayModeNeedsNoChain(t *testing.T) {
	var out bytes.Buffer
	code := run(context.Background(), &out, []string{
		"-gateway", "gateway.invalid",
		"-chain-rpc-url", "http://127.0.0.1:0",
		"-timeout", "2s",
		"-releases", "0", // no GitHub lookup; this test is about the chain flags
	})
	if code != 1 {
		t.Errorf("exit = %d, want 1 (a failed check)\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "FAIL") {
		t.Errorf("expected a FAIL report:\n%s", out.String())
	}
}
