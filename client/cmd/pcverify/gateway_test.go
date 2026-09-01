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

// passing is the report shape of a fully successful run — one where every check both
// ran and passed, which is what exit 0 now means. Each case below then breaks it in
// one place.
//
// The code-identity and os-image fields are populated rather than left zero: a report
// with neither describes a run that skipped both, which is exit 3 (see
// incompleteReason), not a pass. Cases that want a partial run clear them explicitly.
func passing() evidence.Report {
	return evidence.Report{
		Domain: "pc-gateway.test",
		Files: []evidence.FileCheck{
			{Name: "acme-account.json"},
			{Name: "cert-pc-gateway.test.pem"},
		},
		CertMatch: evidence.CertExact,
		Code: evidence.CodeIdentity{
			Requested:       true,
			Source:          "55d872aa…-8090.in1.phala.network",
			ExpectRequested: true,
			MatchedExpect:   "release-2026.08.07.1",
		},
		OSImage: evidence.OSImageCheck{Configured: true, Matched: "dstack-nvidia-0.5.4.1"},
		// A representative note; the real strings live in client/evidence.
		Note: "code identity is only as strong as the image pinning inside the compose text",
	}
}

// partial is a run that failed nothing and checked less than everything: the OS image
// is unpinned and no manifest comparison happened. It is the shape exit 3 names.
func partial() evidence.Report {
	rep := passing()
	rep.Code.ExpectRequested = false
	rep.Code.MatchedExpect = ""
	rep.OSImage = evidence.OSImageCheck{}
	return rep
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

	// Same key, different bytes. dstack-ingress regenerates the evidence before it
	// reloads HAProxy (scripts/dns01.sh run_pass), so mid-renewal it is the SERVED
	// certificate that lags the bundle — not the other way round.
	renewing := passing()
	renewing.CertMatch = evidence.CertSameKeyDifferentCert

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
		{name: "renewal mid-apply", rep: renewing, wantCode: 1, contains: "renewal mid-apply"},
		{name: "cert uncheckable", rep: certUncheckable, wantCode: 1, contains: "i/o timeout"},
		// Chain trust is its own axis: a failure fails the run by default, and only
		// -allow-untrusted-cert downgrades it. No attestation check moves either way.
		{name: "untrusted chain fails by default", rep: untrusted, wantCode: 1, contains: "unknown authority"},
		// Waived trust is a pass that does not cover the domain binding, which is
		// precisely the "passed, but not fully" state exit 3 exists to name.
		{name: "untrusted chain allowed is incomplete", rep: untrusted, allowUntrusted: true, wantCode: 3, contains: "-allow-untrusted-cert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := reportGateway(context.Background(), &out, stubEvidence{rep: tc.rep}, "pc-gateway.test", tc.allowUntrusted, false, expectSource{})
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

	// 3, not 0: nothing failed, but the domain binding went unestablished, so the
	// verdict has to agree with the warning rather than read as a full pass.
	var out bytes.Buffer
	if code := reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", true, false, expectSource{}); code != 3 {
		t.Fatalf("code = %d, want 3\n%s", code, out.String())
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
	if code := reportGateway(context.Background(), &out, stubEvidence{rep: passing()}, "pc-gateway.test", true, false, expectSource{}); code != 0 {
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
	if code := reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", false, false, expectSource{}); code != 0 {
		t.Fatalf("code = %d, want 0\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "not proof") {
		t.Errorf("a passing report must still surface its caveats:\n%s", out.String())
	}
}

// An unpinned OS image is reported as advisory (a check that did not run — exit 3),
// and a mismatch as a failure (exit 1). The two must not look alike on screen either.
func TestReportGateway_OSImage(t *testing.T) {
	unpinned := passing()
	unpinned.OSImage = evidence.OSImageCheck{Configured: false}

	mismatch := passing()
	mismatch.OSImage = evidence.OSImageCheck{Configured: true,
		Err: errors.New("MRTD/RTMR1/RTMR2 match no allowlisted OS image (dstack-0.5.3)")}

	matched := passing()
	matched.OSImage = evidence.OSImageCheck{Configured: true, Matched: "dstack-nvidia-0.5.4.1 (1 vCPU)"}

	cases := []struct {
		name     string
		rep      evidence.Report
		wantCode int
		contains string
	}{
		{"not pinned is incomplete, not a failure", unpinned, 3, "not pinned"},
		{"mismatch fails", mismatch, 1, "no allowlisted OS image"},
		{"match names the image", matched, 0, "dstack-nvidia-0.5.4.1 (1 vCPU)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := reportGateway(context.Background(), &out, stubEvidence{rep: tc.rep},
				"pc-gateway.test", false, false, expectSource{})
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
	reportGateway(context.Background(), &out, stubEvidence{rep: matched}, "pc-gateway.test", false, false, expectSource{})
	if strings.Contains(out.String(), "observed mrtd") {
		t.Errorf("a clean match should not dump registers:\n%s", out.String())
	}
}

// The three verdicts have to stay distinguishable, because the whole point of exit 3
// is that a gate reading only zero/non-zero cannot tell "verified" from "checked less
// than everything". -strict collapses 3 into 1 and must never touch 0 or an actual
// failure.
func TestReportGateway_StrictAndIncompleteVerdicts(t *testing.T) {
	failed := passing()
	failed.BindingErr = errors.New("manifest digest aa…, quote binds bb…")

	for _, tc := range []struct {
		name     string
		rep      evidence.Report
		strict   bool
		wantCode int
		present  []string
		absent   []string
	}{
		{
			name: "complete run passes", rep: passing(), wantCode: 0,
			present: []string{"PASS"}, absent: []string{"INCOMPLETE", "-strict"},
		},
		{
			name: "complete run passes under strict too", rep: passing(), strict: true, wantCode: 0,
			present: []string{"PASS"}, absent: []string{"INCOMPLETE"},
		},
		{
			// Nothing is wrong; something simply was not checked. It must say which.
			name: "partial run is 3 and names the gap", rep: partial(), wantCode: 3,
			present: []string{"PASS (INCOMPLETE)", "the OS image was not pinned", "-strict"},
		},
		{
			name: "strict turns a partial run into a failure", rep: partial(), strict: true, wantCode: 1,
			present: []string{"-strict requires every check to run", "the OS image was not pinned", "FAIL"},
			absent:  []string{"PASS"},
		},
		{
			// A real failure stays 1 either way — strict must not disguise one as the other.
			name: "failure is 1 without strict", rep: failed, wantCode: 1,
			present: []string{"FAIL"}, absent: []string{"INCOMPLETE"},
		},
		{
			name: "failure is still 1 under strict", rep: failed, strict: true, wantCode: 1,
			present: []string{"FAIL"}, absent: []string{"INCOMPLETE"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			got := reportGateway(context.Background(), &out, stubEvidence{rep: tc.rep},
				"pc-gateway.test", false, tc.strict, expectSource{})
			if got != tc.wantCode {
				t.Errorf("exit = %d, want %d\n%s", got, tc.wantCode, out.String())
			}
			for _, s := range tc.present {
				if !strings.Contains(out.String(), s) {
					t.Errorf("output missing %q:\n%s", s, out.String())
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(out.String(), s) {
					t.Errorf("output must not contain %q:\n%s", s, out.String())
				}
			}
		})
	}
}

// Each way a run can come up short has to name itself, or a reader gets exit 3 with
// nothing to act on. The reason is also what a failing -strict run prints.
func TestIncompleteReason_NamesTheSpecificGap(t *testing.T) {
	withCode := func(f func(*evidence.CodeIdentity)) evidence.Report {
		rep := passing()
		f(&rep.Code)
		return rep
	}

	for _, tc := range []struct {
		name   string
		rep    evidence.Report
		expect expectSource
		want   string
	}{
		{"complete", passing(), expectSource{}, ""},
		{"os image unpinned", partial(), expectSource{}, "the OS image was not pinned"},
		{
			"no app-compose source",
			withCode(func(c *evidence.CodeIdentity) { c.NoSource = true }),
			expectSource{}, "no app-compose was available, so code identity did not run",
		},
		{
			"app-compose fetch failed",
			withCode(func(c *evidence.CodeIdentity) { c.FetchErr = errors.New("no CNAME chain") }),
			expectSource{}, "the app-compose could not be fetched",
		},
		{
			"compose hash unavailable",
			withCode(func(c *evidence.CodeIdentity) { c.HashErr = errors.New("layout") }),
			expectSource{}, "compose_hash was not recovered, so code identity did not run",
		},
		{
			// A failed release lookup also leaves ExpectRequested false, and this is the
			// more useful of the two readings, so it must win.
			"release lookup failed",
			withCode(func(c *evidence.CodeIdentity) { c.ExpectRequested = false; c.MatchedExpect = "" }),
			expectSource{Err: errors.New("GitHub API rate limit exceeded")},
			"the release lookup failed, so no published manifest was compared",
		},
		{
			"comparison switched off",
			withCode(func(c *evidence.CodeIdentity) { c.ExpectRequested = false; c.MatchedExpect = "" }),
			expectSource{}, "no published manifest was compared",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := incompleteReason(tc.rep, tc.expect); got != tc.want {
				t.Errorf("incompleteReason = %q, want %q", got, tc.want)
			}
		})
	}
}

// An unusable domain is a caller error (exit 2), not a failed check (exit 1).
func TestReportGateway_CheckerError(t *testing.T) {
	var out bytes.Buffer
	code := reportGateway(context.Background(), &out, stubEvidence{err: errors.New("evidence: empty domain")}, "", false, false, expectSource{})
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
		// -strict demands every check; -releases 0 disables the one whose failure is the
		// finding that matters. Honouring both is impossible, so say so up front rather
		// than silently dropping one of the two instructions.
		{"strict with the comparison switched off", []string{
			"-gateway", "pc-gateway.test", "-strict", "-releases", "0",
		}, 2},
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

// A failed app-compose lookup is a "-" and exit 3 (advisory: nothing failed, but a
// check did not run) when it was only discovery, and a "✗" with exit 1 when the caller
// asked for it. The distinction must key off ExpectExplicit, not ExpectRequested:
// -releases defaults to a nonzero count, so a DEFAULT comparison normally has
// candidates, and keying off "candidates exist" made a DNS failure fatal or advisory
// depending on whether GitHub happened to be reachable.
func TestReportGateway_DiscoveredLookupFailureIsAdvisory(t *testing.T) {
	lookupFailed := errors.New("no CNAME chain to a dstack base domain")

	base := func() evidence.Report {
		rep := passing()
		rep.Code.Requested = true
		rep.Code.Discovered = true
		rep.Code.FetchErr = lookupFailed
		return rep
	}

	for _, tc := range []struct {
		name     string
		mutate   func(*evidence.Report)
		wantCode int
		wantMark string
	}{
		{
			name:     "discovery only",
			mutate:   func(*evidence.Report) {},
			wantCode: 3, wantMark: "- app-compose",
		},
		{
			// The bug: a default -releases lookup succeeded, so ExpectRequested is true.
			name:     "default compose comparison also ran",
			mutate:   func(r *evidence.Report) { r.Code.ExpectRequested = true },
			wantCode: 3, wantMark: "- app-compose",
		},
		{
			name: "comparison explicitly requested",
			mutate: func(r *evidence.Report) {
				r.Code.ExpectRequested = true
				r.Code.ExpectExplicit = true
			},
			wantCode: 1, wantMark: "✗ app-compose",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := base()
			tc.mutate(&rep)
			var out bytes.Buffer
			got := reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", false, false,
				expectSource{Label: "newest 5 release(s)"})
			if got != tc.wantCode {
				t.Errorf("exit = %d, want %d\n%s", got, tc.wantCode, out.String())
			}
			if !strings.Contains(out.String(), tc.wantMark) {
				t.Errorf("output does not contain %q:\n%s", tc.wantMark, out.String())
			}
		})
	}
}

// The CLI half of the same bug: -no-dns-discovery must never print a ✓ for an
// app-compose that was never fetched or a compose file that was never compared. The
// old early-return condition included !ExpectRequested, so a DEFAULT -releases lookup
// having found candidates made it fall through to the success branch.
//
// Also covers the mark/exit-code contradiction on the HashErr line: with the default
// -releases, ExpectRequested is set, so mark(!Requested) printed ✓ next to a run that
// then exited 1.
func TestReportCodeIdentity_NeverMarksWorkThatDidNotHappen(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     evidence.CodeIdentity
		wantCode int
		absent   []string
		present  []string
	}{
		{
			name: "no source, default comparison had candidates",
			code: evidence.CodeIdentity{NoSource: true, ExpectRequested: true},
			// Opting out is not a failure, but nothing may be claimed — so exit 3, the
			// code for "ran clean, checked less than everything", never 0.
			wantCode: 3,
			absent:   []string{"✓ app-compose", "✓ compose file", "byte-for-byte"},
			present:  []string{"- app-compose", "not checked"},
		},
		{
			name: "no source, comparison explicitly asked for",
			code: evidence.CodeIdentity{NoSource: true, ExpectRequested: true, ExpectExplicit: true},
			// A comparison was demanded and cannot be performed.
			wantCode: 1,
			absent:   []string{"✓ app-compose", "byte-for-byte"},
			present:  []string{"✗ app-compose"},
		},
		{
			name: "hash unavailable while the default comparison ran",
			code: evidence.CodeIdentity{
				ExpectRequested: true,
				HashErr:         errors.New("mr_config_id layout does not expose compose_hash"),
			},
			wantCode: 1,
			absent:   []string{"✓ code identity"},
			present:  []string{"✗ code identity"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := passing()
			rep.Code = tc.code
			var out bytes.Buffer
			got := reportGateway(context.Background(), &out, stubEvidence{rep: rep},
				"pc-gateway.test", false, false, expectSource{Label: "newest 5 release(s)"})
			if got != tc.wantCode {
				t.Errorf("exit = %d, want %d\n%s", got, tc.wantCode, out.String())
			}
			for _, s := range tc.absent {
				if strings.Contains(out.String(), s) {
					t.Errorf("output must not contain %q:\n%s", s, out.String())
				}
			}
			for _, s := range tc.present {
				if !strings.Contains(out.String(), s) {
					t.Errorf("output must contain %q:\n%s", s, out.String())
				}
			}
		})
	}
}

// The app_id line must say where the value came from. Its three sources are not
// equally reliable, and the weakest one — compose_hash's prefix — fails by TIMING
// OUT rather than by saying anything, so the report is the only place a reader can
// learn that a guess was used.
func TestReportGateway_AppIDCarriesItsSource(t *testing.T) {
	cases := map[string]struct {
		code evidence.CodeIdentity
		want string
	}{
		"discovered": {
			evidence.CodeIdentity{AppID: "08f84bba", AppIDSource: "_dstack-app-address TXT"},
			"08f84bba (_dstack-app-address TXT)",
		},
		"supplied": {
			evidence.CodeIdentity{AppID: "08f84bba", AppIDSource: "supplied"},
			"08f84bba (supplied)",
		},
		"guessed": {
			evidence.CodeIdentity{AppID: "dd79782d", AppIDSource: "compose_hash prefix"},
			"dd79782d (compose_hash prefix)",
		},
		// Nothing settled it (an older report, or a run that never got that far): print
		// the value alone rather than an empty parenthesis.
		"no source": {
			evidence.CodeIdentity{AppID: "dd79782d"},
			"dd79782d",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rep := passing()
			tc.code.Requested = true
			tc.code.Source = rep.Code.Source
			tc.code.ExpectRequested, tc.code.MatchedExpect = true, rep.Code.MatchedExpect
			rep.Code = tc.code

			var out strings.Builder
			reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", false, false, expectSource{})
			if want := "app_id           " + tc.want + "\n"; !strings.Contains(out.String(), want) {
				t.Errorf("output does not contain %q:\n%s", want, out.String())
			}
		})
	}
}

// When the app_id came from the guess, the report must say WHY the better source did
// not answer. Without it a wrong app_id and an unreachable resolver look identical:
// both print a plausible 40-hex value and nothing else.
func TestReportGateway_AppIDFallbackExplainsItself(t *testing.T) {
	rep := passing()
	rep.Code.AppID = "dd79782d9cd5b8243acf468896d4cc81907b1ae8"
	rep.Code.AppIDSource = "compose_hash prefix"
	rep.Code.AppIDErr = errors.New("no usable _dstack-app-address record for gw.example.com: " +
		"_dstack-app-address.gw.example.com: lookup: server misbehaving")

	var out strings.Builder
	reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", false, false, expectSource{})
	got := out.String()
	for _, want := range []string{"(compose_hash prefix)", "server misbehaving", "pass -app-id to pin it"} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not contain %q:\n%s", want, got)
		}
	}
}

// A discovered or supplied app_id has nothing to explain, and the extra lines would
// be noise on every healthy run.
func TestReportGateway_NoFallbackNoteWhenDiscovered(t *testing.T) {
	rep := passing()
	rep.Code.AppID = "08f84bbaee1e78db04d3623eb564ad486b41f7fe"
	rep.Code.AppIDSource = "_dstack-app-address TXT"

	var out strings.Builder
	reportGateway(context.Background(), &out, stubEvidence{rep: rep}, "pc-gateway.test", false, false, expectSource{})
	if strings.Contains(out.String(), "pass -app-id") {
		t.Errorf("a healthy run carries the fallback hint:\n%s", out.String())
	}
}
