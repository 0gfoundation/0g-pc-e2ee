package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/dcap"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

// evidenceChecker is the seam over client/evidence so reportGateway can be
// tested without a live endpoint or DCAP collateral.
type evidenceChecker interface {
	Check(ctx context.Context, domain string) (evidence.Report, error)
}

// gatewayConfig is the gateway mode's flag values, gathered so newEvidenceChecker
// takes one argument instead of six positional ones.
type gatewayConfig struct {
	pccsURL            string
	timeout            time.Duration
	allowUntrustedCert bool
	appComposePath     string
	baseDomain         string
	noDNSDiscovery     bool
	expectComposePath  string
	releases           int
	releaseRepo        string
	releaseAsset       string
}

// newEvidenceChecker builds the real checker: a DCAP verifier over the ingress
// quote, with collateral from pccsURL when set (Intel PCS otherwise — the same
// choice the gateway itself makes, see ZG_GATEWAY_PCCS_URL), plus whatever
// code-identity material the operator supplied.
//
// allowUntrustedCert must reach the checker, not just the reporting below: the
// evidence FETCH is an HTTPS GET, so with an ACME-staging certificate it fails on
// PKI verification before any check runs. See evidence.Config.AllowUntrustedCert.
//
// Unreadable -app-compose / -expect-compose-file paths are errors here rather than
// silently-skipped checks: an operator who passed the flag asked for the check, and
// quietly reporting a pass without it is the worst possible outcome.
func newEvidenceChecker(ctx context.Context, out io.Writer, g gatewayConfig) (*evidence.Checker, error) {
	cfg := evidence.Config{
		QuoteParser:        dcap.NewQuoteParser(dcap.Config{PCCSBaseURL: g.pccsURL}),
		Timeout:            g.timeout,
		AllowUntrustedCert: g.allowUntrustedCert,
		BaseDomain:         g.baseDomain,
		NoDNSDiscovery:     g.noDNSDiscovery,
	}
	if p := strings.TrimSpace(g.appComposePath); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("-app-compose: %w", err)
		}
		cfg.AppCompose = b
	}

	// The two ways to say what the compose text should be are different questions —
	// "exactly this one" versus "any published release" — so requiring exactly one
	// keeps the exit code unambiguous.
	pinned := strings.TrimSpace(g.expectComposePath) != ""
	switch {
	case pinned && g.releases > 0:
		return nil, fmt.Errorf("-expect-compose-file pins one manifest and -releases matches a set; pass one")
	case pinned:
		b, err := os.ReadFile(g.expectComposePath)
		if err != nil {
			return nil, fmt.Errorf("-expect-compose-file: %w", err)
		}
		cfg.ExpectComposeFiles = []evidence.ExpectedCompose{{Label: g.expectComposePath, Content: b}}
	case g.releases > 0:
		repo, asset := g.releaseRepo, g.releaseAsset
		fmt.Fprintf(out, "releases           newest %d of %s (%s)\n", g.releases, repo, asset)
		files, err := fetchReleaseComposeFiles(ctx, newGitHubClient(g.timeout), repo, asset, g.releases, out)
		if err != nil {
			return nil, err
		}
		cfg.ExpectComposeFiles = files
	}
	return evidence.New(cfg)
}

// reportGateway prints the per-step result of verifying a gateway's evidence
// bundle and returns the process exit code (0 pass, 1 any failed check).
//
// allowUntrustedCert downgrades the chain-trust step (step 5) from a failure to a
// note. It exists for ACME-staging deployments, whose certificates are correctly
// bound by the quote but signed by an untrusted CA on purpose
// (deploy/phala/README.md). It relaxes no attestation check, but it does narrow the
// claim — an interceptor running its own attested CVM would satisfy everything
// else — so a run that uses it prints that caveat rather than a bare PASS.
func reportGateway(ctx context.Context, out io.Writer, ec evidenceChecker, domain string, allowUntrustedCert bool) int {
	rep, err := ec.Check(ctx, domain)
	if err != nil {
		fmt.Fprintf(out, "pcverify: %v\n", err)
		return 2
	}

	fmt.Fprintf(out, "gateway            %s\n", rep.Domain)

	// Step 1 — bundle integrity.
	if rep.ManifestErr != nil {
		fmt.Fprintf(out, "%s evidence bundle    %v\n", mark(false), rep.ManifestErr)
		return fail(out)
	}
	filesOK := true
	// Size the name column to the longest name actually present: cert-<domain>.pem
	// grows with the domain, and a fixed width misaligns the digest column the moment
	// a real hostname is longer than the guess.
	nameCol := 20
	for _, f := range rep.Files {
		if n := len(f.Name); n > nameCol {
			nameCol = n
		}
	}
	for _, f := range rep.Files {
		switch {
		case f.Err != nil:
			fmt.Fprintf(out, "%s   %-*s %v\n", mark(false), nameCol, f.Name, f.Err)
			filesOK = false
		case !f.OK():
			fmt.Fprintf(out, "%s   %-*s digest %x, manifest says %x\n", mark(false), nameCol, f.Name, f.Got, f.Want)
			filesOK = false
		default:
			fmt.Fprintf(out, "%s   %-*s %x\n", mark(true), nameCol, f.Name, f.Got)
		}
	}
	fmt.Fprintf(out, "%s evidence bundle    %d file(s) match %s\n", mark(filesOK), len(rep.Files), "sha256sum.txt")

	// Step 2 — quote authenticity.
	if rep.QuoteErr != nil {
		fmt.Fprintf(out, "%s quote              %v\n", mark(false), rep.QuoteErr)
	} else {
		fmt.Fprintf(out, "%s quote              genuine TDX (DCAP verified)\n", mark(true))
		// All five registers, because app identity lives in RTMR3 while MRTD is the
		// VM image: the manual code-identity step needs to see both.
		for _, r := range []struct {
			name string
			val  []byte
		}{
			{"MRTD", rep.Measurement.MRTD[:]},
			{"RTMR0", rep.Measurement.RTMR0[:]},
			{"RTMR1", rep.Measurement.RTMR1[:]},
			{"RTMR2", rep.Measurement.RTMR2[:]},
			{"RTMR3", rep.Measurement.RTMR3[:]},
		} {
			fmt.Fprintf(out, "  measurement %-5s %x\n", r.name, r.val)
		}
	}

	// Step 3 — the quote binds this bundle.
	if rep.BindingErr != nil {
		fmt.Fprintf(out, "%s bundle binding     %v\n", mark(false), rep.BindingErr)
	} else {
		fmt.Fprintf(out, "%s bundle binding     report_data == SHA-256(sha256sum.txt)\n", mark(true))
	}

	// Step 4 — the endpoint serves the certificate the quote binds. The
	// load-bearing step: without it the quote says nothing about this endpoint.
	if rep.CertErr != nil {
		fmt.Fprintf(out, "%s endpoint binding   %v\n", mark(false), rep.CertErr)
	} else {
		fmt.Fprintf(out, "%s endpoint binding   %v\n", mark(rep.CertMatch.OK()), rep.CertMatch)
		fmt.Fprintf(out, "  served cert      %x\n", rep.ServedCertSHA256)
		if !rep.CertMatch.OK() {
			fmt.Fprintf(out, "  bundle cert      %x\n", rep.BundleCertSHA256)
		}
		fmt.Fprintf(out, "  subject          %s\n", rep.CertSubject)
		fmt.Fprintf(out, "  issuer           %s\n", rep.CertIssuer)
		fmt.Fprintf(out, "  not after        %s\n", rep.CertNotAfter.UTC().Format(time.RFC3339))
	}

	// Step 5 — ordinary PKI trust, reported on its own so a staging certificate is
	// distinguishable from a real trust failure.
	trustOK := rep.ChainTrustErr == nil
	trustWaived := !trustOK && allowUntrustedCert
	switch {
	case trustOK:
		fmt.Fprintf(out, "%s chain trust        validates for %s\n", mark(true), rep.Domain)
	case trustWaived:
		fmt.Fprintf(out, "%s chain trust        %v (waived: -allow-untrusted-cert)\n", mark(true), rep.ChainTrustErr)
	default:
		fmt.Fprintf(out, "%s chain trust        %v\n", mark(false), rep.ChainTrustErr)
	}

	// Step 6 — code identity.
	reportCodeIdentity(out, rep.Code)

	fmt.Fprintf(out, "\nnote: %s\n", rep.Note)
	// Waiving chain trust drops the link between this connection and the name that
	// was asked for, so say what the pass no longer covers. Without this an operator
	// reads a bare PASS as the full claim.
	// The domain goes on its own line rather than mid-sentence: interpolating a
	// hostname of unknown length into a hand-wrapped paragraph leaves it ragged.
	if trustWaived {
		fmt.Fprintf(out, "\nwarning: chain trust was waived, so this run does NOT establish that the\n"+
			"  connection reached the domain asked for:\n"+
			"    %s\n"+
			"  An interceptor running its own attested CVM would satisfy every other check\n"+
			"  above, serving its own quote, bundle and certificate — which match each other\n"+
			"  because it controls both. The claim is only \"a genuine TEE minted the\n"+
			"  certificate served on this connection\". Fine for smoke-testing a deployment\n"+
			"  you operate; not for auditing an endpoint you do not control, and not on a\n"+
			"  production hostname, where this check should pass without the flag.\n", rep.Domain)
	}

	if rep.Pass() && (trustOK || allowUntrustedCert) {
		fmt.Fprintln(out, "\nPASS")
		return 0
	}
	return fail(out)
}

// reportCodeIdentity prints the mr_config_id → compose_hash → app-compose →
// docker_compose_file chain. compose_hash and app_id are printed whenever they are
// available even if nothing else was requested: they are reproducible values an
// operator can record and compare across deploys, unlike the raw measurement
// registers.
func reportCodeIdentity(out io.Writer, code evidence.CodeIdentity) {
	if code.HashErr != nil {
		fmt.Fprintf(out, "%s code identity      %v\n", mark(!code.Requested), code.HashErr)
		return
	}
	fmt.Fprintf(out, "%s compose_hash       %x\n", mark(true), code.ComposeHash)
	fmt.Fprintf(out, "  app_id           %s\n", code.AppID)

	if !code.Requested && !code.ExpectRequested && code.Source == "" && code.FetchErr == nil {
		// Discovery was switched off. Not a failure — say what would close the gap,
		// next to the value it would resolve.
		fmt.Fprintf(out, "- app-compose        not checked (-no-dns-discovery; pass -app-compose or -base-domain)\n")
		return
	}
	switch {
	case code.FetchErr != nil:
		// A lookup nobody asked for is a "-", not a "✗": DNS or the platform endpoint
		// being unavailable says nothing about the deployment.
		fmt.Fprintf(out, "%s app-compose        %v\n", failMark(code, code.Discovered), code.FetchErr)
		return
	case code.BoundErr != nil:
		fmt.Fprintf(out, "%s app-compose        %v\n", mark(false), code.BoundErr)
		if code.Source != "" {
			fmt.Fprintf(out, "  source           %s\n", code.Source)
		}
		return
	}
	fmt.Fprintf(out, "%s app-compose        sha256 == compose_hash (authenticated)\n", mark(true))
	fmt.Fprintf(out, "  source           %s\n", code.Source)
	if code.Name != "" {
		fmt.Fprintf(out, "  app name         %s\n", code.Name)
	}
	if len(code.AllowedEnvs) > 0 {
		// Names only — the measured manifest never carries values. Worth showing:
		// widening this set changes what the deployment can be handed at boot.
		fmt.Fprintf(out, "  allowed_envs     %s\n", strings.Join(code.AllowedEnvs, " "))
	}

	if !code.ExpectRequested {
		fmt.Fprintf(out, "- compose file       not compared (pass -expect-compose-file or -releases N)\n")
		return
	}
	if code.ExpectErr != nil {
		fmt.Fprintf(out, "%s compose file       %v\n", mark(false), code.ExpectErr)
		return
	}
	fmt.Fprintf(out, "%s compose file       matches %s byte-for-byte\n", mark(true), code.MatchedExpect)
}

// failMark renders a failed check as an advisory "-" when it was only attempted as
// discovery, so an unavailable optional lookup does not read like a verification
// failure. The exit code follows CodeIdentity.OK, which applies the same rule.
func failMark(code evidence.CodeIdentity, advisory bool) string {
	if advisory && !code.ExpectRequested {
		return "-"
	}
	return mark(false)
}
