package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/dcap"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
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
	osImagesPath       string
	expectComposePath  string
	releases           int
	releaseRepo        string
	releaseAsset       string
	// releasesSet / expectComposeSet record whether the flag was PASSED, as opposed
	// to holding its default. -releases defaults to a nonzero count, so the two have
	// to be distinguished: an explicit request must win over the default and must be
	// fatal when it cannot be satisfied, while the default degrades to advisory.
	releasesSet      bool
	expectComposeSet bool
	// strict turns "no check failed" into "every check ran and passed". The optional
	// lookups stop degrading to advisory, so a run that could not reach GitHub or
	// could not locate the app-compose fails instead of printing "-" and exiting 0.
	// It demands the checks WITHOUT demanding their inputs: DNS discovery still finds
	// the base domain, it just may no longer come up empty.
	strict bool
}

// expectSource records how the "what should be running" side was resolved, so the
// report can say what happened when it could not be.
type expectSource struct {
	// Label describes where the candidates came from, for the report.
	Label string
	// Err is set when the candidates could not be obtained. Advisory says the lookup
	// was only the default, so a failure is reported without failing the run — the
	// same rule DNS discovery follows.
	Err      error
	Advisory bool
}

// defaultReleases is how many published releases the compose text is matched against
// when the operator says nothing. Enough to cover a rollback or a lagging side of a
// blue/green pair, few enough that "matches none of them" stays a strong signal.
const defaultReleases = 5

// errLookupRequired marks a lookup the caller DEMANDED — with -strict, or with an
// explicit -releases N — that could not be completed.
//
// It exists to keep the exit codes honest. Setup failures otherwise mean "caller
// mistake" (exit 2): unusable flags, an unreadable file, a domain that is not a
// domain. A GitHub outage or a 403 from rate limiting is none of those — the flags
// were fine and the claim simply could not be made, which is a failed check (exit 1).
// Collapsing the two would point a CI gate at the wrong branch precisely in the
// scenario -strict exists for, since the unauthenticated GitHub API allows 60
// requests/hour per IP and shared runners do hit it.
type errLookupRequired struct{ err error }

func (e errLookupRequired) Error() string { return e.err.Error() }
func (e errLookupRequired) Unwrap() error { return e.err }

// flagSet reports whether name was passed on the command line, rather than holding
// its default.
func flagSet(fs *flag.FlagSet, name string) bool {
	seen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}

// newEvidenceChecker builds the real checker: a DCAP verifier over the ingress
// quote, with collateral from pccsURL when set (Intel PCS otherwise — the same
// choice the gateway itself makes, see ZG_GATEWAY_PCCS_URL), plus whatever
// code-identity material the operator supplied.
//
// allowUntrustedCert is deliberately NOT passed to the checker: the evidence fetch
// never verifies PKI (it rides the same unverified-but-recorded connection the
// certificate comparison examines — see evidence's session type), so nothing needs
// relaxing for a staging deployment to be checkable. The flag is purely a reporting
// decision, applied in reportGateway: whether a failed chain-trust step blocks the
// verdict.
//
// Unreadable -app-compose / -expect-compose-file paths are errors here rather than
// silently-skipped checks: an operator who passed the flag asked for the check, and
// quietly reporting a pass without it is the worst possible outcome.
func newEvidenceChecker(ctx context.Context, out io.Writer, g gatewayConfig) (*evidence.Checker, expectSource, error) {
	var expect expectSource
	cfg := evidence.Config{
		QuoteParser:    dcap.NewQuoteParser(dcap.Config{PCCSBaseURL: g.pccsURL}),
		Timeout:        g.timeout,
		BaseDomain:     g.baseDomain,
		NoDNSDiscovery: g.noDNSDiscovery,
	}
	if p := strings.TrimSpace(g.osImagesPath); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, expect, fmt.Errorf("-os-image-allowlist: %w", err)
		}
		imgs, err := evidence.ParseOSImages(b)
		if err != nil {
			return nil, expect, fmt.Errorf("-os-image-allowlist: %w", err)
		}
		// A file that parses to nothing disables the check; say so rather than letting a
		// caller think they pinned something.
		if len(imgs) == 0 {
			return nil, expect, fmt.Errorf("-os-image-allowlist %s contains no images", p)
		}
		cfg.OSImages = imgs
	}
	if p := strings.TrimSpace(g.appComposePath); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, expect, fmt.Errorf("-app-compose: %w", err)
		}
		cfg.AppCompose = b
	}

	// The two ways to say what the compose text should be are different questions —
	// "exactly this one" versus "any published release". Passing BOTH explicitly is
	// ambiguous and rejected; -expect-compose-file otherwise simply wins over the
	// -releases default, since naming a file is the more specific instruction.
	pinned := strings.TrimSpace(g.expectComposePath) != ""
	switch {
	case g.expectComposeSet && g.releasesSet:
		return nil, expect, fmt.Errorf("-expect-compose-file pins one manifest and -releases matches a set; pass one")
	// -strict demands every check; -releases 0 with no pinned manifest disables the
	// one check whose failure is the finding that matters. Rejecting the pair is the
	// only reading that does not silently break one of the two instructions.
	case g.strict && !pinned && g.releases <= 0:
		return nil, expect, fmt.Errorf("-strict requires a compose comparison; drop -releases 0 or pass -expect-compose-file")
	case pinned:
		b, err := os.ReadFile(g.expectComposePath)
		if err != nil {
			return nil, expect, fmt.Errorf("-expect-compose-file: %w", err)
		}
		cfg.ExpectComposeFiles = []evidence.ExpectedCompose{{Label: g.expectComposePath, Content: b}}
		cfg.ExpectComposeExplicit = true
		expect.Label = g.expectComposePath
	case g.releases > 0:
		expect.Label = fmt.Sprintf("newest %d release(s) of %s (%s)", g.releases, g.releaseRepo, g.releaseAsset)
		fmt.Fprintf(out, "expected compose   %s\n", expect.Label)
		// Not explicitly asked for: the lookup reaches GitHub, and an unreachable or
		// rate-limited API says nothing about the deployment. Degrade to advisory rather
		// than fail, exactly as a DNS-discovered app-compose lookup does. -strict is the
		// caller saying they want the claim made or the run failed, so it ends the
		// degradation without their having to name the count.
		expect.Advisory = !g.releasesSet && !g.strict
		// Explicit iff the operator typed -releases (or -strict). Passing the bare
		// default through as "explicit" would let a successful GitHub lookup harden the
		// unrelated DNS-discovered app-compose lookup — see evidence.CodeIdentity.OK.
		cfg.ExpectComposeExplicit = g.releasesSet || g.strict
		files, err := fetchReleaseComposeFiles(ctx, newGitHubClient(g.timeout), g.releaseRepo, g.releaseAsset, g.releases, out)
		switch {
		case err != nil && expect.Advisory:
			expect.Err = err
		case err != nil:
			// Demanded and not obtained. Typed, so run() can exit 1 rather than folding
			// it in with the caller mistakes — see errLookupRequired.
			return nil, expect, errLookupRequired{err}
		default:
			cfg.ExpectComposeFiles = files
		}
	}
	c, err := evidence.New(cfg)
	return c, expect, err
}

// incompleteReason names the first check that did NOT run in a run that failed
// nothing, or "" when every check ran. It is derived from the report rather than
// observed from the printing, so the verdict cannot drift from what a reader is told,
// and it names the reason rather than returning a bare bool because the verdict line
// has to point at the specific gap — "something was skipped" sends a reader hunting.
//
// This is the distinction exit code 3 exists to carry: "nothing I checked was wrong"
// is a weaker claim than "I checked everything", and a gate that reads only
// zero/non-zero cannot tell them apart. Deliberate skips count — -releases 0 and
// -no-dns-discovery are choices to check less, not reasons to call a run complete.
func incompleteReason(rep evidence.Report, expect expectSource) string {
	// The OS image grounds step 6: without it, compose_hash is a register the
	// untrusted host wrote. An empty allowlist reports "not pinned" and passes.
	if !rep.OSImage.Configured {
		return "the OS image was not pinned"
	}
	// Mirrors reportCodeIdentity's branches, in its order.
	code := rep.Code
	switch {
	case code.HashErr != nil:
		return "compose_hash was not recovered, so code identity did not run"
	case code.NoSource:
		return "no app-compose was available, so code identity did not run"
	case code.FetchErr != nil:
		return "the app-compose could not be fetched"
	// Before !ExpectRequested: a failed lookup leaves that false too, and "the lookup
	// failed" is the more useful of the two readings.
	case expect.Err != nil:
		return "the release lookup failed, so no published manifest was compared"
	case !code.ExpectRequested:
		return "no published manifest was compared"
	}
	return ""
}

// reportGateway prints the per-step result of verifying a gateway's evidence bundle
// and returns the process exit code: 0 every check ran and passed, 1 a check failed,
// 3 nothing failed but something did not run (see incompleteReason). 2 is reserved for
// a caller mistake, which is why "incomplete" could not have it.
//
// strict collapses 3 into 1: the caller asked for a complete run, so an incomplete
// one is a failed one. Most of that is already enforced upstream through
// Config.ExpectComposeExplicit — this is the backstop that makes the guarantee hold
// for every "-" line rather than only the ones that flag reaches.
//
// allowUntrustedCert downgrades the chain-trust step (step 5) from a failure to a
// note. It exists for ACME-staging deployments, whose certificates are correctly
// bound by the quote but signed by an untrusted CA on purpose
// (deploy/phala/README.md). It relaxes no attestation check, but it does narrow the
// claim — an interceptor running its own attested CVM would satisfy everything
// else — so a run that uses it prints that caveat rather than a bare PASS, and is
// incomplete for the same reason: the domain binding went unestablished.
func reportGateway(ctx context.Context, out io.Writer, ec evidenceChecker, domain string, allowUntrustedCert, strict bool, expect expectSource) int {
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
		// The measurement registers are deliberately NOT dumped here. MRTD/RTMR1/RTMR2 are
		// reported by the os-image step below, which is the check that gives them meaning,
		// and RTMR3 is superseded by compose_hash — a value that can actually be
		// recomputed and compared. Printing 5×96 hex characters that nothing checks was
		// noise dressed as rigour.
		fmt.Fprintf(out, "%s quote              genuine TDX (DCAP verified)\n", mark(true))
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
	reportCodeIdentity(out, rep.Code, expect)

	// Step 7 — the OS image that enforced step 6's binding. The boot-chain registers
	// are printed only when they are the reader's next action: to record a value that
	// is not pinned yet, or to diagnose one that did not match. A clean match needs
	// only the name.
	switch {
	case !rep.OSImage.Configured:
		fmt.Fprintf(out, "- os image           not pinned (allowlist is empty; see client/evidence/osimages.json)\n")
		reportBootChain(out, rep.OSImage.Observed)
		reportShapeRegister(out, rep.Measurement)
	case rep.OSImage.Err != nil:
		fmt.Fprintf(out, "%s os image           %v\n", mark(false), rep.OSImage.Err)
		reportBootChain(out, rep.OSImage.Observed)
		reportShapeRegister(out, rep.Measurement)
	default:
		fmt.Fprintf(out, "%s os image           %s\n", mark(true), rep.OSImage.Matched)
	}

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

	if !rep.Pass() || !(trustOK || allowUntrustedCert) {
		return fail(out)
	}
	reason := incompleteReason(rep, expect)
	// Waiving chain trust leaves the connection untied to the name asked for, so that
	// run did not cover everything either — the warning above says so at length, and
	// the verdict should agree with it. Checked second: an actual skipped check is the
	// more actionable thing to name.
	if reason == "" && !trustOK {
		reason = "chain trust was waived, so the connection was not tied to the domain"
	}
	switch {
	case reason != "" && strict:
		fmt.Fprintf(out, "\n-strict requires every check to run, and one did not: %s.\n"+
			"  Supply what it needs, or drop -strict to accept a partial run.\n", reason)
		return fail(out)
	case reason != "":
		// Named on screen, not just implied by the exit code: the failure mode this
		// guards against is a reader taking "not FAIL" for "verified".
		fmt.Fprintf(out, "\nPASS (INCOMPLETE) — no check failed, but %s,\n"+
			"  so this is not a full verification. Re-run with -strict to make it fatal.\n", reason)
		return 3
	}
	fmt.Fprintln(out, "\nPASS")
	return 0
}

// reportCodeIdentity prints the mr_config_id → compose_hash → app-compose →
// docker_compose_file chain. compose_hash and app_id are printed whenever they are
// available even if nothing else was requested: they are reproducible values an
// operator can record and compare across deploys, unlike the raw measurement
// registers.
func reportCodeIdentity(out io.Writer, code evidence.CodeIdentity, expect expectSource) {
	if code.HashErr != nil {
		// Both halves of OK's short-circuit, or the mark contradicts the exit code: with
		// -releases at its default ExpectRequested is set, so mark(!Requested) alone
		// printed a ✓ next to a run that then failed.
		fmt.Fprintf(out, "%s code identity      %v\n", mark(!code.Requested && !code.ExpectRequested), code.HashErr)
		return
	}
	fmt.Fprintf(out, "%s compose_hash       %x\n", mark(true), code.ComposeHash)
	fmt.Fprintf(out, "  app_id           %s\n", code.AppID)

	if code.NoSource {
		// Discovery was switched off and no bytes were supplied, so the app-compose stage
		// never ran. This must be keyed on NoSource, not on ExpectRequested being false:
		// -releases defaults to 5, so candidates normally exist and the old condition fell
		// through to the success branch — printing ✓ for an app-compose never fetched and a
		// comparison never made. Say what would close the gap, next to the value it would
		// resolve; a ✗ when the caller explicitly asked for a comparison, since they
		// demanded one that cannot be performed without a source.
		fmt.Fprintf(out, "%s app-compose        not checked (-no-dns-discovery; pass -app-compose or -base-domain)\n",
			failMark(code, !code.ExpectExplicit))
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
		switch {
		case expect.Err != nil:
			// The default lookup ran and failed. Say so — "not compared" alone would read
			// as a choice rather than an outcome.
			fmt.Fprintf(out, "- compose file       not compared: %v\n", expect.Err)
		default:
			fmt.Fprintf(out, "- compose file       not compared (-releases 0; pass -expect-compose-file or -releases N)\n")
		}
		return
	}
	if code.ExpectErr != nil {
		fmt.Fprintf(out, "%s compose file       %v\n", mark(false), code.ExpectErr)
		return
	}
	// No error AND no label means nothing was actually compared — the shape any future
	// early return would produce. Never print it as a match; OK() rejects it too.
	if code.MatchedExpect == "" {
		fmt.Fprintf(out, "%s compose file       not compared (no result recorded)\n", mark(false))
		return
	}
	fmt.Fprintf(out, "%s compose file       matches %s byte-for-byte\n", mark(true), code.MatchedExpect)
}

// failMark renders a failed check as an advisory "-" when it was only attempted as
// discovery, so an unavailable optional lookup does not read like a verification
// failure. The exit code follows CodeIdentity.OK, which applies the same rule.
func failMark(code evidence.CodeIdentity, advisory bool) string {
	if advisory && !code.ExpectExplicit {
		return "-"
	}
	return mark(false)
}

// reportBootChain prints the observed image registers in the shape an osimages.json
// entry wants, so recording a legitimate OS upgrade is a copy rather than a
// transcription.
//
// These are the three the allowlist compares. RTMR0 is deliberately absent: it records
// the VM shape, which is not what this check is about (see attest.BootChain), and
// printing it here would invite someone to paste it into an entry field that no longer
// exists. reportShapeRegister covers it separately, as information.
func reportBootChain(out io.Writer, bc attest.BootChain) {
	for _, r := range []struct {
		key string
		val []byte
	}{
		{"mrtd", bc.MRTD[:]},
		{"rtmr1", bc.RTMR1[:]},
		{"rtmr2", bc.RTMR2[:]},
	} {
		fmt.Fprintf(out, "  observed %-6s %x\n", r.key, r.val)
	}
}

// reportShapeRegister prints RTMR0, which nothing compares. It is worth showing
// because it changes when the VM shape changes — a signal an operator may want even
// though it is not part of the OS-image identity the allowlist pins.
func reportShapeRegister(out io.Writer, m attest.Measurement) {
	fmt.Fprintf(out, "  rtmr0 (vm shape, not pinned) %x\n", m.RTMR0[:])
}
