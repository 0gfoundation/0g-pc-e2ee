package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/dcap"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

// evidenceChecker is the seam over client/evidence so reportGateway can be
// tested without a live endpoint or DCAP collateral.
type evidenceChecker interface {
	Check(ctx context.Context, domain string) (evidence.Report, error)
}

// newEvidenceChecker builds the real checker: a DCAP verifier over the ingress
// quote, with collateral from pccsURL when set (Intel PCS otherwise — the same
// choice the gateway itself makes, see ZG_GATEWAY_PCCS_URL).
func newEvidenceChecker(pccsURL string, timeout time.Duration) (*evidence.Checker, error) {
	return evidence.New(evidence.Config{
		QuoteParser: dcap.NewQuoteParser(dcap.Config{PCCSBaseURL: pccsURL}),
		Timeout:     timeout,
	})
}

// reportGateway prints the per-step result of verifying a gateway's evidence
// bundle and returns the process exit code (0 pass, 1 any failed check).
//
// allowUntrustedCert downgrades the chain-trust step (step 5) from a failure to a
// note. It exists for ACME-staging deployments, whose certificates are correctly
// bound by the quote but signed by an untrusted CA on purpose
// (deploy/phala/README.md); it does NOT relax any attestation check.
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
	// Widest evidence filename in practice is cert-<domain>.pem; pad to keep the
	// digest column aligned for the names that fit and merely push it right for the
	// ones that do not.
	const nameCol = 30
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
	switch {
	case trustOK:
		fmt.Fprintf(out, "%s chain trust        validates for %s\n", mark(true), rep.Domain)
	case allowUntrustedCert:
		fmt.Fprintf(out, "%s chain trust        %v (ignored: -allow-untrusted-cert)\n", mark(true), rep.ChainTrustErr)
	default:
		fmt.Fprintf(out, "%s chain trust        %v\n", mark(false), rep.ChainTrustErr)
	}

	fmt.Fprintf(out, "\nnote: %s\n", rep.Note)

	if rep.Pass() && (trustOK || allowUntrustedCert) {
		fmt.Fprintln(out, "\nPASS")
		return 0
	}
	return fail(out)
}
