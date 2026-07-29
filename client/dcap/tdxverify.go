// Package dcap fills the protocol/attest quote-parser seam with a real Intel
// TDX (DCAP) verifier backed by go-tdx-guest.
//
// It lives in the client module rather than protocol on purpose: go-tdx-guest is
// a heavy, Go-specific dependency, while protocol is kept lean and portable (it
// may gain a Rust/TS port). The seam (protocol/attest.WithQuoteParser) is exactly
// the boundary that lets the heavy verifier plug in from here.
//
// Division of labor:
//   - go-tdx-guest does the DCAP cryptography: the quote's signature chain up to
//     the Intel SGX root, the Quoting-Enclave identity, and the platform TCB
//     status (the last two need collateral — TCB Info / QE Identity / CRLs).
//   - measurement + report_data extraction reuses protocol/attest.ParseTDXQuoteBody,
//     whose byte offsets are pinned by a real-vector KAT, so extraction stays
//     under our control and identical to the rest of the codebase.
//
// Fail-closed: NewQuoteParser only extracts (and returns) keys after verification
// succeeds; any verification error propagates and the candidate is skipped.
package dcap

import (
	"fmt"
	"time"

	attest "github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

// Config controls the DCAP verification NewQuoteParser performs.
type Config struct {
	// Getter fetches DCAP collateral (TCB Info, QE Identity, CRLs). In production
	// point it at a PCCS/Intel PCS; in hermetic tests inject one backed by
	// captured fixtures so a fixed snapshot verifies offline. Nil uses
	// go-tdx-guest's default (network http.Get against Intel PCS).
	Getter trust.HTTPSGetter
	// Now is the time verification uses to check certificate and collateral
	// validity. Freeze it against a captured collateral snapshot so a hermetic
	// test is deterministic (collateral has issueDate/nextUpdate). Zero means
	// time.Now().
	Now time.Time
	// SkipRevocation disables CRL (revocation) checking. Revocation is checked by
	// DEFAULT: a PCK certificate Intel has revoked (e.g. after a platform-key
	// compromise) must not pass on a confidentiality-critical path. Set this only
	// for an environment that genuinely cannot reach the CRLs, accepting that
	// revoked platforms would then verify.
	SkipRevocation bool
}

// NewQuoteParser returns a parser for protocol/attest.WithQuoteParser: it
// DCAP-verifies the raw quote and, only on success, extracts the measurement and
// report_data. Collateral fetching is always enabled — the QE-identity and TCB
// checks require it — so a Getter (network or fixture) must be able to serve it.
func NewQuoteParser(cfg Config) func([]byte) (attest.Measurement, [64]byte, error) {
	return func(raw []byte) (attest.Measurement, [64]byte, error) {
		opts := verify.DefaultOptions()
		opts.GetCollateral = true
		opts.CheckRevocations = !cfg.SkipRevocation
		if cfg.Getter != nil {
			opts.Getter = cfg.Getter
		}
		if !cfg.Now.IsZero() {
			opts.Now = cfg.Now
		}

		if err := verify.RawTdxQuote(raw, opts); err != nil {
			return attest.Measurement{}, [64]byte{}, fmt.Errorf("dcap: quote verification failed: %w", err)
		}

		// Only reached once the quote is proven genuine; extract with our own
		// KAT-pinned parser rather than trusting a second decoder.
		body, err := attest.ParseTDXQuoteBody(raw)
		if err != nil {
			return attest.Measurement{}, [64]byte{}, fmt.Errorf("dcap: extract verified quote body: %w", err)
		}
		return body.Measurement, body.ReportData, nil
	}
}
