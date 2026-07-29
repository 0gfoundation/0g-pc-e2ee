package attest

import (
	"errors"
	"fmt"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// Sentinel errors from Verify. Callers (the route fallback loop) treat any
// verification error as "skip this candidate, never seal to it" (SPEC §4.4,
// fail-closed); the distinct sentinels exist for logging and tests.
var (
	// ErrQuoteVerifierNotConfigured is returned by a Verifier built without a
	// real quote parser. The default parser rejects everything, so a no-op
	// verification can never silently trust a quote.
	ErrQuoteVerifierNotConfigured = errors.New("attest: no quote parser configured (fail-closed)")
	// ErrUntrustedMeasurement is returned when a genuine quote's measurement is
	// not in the Policy allowlist — i.e. the enclave runs code the client has
	// not audited.
	ErrUntrustedMeasurement = errors.New("attest: quote measurement not in allowlist")
)

// quoteParser is the seam over raw TDX quote handling: it parses the quote
// structure AND verifies its signature chains to a genuine Intel TDX root,
// returning the enclave's measurement and its raw 64-byte report_data. It must
// fail closed — return an error, never zero values with a nil error — when the
// quote is malformed, unsigned, or does not chain to a trusted root.
//
// It is a seam so the dependency-heavy TDX verification (go-tdx-guest, Intel
// PCK cert chain) can be filled in later (issue #7) and so tests can inject a
// controlled fake. The two checks this package owns — measurement allowlist and
// report_data binding — sit on top of whatever this returns.
type quoteParser func(rawQuote []byte) (Measurement, [64]byte, error)

// notConfigured is the default parser: it trusts nothing. A Verifier is only
// useful once WithQuoteParser installs a real (or, in tests, fake) parser.
func notConfigured([]byte) (Measurement, [64]byte, error) {
	return Measurement{}, [64]byte{}, ErrQuoteVerifierNotConfigured
}

// Verifier verifies provider quotes against a fixed Policy. It is immutable
// after New and safe for concurrent use.
type Verifier struct {
	policy Policy
	parse  quoteParser
}

// Option customizes a Verifier.
type Option func(*Verifier)

// WithQuoteParser installs the TDX quote parser/verifier. Without it the
// Verifier is fail-closed (every Verify returns ErrQuoteVerifierNotConfigured).
// Production wires a go-tdx-guest-backed parser here; tests inject a fake.
func WithQuoteParser(p quoteParser) Option {
	return func(v *Verifier) {
		if p != nil {
			v.parse = p
		}
	}
}

// New returns a Verifier that accepts quotes whose measurement is in policy's
// allowlist. It defaults to the fail-closed parser, so a caller that forgets to
// supply one rejects every quote rather than trusting it.
func New(policy Policy, opts ...Option) *Verifier {
	v := &Verifier{policy: policy, parse: notConfigured}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verified is the trusted result of Verify: the keys bound into a genuine quote
// whose measurement the client accepts.
type Verified struct {
	// EncPub is the HPKE recipient key the client may now seal to (§4.4: "only
	// then is enc_pub trusted as the HPKE recipient").
	EncPub crypto.PublicKey
	// SignerAddr is the provider's TEE signer address from report_data. The
	// caller MUST still confirm it equals the provider's on-chain
	// teeSignerAddress before pinning (SPEC §4.4 step 3; issue #18) — this
	// package returns it but does not know the chain.
	SignerAddr string
	// Measurement is the accepted measurement, surfaced for logging/audit.
	Measurement Measurement
}

// Verify runs the full SPEC §4.4 pre-seal check on a raw provider quote:
//
//  1. parse — verify it is a genuine, signed TDX quote and extract its
//     measurement + report_data (the quoteParser seam).
//  2. allowlist — the measurement MUST be one the client audited (Policy).
//  3. binding — decode report_data (§4.2) for enc_pub + signer_addr.
//
// Every step is fail-closed: any failure returns an error and no Verified, so a
// candidate that does not fully verify is never sealed to.
func (v *Verifier) Verify(rawQuote []byte) (Verified, error) {
	if len(rawQuote) == 0 {
		return Verified{}, fmt.Errorf("attest: empty quote")
	}

	// 1. Genuine TDX + untampered signature (seam).
	measurement, reportData, err := v.parse(rawQuote)
	if err != nil {
		return Verified{}, fmt.Errorf("attest: quote verification: %w", err)
	}

	// 2. Measurement allowlist — the load-bearing defense against a router that
	// routes to an enclave running unaudited (malicious) code. Checked before
	// trusting any key the quote carries.
	if !v.policy.permits(measurement) {
		return Verified{}, ErrUntrustedMeasurement
	}

	// 3. Bind the keys out of the verified report_data.
	rd, err := ParseReportData(reportData[:])
	if err != nil {
		return Verified{}, err
	}

	return Verified{
		EncPub:      rd.EncPub,
		SignerAddr:  rd.SignerAddr,
		Measurement: measurement,
	}, nil
}
