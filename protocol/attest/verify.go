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
	// ErrUntrustedMeasurement is returned when a genuine quote's boot chain is not
	// in the BootChainPolicy allowlist — i.e. the enclave runs an OS image the
	// client has not audited.
	ErrUntrustedMeasurement = errors.New("attest: quote boot chain not in allowlist")
	// ErrMeasurementPolicyNotConfigured is returned under ModeEnforce when the
	// allowlist is empty. Enforcing against nothing rejects every provider, which
	// is correct (fail-closed) but says nothing about the providers — it is an
	// unfinished configuration, not a finding about the enclave. Distinguishing it
	// is what stops "enforce is on and the allowlist is empty" from being read, one
	// provider at a time, as "every provider runs unaudited code".
	ErrMeasurementPolicyNotConfigured = errors.New("attest: measurement enforcement requested with an empty allowlist")
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

// MeasurementMode selects what Verify does when an authenticated quote's boot
// chain is NOT in the BootChainPolicy allowlist. Quote authenticity (genuine TDX +
// signature) and report_data binding are ALWAYS enforced regardless of mode;
// this knob only governs the measurement-allowlist decision.
type MeasurementMode int

const (
	// ModeEnforce (the zero value, and the secure default) rejects a quote whose
	// boot chain is not allowlisted: the enclave runs an unaudited image. An empty
	// allowlist rejects everything under this mode — see
	// ErrMeasurementPolicyNotConfigured, which names that case rather than blaming
	// the provider for it.
	ModeEnforce MeasurementMode = iota
	// ModeWarn accepts such a quote but marks Verified.MeasurementTrusted false,
	// leaving it to the caller to log and decide. Use it as a rollout bridge
	// before the audited-image allowlist is finalized — never as a silent accept.
	ModeWarn
)

// Verifier verifies provider quotes against a fixed BootChainPolicy. It is
// immutable after New and safe for concurrent use.
type Verifier struct {
	policy BootChainPolicy
	parse  quoteParser
	mode   MeasurementMode
}

// Option customizes a Verifier.
type Option func(*Verifier)

// WithMeasurementMode sets how an out-of-allowlist measurement is handled
// (default ModeEnforce). It does not affect quote-authenticity or report_data
// checks, which are always enforced.
func WithMeasurementMode(m MeasurementMode) Option {
	return func(v *Verifier) { v.mode = m }
}

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

// New returns a Verifier that accepts quotes whose boot chain is in policy's
// allowlist. It defaults to the fail-closed parser, so a caller that forgets to
// supply one rejects every quote rather than trusting it.
func New(policy BootChainPolicy, opts ...Option) *Verifier {
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
	// teeSignerAddress before pinning (SPEC §4.4 step 3) — this package returns
	// it but does not know the chain; the route resolver does that check (see
	// client/route WithOnChainVerification).
	SignerAddr string
	// Measurement is the quote's full register set, surfaced for logging/audit.
	// BootChainOf projects it onto the registers the allowlist actually compares.
	Measurement Measurement
	// MeasurementTrusted reports whether BootChainOf(Measurement) is in the
	// BootChainPolicy allowlist. It is always true under ModeEnforce (a false would
	// have errored). Under ModeWarn it may be false: the quote is genuine and
	// EncPub/SignerAddr are safely bound, but the enclave runs an image the client
	// has not audited — the caller MUST log this before proceeding. It is also
	// false, under ModeWarn, when no allowlist is configured at all; the two are
	// distinguishable only under ModeEnforce, via the error.
	MeasurementTrusted bool
}

// Verify runs the full SPEC §4.4 pre-seal check on a raw provider quote:
//
//  1. parse — verify it is a genuine, signed TDX quote and extract its
//     measurement + report_data (the quoteParser seam).
//  2. allowlist — the quote's BOOT CHAIN (MRTD + RTMR1 + RTMR2) must be one the
//     client audited (BootChainPolicy); under ModeWarn a miss is tolerated and
//     flagged instead (see MeasurementMode).
//  3. binding — decode report_data (§4.2) for enc_pub + signer_addr.
//
// Steps 1 and 3 are always fail-closed: any failure returns an error and no
// Verified. Only step 2's allowlist decision is softened by ModeWarn.
//
// Step 2 compares the boot chain rather than the full Measurement because RTMR3
// carries per-INSTANCE events (see BootChain): a full-equality entry pins one CVM,
// so an allowlist of that shape needed an entry per replica and could never be
// published ahead of a deployment. This is the OS-image half of the code root; the
// application half is the compose hash in mr_config_id, which this seam does not
// surface yet — the gateway pins it separately (client/evidence), and the provider
// path cannot until quoteParser returns it.
func (v *Verifier) Verify(rawQuote []byte) (Verified, error) {
	if len(rawQuote) == 0 {
		return Verified{}, fmt.Errorf("attest: empty quote")
	}

	// 1. Genuine TDX + untampered signature (seam).
	measurement, reportData, err := v.parse(rawQuote)
	if err != nil {
		return Verified{}, fmt.Errorf("attest: quote verification: %w", err)
	}

	// 2. Boot-chain allowlist — the load-bearing defense against a router that
	// routes to an enclave running unaudited (malicious) code. Under ModeEnforce
	// a miss is fatal (checked before trusting any key the quote carries); under
	// ModeWarn it is recorded on the result for the caller to log and decide.
	trusted := v.policy.Permits(BootChainOf(measurement))
	if !trusted && v.mode == ModeEnforce {
		// An empty allowlist rejects every provider. Still fail-closed, but report it
		// as the configuration gap it is rather than as a verdict on this enclave.
		if !v.policy.Configured() {
			return Verified{}, ErrMeasurementPolicyNotConfigured
		}
		return Verified{}, ErrUntrustedMeasurement
	}

	// 3. Bind the keys out of the verified report_data. This is enforced in every
	// mode — ModeWarn relaxes only the allowlist decision, never report_data
	// validity.
	rd, err := ParseReportData(reportData[:])
	if err != nil {
		return Verified{}, err
	}

	return Verified{
		EncPub:             rd.EncPub,
		SignerAddr:         rd.SignerAddr,
		Measurement:        measurement,
		MeasurementTrusted: trusted,
	}, nil
}
