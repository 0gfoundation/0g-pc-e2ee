// Package attest verifies a provider's TEE attestation quote and extracts the
// keys it binds, so a client seals only to an enc key proven to live inside a
// genuine enclave running audited code — not merely to whatever key an
// (untrusted) router handed over.
//
// The verification contract mirrors SPEC §4.4 "Client obligations before
// sealing":
//
//  1. Verify the quote — genuine TDX + expected measurement. The measurement is
//     checked against a Policy allowlist the *client* holds (the audited
//     0gfoundation/broker image), never a value the router or provider self-
//     reports; a measurement outside the allowlist is rejected.
//  2. Extract enc_pub + signer_addr from the 64-byte report_data (§4.2) and
//     check its version. This binds both keys into the same attestation, so a
//     verifier reads enc_pub straight out of a verified quote — no side channel,
//     no chance for an intermediary to substitute a key.
//
// Step 3 of §4.4 — confirming signer_addr equals the provider's on-chain
// teeSignerAddress — is deliberately NOT done here: it belongs to the caller
// (the route resolver), which knows the on-chain identity. Verify returns the
// bound signer_addr for the caller to cross-check (issue #18).
//
// # What is real vs. deferred in this skeleton
//
// The two load-bearing checks are implemented and tested here:
//
//   - report_data / enc_pub binding — ParseReportData decodes the §4.2 layout
//     byte-for-byte and fails closed on any malformation.
//   - measurement allowlist — Policy.permits gates on a client-held set.
//
// The genuinely hard, dependency-heavy part — parsing the raw TDX quote
// structure and verifying its signature chains to Intel's roots — is isolated
// behind the quoteParser seam (WithQuoteParser). The default parser is
// fail-closed: a Verifier constructed without a real parser rejects every quote
// with ErrQuoteVerifierNotConfigured, so a no-op verification can never silently
// trust anything. Wiring a production parser (go-tdx-guest) and threading Verify
// into the route fallback loop are follow-up steps (issue #7).
//
// Contract: broker <-> client (byte-for-byte, per SPEC.md).
package attest
