package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// QuoteResponse is a provider's /v1/quote reply (the dstack / Phala shape).
//
// Only Quote — the hex-encoded Intel TDX quote — is part of the trusted path:
// the quote is the sole artifact Intel signs. The real reply also carries
// event_log, tcb_info, vm_config and app_compose, but NONE of those are signed
// by Intel; they are convenience decodes a caller must not trust directly. A
// verifier re-derives the measurement from the *verified* quote (and, for app
// identity, replays the event log against it) instead of reading tcb_info. Those
// fields are intentionally omitted from this struct so the trusted path cannot
// accidentally depend on them.
type QuoteResponse struct {
	Quote string `json:"quote"`
}

// DecodeQuoteResponse parses a /v1/quote JSON body and returns the raw
// (hex-decoded) TDX quote bytes, ready for verification and structural parsing.
// It does not verify anything — it only unwraps the transport.
func DecodeQuoteResponse(body []byte) ([]byte, error) {
	var qr QuoteResponse
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("attest: decode quote response: %w", err)
	}
	if qr.Quote == "" {
		return nil, fmt.Errorf("attest: quote response has no \"quote\" field")
	}
	raw, err := hex.DecodeString(qr.Quote)
	if err != nil {
		return nil, fmt.Errorf("attest: quote is not valid hex: %w", err)
	}
	return raw, nil
}

// evidenceManifestHashLen is the length of the SHA-256 digest the cert-binding
// report_data opens with; the remaining reportDataLen-evidenceManifestHashLen
// bytes are the zero padding.
const evidenceManifestHashLen = sha256.Size

// EvidenceReportData computes the 64-byte report_data a dstack-ingress
// **cert-binding** quote must carry for a given evidence manifest: the SHA-256 of
// the manifest, right-padded with zero bytes
// (docs/design/cloud-gateway.md §6.1, deploy/phala/README.md "Verify").
//
// manifest is the verbatim bytes of the bundle's `sha256sum.txt`, which in turn
// hashes every other published evidence file (the served certificate chain and
// the ACME account document). So this one binding transitively commits the quote
// to the whole bundle: recompute it, compare it to the verified quote's
// report_data, and a match proves the enclave — not whoever served the HTTP
// response — chose those exact files.
//
// **This is a different layout from ParseReportData (SPEC §4.2), by a different
// producer, and the two must never be crossed.** §4.2 is the *provider broker's*
// `enc_pub‖signer_addr‖version` binding, whose keys the client seals to;
// dstack-ingress emits the layout here, which carries no keys at all. Feeding an
// evidence quote to ParseReportData fails closed on the version field (these
// bytes have zeros where §4.2 expects version 1) — which is correct, and is why
// this second entry point exists rather than a looser parse in one place.
//
// Producer note: dstack-ingress pads in the *hex* domain, appending ASCII '0'
// until the query parameter is 128 characters (`evidence-lib.sh`,
// `evidence_finalize`), which decodes to the zero-byte padding used here.
func EvidenceReportData(manifest []byte) [reportDataLen]byte {
	sum := sha256.Sum256(manifest)
	var rd [reportDataLen]byte
	copy(rd[:], sum[:])
	return rd
}

// VerifyEvidenceReportData checks that rd — the report_data of an already
// **DCAP-verified** cert-binding quote — is the binding for manifest, i.e. that
// the enclave committed to this exact evidence bundle. It reports which half
// diverged so a caller can tell a stale bundle (the digest moved, e.g. evidence
// regenerated after a renewal while an older quote is still served) from a
// producer that does not use this layout at all (nonzero padding).
//
// Order matters for the error message only: both halves must match. A plain
// comparison is used deliberately — every input here is public evidence, so
// there is no secret to leak through timing.
//
// It authenticates nothing on its own: rd must come from a quote whose signature
// chain a verifier already checked, exactly as with ParseReportData. Passing an
// attacker-chosen 64 bytes proves only that the attacker can hash.
func VerifyEvidenceReportData(rd [reportDataLen]byte, manifest []byte) error {
	want := EvidenceReportData(manifest)
	if !bytes.Equal(rd[:evidenceManifestHashLen], want[:evidenceManifestHashLen]) {
		return fmt.Errorf("%w: manifest digest %x, quote binds %x",
			ErrMalformedReportData, want[:evidenceManifestHashLen], rd[:evidenceManifestHashLen])
	}
	// The padding is part of the layout: a nonzero tail means the quote was
	// produced against a different report_data convention, so the leading match
	// alone must not be read as "this is a cert-binding quote".
	for i, b := range rd[evidenceManifestHashLen:] {
		if b != 0 {
			return fmt.Errorf("%w: padding byte %d is 0x%02x, want zero",
				ErrMalformedReportData, evidenceManifestHashLen+i, b)
		}
	}
	return nil
}
