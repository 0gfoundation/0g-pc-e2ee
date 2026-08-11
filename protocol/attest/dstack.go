package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// QuoteResponse is a provider's /v1/quote reply (the dstack / Phala shape).
//
// Only Quote — the hex-encoded Intel TDX quote — is part of the trusted path:
// the quote is the sole artifact Intel signs. The real reply also carries
// event_log, tcb_info, vm_config and app_compose, but NONE of those are signed
// by Intel; they are convenience decodes a caller must not trust directly. A
// verifier re-derives everything it needs from the *verified* quote instead of
// reading tcb_info: the measurement registers and, for app identity, the compose
// hash in mr_config_id (see ComposeHashFromMRConfigID — it is in the signed report,
// so no event-log replay is involved). Those fields are intentionally omitted from
// this struct so the trusted path cannot accidentally depend on them.
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

// MRConfigVersion is the layout version in the first byte of a dstack
// mr_config_id. dstack packs the app's identity into that register; the version
// selects how, and the layouts are NOT interchangeable (see
// ComposeHashFromMRConfigID).
type MRConfigVersion uint8

const (
	// MRConfigV1 is `0x01 ‖ compose_hash(32) ‖ zero padding`. The compose hash is
	// carried in the clear, so it can be read straight out.
	MRConfigV1 MRConfigVersion = 1
	// MRConfigV2 is `0x02 ‖ keccak256(compose_hash‖app_id‖key_provider_kind‖key_provider_id) ‖ zeros`.
	// The compose hash is *inside* a digest, so it cannot be extracted — only
	// confirmed, and only by a caller that already holds every input.
	MRConfigV2 MRConfigVersion = 2
	// MRConfigV3 is `0x03 ‖ <hash of a JCS mr_config document> ‖ …`. Like V2 the
	// compose hash is not directly recoverable; verification needs the document.
	MRConfigV3 MRConfigVersion = 3
)

// ErrUnsupportedMRConfig is returned when an mr_config_id does not use a layout
// this package can read a compose hash out of — an unknown version, or V2/V3,
// where the hash is committed inside a digest rather than carried in the clear.
var ErrUnsupportedMRConfig = errors.New("attest: mr_config_id layout does not expose compose_hash")

// ComposeHashLen is the length of a dstack compose hash: SHA-256 over the bytes
// of the CVM's app-compose.json.
const ComposeHashLen = sha256.Size

// ComposeHashFromMRConfigID reads the dstack **compose hash** out of a TD's
// mr_config_id — the app-identity commitment `docs/design/cloud-gateway.md` §6.1
// calls `app_id`'s source.
//
// compose_hash is SHA-256 over the bytes of the CVM's `app-compose.json`, the
// manifest that embeds the docker-compose text verbatim. So a verified quote
// plus this register pins **which configuration, and therefore which container
// images, the CVM booted** — the "code identity" half of the gateway's
// attestation. Recovering it needs no event-log replay: mr_config_id is part of
// the signed TD report, so whatever verified the quote already authenticated it.
// (The `compose-hash` runtime event in RTMR3 carries the same value and can be
// cross-checked, but the event log is unsigned data and would itself have to be
// replayed against RTMR3 to be trustworthy.)
//
// Only MRConfigV1 exposes the hash. V2 and V3 commit to it inside a digest, so
// they return ErrUnsupportedMRConfig rather than a guess: a caller holding all of
// V2's inputs can recompute and compare, but that is a different operation from
// extraction and must not be conflated with it.
//
// An all-zero mr_config_id (a TD built without one) also fails — there is nothing
// to read, and returning a zero hash would look like a real commitment.
func ComposeHashFromMRConfigID(mrConfigID [mrConfigIDLen]byte) ([ComposeHashLen]byte, error) {
	var out [ComposeHashLen]byte
	version := MRConfigVersion(mrConfigID[0])
	if version != MRConfigV1 {
		return out, fmt.Errorf("%w: version %d", ErrUnsupportedMRConfig, version)
	}
	// Everything past the hash MUST be zero: a nonzero tail means a producer whose
	// layout only coincidentally starts with 0x01, and reading 32 bytes out of it
	// would invent a commitment.
	for i, b := range mrConfigID[1+ComposeHashLen:] {
		if b != 0 {
			return out, fmt.Errorf("%w: v1 padding byte %d is 0x%02x, want zero",
				ErrUnsupportedMRConfig, 1+ComposeHashLen+i, b)
		}
	}
	copy(out[:], mrConfigID[1:1+ComposeHashLen])
	if out == ([ComposeHashLen]byte{}) {
		return [ComposeHashLen]byte{}, fmt.Errorf("%w: compose_hash is all zero", ErrUnsupportedMRConfig)
	}
	return out, nil
}

// AppIDLen is the length of a dstack app_id: the leading bytes of compose_hash.
const AppIDLen = 20

// AppIDFromComposeHash derives the dstack `app_id` — the first AppIDLen bytes of
// compose_hash, hex-encoded (dstack's own `short(&hash, 40)`). It is the name the
// platform routes and labels by, so it is what an operator recognises; the full
// compose_hash is the stronger value and is what verification should compare.
func AppIDFromComposeHash(composeHash [ComposeHashLen]byte) string {
	return hex.EncodeToString(composeHash[:AppIDLen])
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
