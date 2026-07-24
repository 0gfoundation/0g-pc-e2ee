// Package tee produces the cloud-TEE gateway's own attestation quote and serves
// it for download, so an out-of-band validator (or a tier-3 client) can confirm
// the endpoint is a genuine enclave running the expected measurement — the
// validation plane of docs/design/cloud-gateway.md (§6, phase 2).
//
// This is the *gateway's* quote (it attests the gateway enclave), distinct from
// the *provider's* quote the client verifies on the seal path (protocol/attest,
// SPEC §4). Per the design (§6.1), report_data binds the enclave's TLS
// certificate public key, so the quote proves "this measurement controls this
// cert"; ReportDataForCert builds that binding.
//
// Quote verification (genuine TDX hardware + expected measurement) is the
// downloader's job and is deliberately NOT here — this package only *produces*
// the quote.
package tee

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
)

// MaxReportData is the TDX report_data capacity. dstack rejects a longer value,
// so callers MUST bind at most this many bytes; shorter values are zero-padded
// by the TEE.
const MaxReportData = 64

// certBindingDomain domain-separates the TLS-cert-key binding from any other
// report_data scheme. Without it, SHA-256(SPKI) (32 bytes) would be
// byte-indistinguishable from a raw 32-byte X25519 enc-pubkey that a provider
// quote may bind (SPEC §4.2), so a verifier handling both quote kinds could
// confuse them. Hashing a fixed domain prefix makes the cert binding a distinct,
// self-consistent value.
const certBindingDomain = "0g-pc/gateway-tls-cert/v1"

// Quote is the enclave attestation as produced by the TEE, served verbatim at
// GET /quote for a downloader to verify. Fields mirror dstack's GetQuote
// response (the broker's QuoteResponseWithNvidia, minus the GPU payload the
// gateway does not carry).
type Quote struct {
	Quote      string `json:"quote"`               // hex TDX quote
	EventLog   string `json:"event_log"`           // RTMR event log
	ReportData []byte `json:"report_data"`         // the 64-byte report_data bound into the quote
	VmConfig   string `json:"vm_config,omitempty"` // dstack VM config
	TcbInfo    string `json:"tcb_info,omitempty"`  // TCB info for TCB-status checks
}

// Attestor produces the enclave's quote over a caller-supplied report_data.
// The dstack implementation talks to the in-enclave tappd socket; the mock is
// for local/dev where no TEE is present.
type Attestor interface {
	// Quote returns the enclave quote binding reportData. reportData MUST be at
	// most MaxReportData bytes.
	Quote(ctx context.Context, reportData []byte) (*Quote, error)
}

// ReportDataForCert returns the MaxReportData-byte report_data that binds a TLS
// certificate to the quote: SHA-256(certBindingDomain || SubjectPublicKeyInfo)
// in the leading 32 bytes, the remaining bytes zero. It hashes the public key
// (not the whole cert) so the binding survives cert re-issuance that keeps the
// key, and prefixes a domain tag so it cannot be confused with another 32-byte
// binding (see certBindingDomain). Design §6.1.2.
//
// The full MaxReportData-byte value is returned (not the bare 32-byte digest) so
// the producer and a verifier agree byte-for-byte on report_data: the TEE embeds
// exactly these 64 bytes into the quote, and a verifier that extracts the 64-byte
// report_data field can compare it directly.
//
// SECURITY CONTRACT: cert MUST be the enclave-controlled TLS certificate — the
// one dstack ZT-HTTPS provisions and terminates TLS with, whose private key is
// generated in and never leaves the TEE (design §5.3, §7). The quote only proves
// "measurement X hashed this public key"; it is the enclave's *control* of the
// matching private key (established by dstack provisioning it in-enclave) that
// makes "measurement X controls this cert" sound. Binding an arbitrary externally
// held cert produces a genuine but meaningless quote.
func ReportDataForCert(cert *x509.Certificate) []byte {
	h := sha256.New()
	h.Write([]byte(certBindingDomain))
	h.Write(cert.RawSubjectPublicKeyInfo)
	rd := make([]byte, MaxReportData)
	copy(rd, h.Sum(nil))
	return rd
}
