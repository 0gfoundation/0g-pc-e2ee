package attest

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// ReportDataVersion is the report_data layout version this package implements
// (SPEC §4.2, "= 1 for this spec"). The layout is version-gated: a different
// version may place the fields differently, so ParseReportData refuses anything
// but this version rather than misread the offsets. It is independent of
// wire.Version (the envelope version) and the response envelope version — all
// three may advance separately (SPEC §8.5).
const ReportDataVersion = 1

// report_data field offsets and the total size (SPEC §4.2, 64 bytes).
const (
	reportDataLen = 64

	encPubOff   = 0  // [0:32]  X25519 public key
	encPubLen   = 32 //         (RFC 7748 u-coordinate, little-endian)
	signerOff   = 32 // [32:52] secp256k1 Ethereum address
	signerLen   = 20 //         (20 raw bytes)
	versionOff  = 52 // [52:56] uint32, big-endian
	versionLen  = 4
	reservedOff = 56 // [56:64] MUST be zero
	reservedLen = 8
)

// ErrMalformedReportData is returned when the 64-byte report_data does not match
// the §4.2 layout this package can trust: wrong length, an unsupported version
// (so the offsets cannot be relied on), or nonzero reserved bytes.
var ErrMalformedReportData = errors.New("attest: malformed report_data")

// ReportData is the decoded §4.2 report_data: the two keys a verified quote
// binds, plus the layout version. EncPub is the HPKE recipient the client seals
// to; SignerAddr is the provider's TEE signer, which the caller cross-checks
// against the on-chain teeSignerAddress (SPEC §4.4 step 3; issue #18).
type ReportData struct {
	EncPub     crypto.PublicKey // 32-byte X25519 recipient key
	SignerAddr string           // "0x" + 40 lowercase hex (the 20 raw bytes formatted)
	Version    uint32
}

// ParseReportData decodes the 64-byte report_data (SPEC §4.2). It is the
// enc_pub/report_data binding check: it fails closed on any deviation from the
// layout — a wrong length, an unsupported version, or nonzero reserved bytes —
// so a caller can only ever obtain keys from a well-formed, current-version
// report_data. It validates structure only; whether the bound measurement is
// trusted is the Policy's job, and whether SignerAddr matches the chain is the
// caller's (route) job.
//
// Note this does NOT authenticate rd: it assumes rd was extracted from a quote
// whose signature the quoteParser already verified. Parsing an attacker-chosen
// 64 bytes yields attacker-chosen keys — which is exactly why Verify runs the
// quote signature + measurement checks first.
func ParseReportData(rd []byte) (ReportData, error) {
	if len(rd) != reportDataLen {
		return ReportData{}, fmt.Errorf("%w: length %d, want %d", ErrMalformedReportData, len(rd), reportDataLen)
	}

	// Version first: the field offsets below are only valid for the layout this
	// package implements, so an unexpected version means we must not trust them.
	version := binary.BigEndian.Uint32(rd[versionOff : versionOff+versionLen])
	if version != ReportDataVersion {
		return ReportData{}, fmt.Errorf("%w: version %d, want %d", ErrMalformedReportData, version, ReportDataVersion)
	}

	// Reserved bytes MUST be zero (§4.2). A nonzero reserved region signals a
	// producer that does not match this layout — reject rather than ignore.
	for _, b := range rd[reservedOff : reservedOff+reservedLen] {
		if b != 0 {
			return ReportData{}, fmt.Errorf("%w: reserved bytes not zero", ErrMalformedReportData)
		}
	}

	// enc_pub: copy out so the returned key does not alias the caller's buffer.
	encPub := make(crypto.PublicKey, encPubLen)
	copy(encPub, rd[encPubOff:encPubOff+encPubLen])

	// signer_addr: 20 raw bytes → canonical "0x"+lowercase-hex Ethereum address.
	signer := "0x" + hex.EncodeToString(rd[signerOff:signerOff+signerLen])

	return ReportData{EncPub: encPub, SignerAddr: signer, Version: version}, nil
}
