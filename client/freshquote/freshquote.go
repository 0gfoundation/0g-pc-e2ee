// Package freshquote is the nonce-bound attestation served at GET /evidence: a TDX
// quote minted on request, whose report_data commits to a caller's nonce and to the
// public key of the TLS certificate this CVM serves.
//
// The layout is AntSeed's `nonce-pubkey-sha256-v1`, matched byte for byte so their
// verifier accepts it unchanged:
//
//	report_data[0:32]  = SHA-256(nonce_hex ‖ e2e_pubkey_b64)
//	report_data[32:64] = zero
//
// nonce_hex is the lowercase hex of the 32-byte nonce and e2e_pubkey_b64 is the
// standard base64 of the leaf certificate's DER SubjectPublicKeyInfo, both hashed as
// their ASCII strings. The nonce is fixed-length, so the concatenation is unambiguous.
//
// What this adds over the /evidences bundle is freshness: the quote was minted after
// the caller picked the nonce. See docs/design/cloud-gateway.md §6.1.
package freshquote

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// NonceBytes is the nonce length the route accepts.
const NonceBytes = 32

// Response is the JSON body of GET /evidence.
type Response struct {
	// Quote is the raw TDX quote, standard base64.
	Quote string `json:"quote"`
	// E2EPubkey is the served certificate's SubjectPublicKeyInfo (DER), standard base64.
	E2EPubkey string `json:"e2e_pubkey"`
}

// ParseNonce validates a nonce given as hex and returns its canonical lowercase form,
// which is what the report_data commits to. Upper-case input is accepted and folded.
func ParseNonce(s string) (string, error) {
	if len(s) != 2*NonceBytes {
		return "", fmt.Errorf("nonce must be %d hex characters", 2*NonceBytes)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", errors.New("nonce must be hex")
	}
	return hex.EncodeToString(b), nil
}

// ReportData builds the 64-byte report_data for a canonical nonce and a base64 SPKI.
func ReportData(nonceHex, pubkeyB64 string) [64]byte {
	var rd [64]byte
	h := sha256.New()
	h.Write([]byte(nonceHex))
	h.Write([]byte(pubkeyB64))
	copy(rd[:], h.Sum(nil))
	return rd
}

// SPKIBase64 returns the base64 SubjectPublicKeyInfo of the first certificate in a
// PEM file — the leaf, in the fullchain layout dstack-ingress writes.
func SPKIBase64(certPEM []byte) (string, error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return "", errors.New("no CERTIFICATE block")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse certificate: %w", err)
		}
		return base64.StdEncoding.EncodeToString(cert.RawSubjectPublicKeyInfo), nil
	}
}
