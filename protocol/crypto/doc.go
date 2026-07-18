// Package crypto implements the security-critical wire crypto once: HPKE
// sealing to a provider enclave key, EIP-191 (personal_sign) response-signature
// recovery/verification, and key helpers.
//
// Contract: broker <-> client (byte-for-byte, per SPEC.md).
package crypto
