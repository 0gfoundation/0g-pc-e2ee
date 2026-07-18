// Package attest parses TEE quotes into measurement + report_data (signer /
// encryption pubkey) and binds them to the on-chain teeSignerAddress.
//
// Contract: broker <-> client (byte-for-byte, per SPEC.md).
package attest
