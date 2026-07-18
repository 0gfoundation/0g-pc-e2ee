// Package wire defines the request envelope — the cleartext route manifest
// plus the sealed body — and its encode/decode. It also classifies which
// fields travel in cleartext (routing params, billing) versus sealed
// (prompt, tool defs).
//
// Contract: broker <-> client (byte-for-byte, per SPEC.md).
package wire
