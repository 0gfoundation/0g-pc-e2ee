// Package core is the single client core shared by all three forms — sidecar,
// cloud-TEE gateway, and in-process SDK. It performs: verify quote -> seal ->
// pin -> fallback -> verify response signature -> key cache.
//
// The security-critical crypto lives here exactly once (delegated to the shared
// protocol module). The three shells around it MUST NOT reimplement seal/verify;
// they only wrap this core (as a server, or as a library).
package core
