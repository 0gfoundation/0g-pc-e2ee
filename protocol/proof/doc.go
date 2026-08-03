// Package proof defines the §8 response-signature contract shared by the broker
// (which signs) and the client (which verifies), byte-for-byte per SPEC.md.
//
// It holds the versioned signed-text format ("<scheme>:<reqH>:<respH>"), the
// injective §8 binding (BindingHash = sha256(sha256(aad)‖sha256(ct))), the
// non-stream and streaming text builders (SignedTextE2EE / SignedTextE2EEStream /
// StreamBinder), and the fail-closed verifier (ChatSignature.VerifyE2EE[Stream]).
//
// The binding is assembled in exactly one place so the bytes cannot drift: the
// broker imports the SignedText* builders to sign, and the client calls the same
// code to recompute and verify. secp256k1/keccak recovery is injected via
// RecoverFunc, keeping this package dependency-light and portable.
//
// Scope: E2EE (ciphertext-bound) only. The plaintext scheme tag is defined for
// contract completeness but its verifier lives with the out-of-band auditor, not
// here (the plaintext-direct flow never traverses the E2EE client) — see
// 0g-pc-e2ee#48.
package proof
