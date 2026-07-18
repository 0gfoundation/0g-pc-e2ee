# sdk/ts — browser (TS / WASM) build

> Status: planned. Placeholder for the browser segment.

A focused TypeScript / WASM build of **just verify + seal** for pure-browser
clients (in-browser quote verification + HPKE), since Go→WASM is awkward for a
browser crypto/network library.

## Important: this does NOT import the Go core

Unlike `cmd/*` and `sdk/go` (which share `client/core` in Go), this build is a
**different language stack**. It cannot reuse the Go core. It stays in lockstep
with the Go reference implementation **only** through the frozen wire spec —
[`protocol/SPEC.md`](../../../protocol/SPEC.md) — and must match it
byte-for-byte. The spec, not shared code, is the alignment anchor here.

If/when multi-language in-process SDKs are needed, this is where a
Rust core + `wasm-bindgen` (and `napi-rs` / `PyO3` for other languages) would
live, per the design doc.
