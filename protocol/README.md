# 0g-pc-e2ee/protocol

The shared **protocol contract** for the 0G Private Computer end-to-end-encrypted
(E2EE) inference stack. It is the single source of truth that the provider
broker, the router, and the client all depend on, so every participant agrees
**byte-for-byte** on how requests are sealed and how responses are proven.

> **"E2EE" here is the broad sense** — both halves of an end-to-end secure
> channel to an attested provider enclave: **confidentiality** (sealing the
> prompt/tool defs to the enclave) *and* **authenticity** (attestation binding +
> response-signature verification). It does **not** mean confidentiality alone.

> Status: early / design-stage. `SPEC.md` is normative; APIs will change.

## Why this exists

- **One implementation of security-critical crypto.** Sealing, response-signature
  verification, and attestation binding are implemented and audited **once** here
  — not re-written per component, where a subtle divergence (EIP-191 prefix, HPKE
  params, quote parsing) would silently break security.
- **No protocol drift.** The broker *produces* proofs, the client *verifies*
  them, and the router *routes* on the envelope's cleartext manifest — if any two
  disagree on the wire format, verification or routing breaks. Pinning them to
  one module (and one spec) prevents that.

## What's inside

| Area | Contents |
|------|----------|
| **Wire / envelope** | The request envelope: cleartext **route manifest** + **sealed body**; encode/decode; field classification (what is cleartext vs sealed) |
| **Crypto** | HPKE sealing to a provider enclave key; EIP-191 (`personal_sign`) response-signature recovery/verification; key helpers |
| **Attestation** | Quote parsing → measurement + `report_data` (signer / encryption pubkey) extraction; binding to the on-chain `teeSignerAddress` |
| **Proof** | The versioned routing-proof text (`zg-routing-proof-v1: …`), `ChatSignature`, `CapturedCert` |
| **Types** | Shared types: `Candidate`, `RouteManifest`, `ChatSignature`, … |

### Design principle: pure, no I/O

This module is a **pure library** — no network, no filesystem, no global state.
That keeps it easy to audit and safe to embed in every component.

Provider **scoring / ranking is not part of this contract** — it lives entirely
in the **router**, which exposes it as an API (request metadata in → best
provider + fallback list out). The client does not re-run any scorer, so there is
no ordering to keep in sync here. This module carries a single contract: the
confidentiality / proof **wire format** (`wire crypto attest proof`) that binds
**broker ↔ client**, plus the shared `types`. The invariant is unchanged —
*everyone on `protocol` vX, no drift*.

## Layout

```
SPEC.md          # normative wire + envelope + proof spec — source of truth for ALL languages
wire/            # envelope encode/decode (route manifest + sealed body)
crypto/          # HPKE sealing, EIP-191 response-signature verify, key helpers
attest/          # quote parsing, measurement / report_data extraction, on-chain signer binding
proof/           # zg-routing-proof-v1 text format, ChatSignature, CapturedCert
types/           # Candidate, RouteManifest, ChatSignature, ...
```

The Go packages here are the **reference implementation**. Any non-Go
implementation (e.g. a TS/WASM build for the browser client) must conform to
`SPEC.md` and match the reference byte-for-byte.

## Benchmarks

Micro-benchmarks cover the two hot paths separately, so cost is attributable to
the layer that owns it:

```
cd protocol
go test -run '^$' -bench . -benchmem ./crypto/... ./wire/...
```

- **`crypto`** isolates the HPKE handshake (`SetupSender`/`SetupReceiver` — one
  X25519 DH per request) from the ChaCha20-Poly1305 AEAD (`SealAEAD`, a reused
  context, i.e. streaming's per-frame cost), plus the full one-shot `Seal`/`Open`
  across payload sizes and a parallel run for core scaling.
- **`wire`** measures the end-to-end envelope — `SealRequest`/`OpenRequest` and
  `Seal`/`OpenResponse` — **including** JCS canonicalization and JSON, plus
  `ResponseSealFrame` for the per-frame streaming cost.

Two things the numbers make concrete: the per-request cost is dominated by the
single X25519 handshake (the AEAD is comparatively free), and at large payloads
the end-to-end envelope is bounded by JCS + JSON, not the crypto. Absolute
figures are machine-dependent — run the benches on the target host rather than
pinning numbers here.