# 0g-pc-protocol

The shared **protocol contract** for the 0G Private Computer verifiable-inference
stack. It is the single source of truth that the provider broker, the router,
and the client all depend on, so every participant agrees **byte-for-byte** on
how requests are sealed, how responses are proven, and how providers are ranked.

> Status: early / design-stage. `SPEC.md` is normative; APIs will change.

## Why this exists

- **One implementation of security-critical crypto.** Sealing, response-signature
  verification, and attestation binding are implemented and audited **once** here
  — not re-written per component, where a subtle divergence (EIP-191 prefix, HPKE
  params, quote parsing) would silently break security.
- **No protocol drift.** The broker *produces* proofs, the client *verifies*
  them, the router *routes* — if any two disagree on the wire format or the
  scoring rule, verification or routing breaks. Pinning them to one module (and
  one spec) prevents that.

## What's inside

| Area | Contents |
|------|----------|
| **Wire / envelope** | The request envelope: cleartext **route manifest** + **sealed body**; encode/decode; field classification (what is cleartext vs sealed) |
| **Crypto** | HPKE sealing to a provider enclave key; EIP-191 (`personal_sign`) response-signature recovery/verification; key helpers |
| **Attestation** | Quote parsing → measurement + `report_data` (signer / encryption pubkey) extraction; binding to the on-chain `teeSignerAddress` |
| **Proof** | The versioned routing-proof text (`zg-routing-proof-v1: …`), `ChatSignature`, `CapturedCert` |
| **Route** | A **pure** scoring function `(candidates, stats) → ranked order` |
| **Types** | Shared types: `Candidate`, `RouteManifest`, `ChatSignature`, … |

### Design principle: pure, no I/O

This module is a **pure library** — no network, no filesystem, no global state.
That keeps it easy to audit and safe to embed in every component.

In particular, **route scoring is a pure function**: it ranks a candidate list
using stats passed in. The **live fleet view** (which providers are up, load,
price) and the endpoints stay in the **router** — the router (and the client,
over the router-returned candidate list) call the *same* scorer so their ordering
always agrees, without the client needing global data.

### Two contracts, one module (and why `route` stays here)

This module bundles two *orthogonal* contracts, plus their shared types:

| Contract | Binds | Packages |
|----------|-------|----------|
| Confidentiality / proof (wire format — one wrong byte breaks security) | **broker ↔ client** | `wire crypto attest proof` |
| Routing / ranking (both sides run the same algorithm to agree on order) | **router ↔ client** | `route` |
| Shared foundation | everyone | `types` |

`route` has a *different* consumer pair than the crypto packages, which invites
splitting it out. We deliberately **keep it in `protocol`**: it is a pure,
dependency-free function, so a broker that imports the crypto packages carries
no `route` weight anyway; the **client uses both** contracts, so a split only
adds a second version to pin; and both contracts share `types`, so a split
forces a dependency diamond. Keeping one module preserves the core invariant —
*everyone on `protocol` vX, no drift*. `route` is kept as a clean, self-contained
package so it can be promoted to its own module later **if** it ever grows heavy
deps or its release cadence diverges sharply from the audited crypto — neither
is true today.

## Layout

```
SPEC.md          # normative wire + envelope + proof spec — source of truth for ALL languages
wire/            # envelope encode/decode (route manifest + sealed body)
crypto/          # HPKE sealing, EIP-191 response-signature verify, key helpers
attest/          # quote parsing, measurement / report_data extraction, on-chain signer binding
proof/           # zg-routing-proof-v1 text format, ChatSignature, CapturedCert
route/           # pure scoring: (candidates, stats) -> ranked
types/           # Candidate, RouteManifest, ChatSignature, ...
```

The Go packages here are the **reference implementation**. Any non-Go
implementation (e.g. a TS/WASM build for the browser client) must conform to
`SPEC.md` and match the reference byte-for-byte.