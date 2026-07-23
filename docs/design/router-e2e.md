---

## Deployment modes & packaging

There is one **client core** — verify quote → HPKE-seal → pin → fallback →
verify response signature → key cache. *Packaging* (how it is consumed) is
independent from *trust* (who runs it, and whether it must be attested).

### Trust boundary by location

The core touches plaintext (it holds the request before sealing), so **where it
runs determines the trust boundary — not just the deployment target.**

| | Local sidecar | Cloud-TEE gateway |
|---|---|---|
| New trust party | none | one (must be attested) |
| Plaintext lands on | the user's own machine | 0G's TEE (in-enclave) |
| Attestation of the client component | not needed (user owns it) | required (else it degrades to today's plaintext L7 router) |
| How plaintext arrives | over localhost (app → sidecar) | over TLS terminated inside the enclave (browser → gateway) |
| Provider selection | via the 0G router (route-preview), per request | via the 0G router (route-preview), per request |
| Best for | clients that can run software; max privacy | clients that cannot (browser / thin / no-install) |

> Both server forms are **route-oriented**: they call the router's route-preview
> to select the provider and fetch its enc key per request (this doc originally
> envisioned the sidecar routing purely locally; it now uses the same router
> control plane as the gateway). And both simply *receive* plaintext and seal it
> to the provider — the sidecar over localhost, the gateway over in-enclave TLS.
> The 0-code gateway does **not** unwrap a client-sealed request (a plain browser
> can't seal); that app-layer "double seal → unwrap → re-seal" is the tier-3 path
> only (see cloud-gateway.md §5.1). The real difference is *where the plaintext
> lands* and whether the component must be attested — not who drives routing.

**A cloud gateway does not remove client-side crypto.** The user→gateway hop
still needs securing (RA-TLS or app-layer seal to the gateway), so the client
must still verify the gateway's quote and seal to it. If the client can do that,
it could seal to the broker directly — so, since both forms route through the
same router control plane, the gateway's added value is **handling the client's
plaintext in an attested TEE** for clients that cannot run a sidecar (browser /
thin / no-install), not centralizing routing. Trusting the gateway *without*
attestation reduces it to today's plaintext L7 router (no privacy). There is no
free lunch: cloud privacy requires attesting the cloud component.

### Packaging forms (one core, several shells)

- **In-process SDK (library):** imported into the app; `create()` verifies +
  seals inline. Lowest latency, no extra process. Cost: per-language
  maintenance; pulls crypto deps (HPKE, quote verification, ethers) into the
  app; browser needs a dedicated JS/WASM build.
- **Local sidecar (process):** the core wrapped as a localhost OpenAI-API
  proxy; user changes only `base_url`. Written once, serves any user language;
  keeps crypto out of the app. Cost: a running process + one localhost hop.
- **Cloud-TEE gateway (server in a CVM):** the same core wrapped as a server,
  run in an attested enclave. Serves no-install / browser clients; adds one
  attested trust party.

The sidecar and the gateway are the *same core wrapped as a server*; the
in-process SDK is that core *without* the server shell.

### Language plan: Go first

1. **Reuse the broker's Go code.** The core shares logic with the broker:
   ECDSA sign/recover (`go-ethereum/crypto`, already used in `signing.go`), TDX
   quote handling (`go-tdx-guest`, dstack client), and shared types
   (`ChatSignature`). One language, byte-for-byte consistency with the broker.
2. **The sidecar binary and the cloud gateway are both server-side Go
   processes** — single static binary, containerized, runs in the same
   Phala/dstack CVM the broker targets.
3. **Shipping the sidecar form covers every non-browser language on day one**
   via `base_url` (Python/TS/… keep their OpenAI SDK). No per-language
   libraries required initially.

**Known gap — the browser needs TS/WASM, and Go does not cover it well.** The
app-layer sealed channel for pure browsers needs in-browser quote verification +
HPKE. Go→WASM for a browser crypto/network library is awkward (bundle size,
WebCrypto/fetch interop), so plan a **focused TS build of just verify + seal**
for the browser segment — kept in lockstep with a written wire spec (envelope +
proof format) so it matches the Go core byte-for-byte.

**Recommended sequencing:** Go core → (1) sidecar binary (covers all
non-browser) + (2) same core reused as the cloud-TEE gateway → later, a TS/WASM
build for the browser segment.

### Shared core vs native per language (and where Go vs Rust fit)

"Go first" above is about the **server-side forms** (sidecar + gateway), which are
standalone Go processes needing no bindings. The separate question — *if we ship
in-process libraries in many languages* — is **shared core + bindings**, not
native reimplementation per language.

- **Do not re-implement the crypto natively N times.** Seal / attestation /
  fallback is security-critical; every reimplementation multiplies the audit
  surface and risks subtle divergence (EIP-191 prefix, HPKE params, quote
  parsing). Minimize implementations.
- **A shared embeddable core points to Rust, not Go.** Go makes a poor FFI/WASM
  core (cgo drags the runtime/GC, heavy shared libs, and Go→WASM is awkward for a
  browser crypto lib). Rust gives a clean small C ABI plus first-class binding
  generators — `napi-rs` (Node/TS), `PyO3` (Python), `wasm-bindgen` (browser) —
  and covers the browser gap Go cannot.
- **These do not conflict.** Server forms stay **Go** (reuse broker code, no
  FFI). A multi-language *embeddable* core, if/when needed, is a **Rust core +
  thin bindings + WASM**. Doing the Go sidecar first lets you defer — and maybe
  avoid — the Rust core entirely.
- **Split by risk.** Heavy/dangerous logic → shared core. A trivial *verify-only*
  helper (ecrecover + two SHA-256s, ~10 lines) is fine to write natively per
  language — low risk, no FFI/distribution burden.
- **Non-negotiable prerequisite:** a frozen **wire spec** (envelope + proof /
  signature format) as the single source of truth, so any implementation (Go
  core, Rust core, native verify helper) matches byte-for-byte.

| Concern | Language / form |
|---------|-----------------|
| Sidecar + cloud gateway (server) | Go native (reuse broker; no bindings) |
| Multi-language in-process SDK + browser | Rust core + `napi-rs`/`PyO3`/`wasm-bindgen` |
| Verify-only helper | native per language (trivial, low risk) |

---

## Migration & phasing

Backward compatible; sealed mode is opt-in ("privacy mode").

1. **Groundwork:** broker publishes an encryption pubkey in the quote; add the
   control-plane candidate endpoint on the router (metadata in → ranked list +
   quotes out). No client change yet.
2. **Route + seal + pin (i-a):** the client (sidecar or gateway) calls the
   router's route-preview to select a provider and fetch its enc key, seals the
   body, and sends with `pin, allow_fallbacks=false`; the L7 router authenticates,
   honors the pin, and forwards without re-routing. A client-side fallback loop
   over the remaining candidates is a later step. (Data-plane bypass — i-b/ii —
   is a later, voucher-gated step.)
3. **Response-direction sealing.** Under i-a the router terminates TLS on the
   return path too, so a sealed *request* with a plaintext *response* is
   asymmetric — the router still reads the completion. Seal the response to a
   client-supplied ephemeral key (client sends its ephemeral public key in the
   route manifest / request; broker encrypts the response to it inside the
   enclave; sidecar decrypts). Closes the return-path leak without giving up L7
   billing. Streaming: seal per-chunk (or per-SSE-frame) so tokens can stream.
4. **Harden:** measurement-tied key rotation + TTL cache; manifest↔body
   consistency check in the enclave; optional direct-to-broker (variant ii).
5. **Legacy path stays** for users who do not opt into privacy mode (router keeps
   doing plaintext L7 routing + fallback for them).

---

## Limitations

- **Metadata still leaks:** model, coarse token count, capability flags, timing,
  sizes are visible to the router / TLS terminator. ECH + padding only if the
  router is not the decryptor.
- **Trust boundary unchanged for the model:** this hides the prompt from the
  router; it does not prove the upstream model behaved. Centralized = verifiable
  *routing/relay*, not verifiable *computation*.
- **Streaming fallback:** pre-first-token only (see above).
- **Replay:** the signed proof still lacks a server-side freshness field. Replay
  of a captured proof is defeated client-side by including a per-request nonce in
  the request body (its hash is already signed, so a stale proof fails the
  content-binding check); "cached-completion, freshly-signed" is mitigated by
  attesting that the code does not cache. A server timestamp/nonce in the signed
  text is the belt-and-suspenders fix. Tracked separately from this doc.
- **Extra round trip:** the control-plane call adds latency; amortized by caching
  candidate pubkeys/quotes by measurement.

---

## Alternatives

**Live fingerprint pinning (rejected as primary).** See #552: fragile under cert
rotation and CDN multi-cert fronting; only an optional secondary check.

---

## Affected code

- `api/common/tee/tee.go` — `SyncQuote`: publish an encryption pubkey; bind it in
  `report_data`.
- `api/common/tee/phala.go` (and `gcp.go`, `alicloud/`) — key derivation
  (measurement-tied), encryption-key material.
- `api/inference/internal/ctrl/signing.go` — response-signature path unchanged;
  see #552 for domain/cert changes to the proof.
- `api/inference/internal/ctrl/sanitize.go` — unchanged; note the "signing
  attests the sanitized copy" contract for the sidecar verifier.
- Broker request handler — accept a sealed body; unseal in-enclave; validate
  manifest↔body consistency.
- Router (`api/inference/integration/router/`) — add the control-plane candidate
  endpoint; honor `pin` / `allow_fallbacks=false`; forward the sealed body
  opaquely.
- New: local sidecar and cloud gateway (OpenAI-compatible proxies over the shared
  client core) — route via the router's route-preview, then verify/seal/pin/
  verify-response with the key cache. Client-side fallback is a later step.

---

## Open questions

- Does the sidecar fetch candidate quotes from the router's candidate response,
  or independently from each broker's `/quote`? (Latency vs. trust-source
  independence.)
- One key (sign+encrypt) vs. two? Two is cleaner cryptographically (distinct
  roles) but doubles the binding/rotation surface.
- Response-direction sealing: needed, or is signature + TLS sufficient for the
  target users?
- Candidate-list freshness/caching policy and how it interacts with the router's
  live load view.