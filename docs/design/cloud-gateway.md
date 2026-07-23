# Cloud-TEE gateway — zero-client-code E2EE with separated validation

> Status: design / discussion. Sibling of [`router-e2e.md`](./router-e2e.md).
> Some cloud specifics (GCP confidential-compute APIs, dstack feature details)
> are marked **[verify]** — confirm against current docs before building.

## 1. Goal

Let a client with **zero of our code** — a plain browser `fetch`, an unmodified
OpenAI SDK pointed at a `base_url` — get **end-to-end confidential** chat
inference, while keeping **verifiability available as a separate, opt-in step**.

Concretely, the target is to **separate two planes**:

- **Inference (data plane)** — 0 client code, confidentiality delivered by the
  transport.
- **Validation (control plane)** — an *extra step* (a tool, a monitor, an
  audit), decoupled from any individual inference request.

This split is not a compromise; it is the **only** way to have both "0 client
code" and "verifiable". Per-request client verification requires client-side
attestation + sealing — i.e. client code (the sidecar or a WASM SDK). If the
client runs no code, verification cannot happen *on the request path* and must
move out of band.

## 2. The fundamental constraint

A plain browser can only do **WebPKI** (validate a CA-issued cert + hostname).
It cannot parse a TDX quote, verify a measurement, or HPKE-seal. Therefore:

| Want | Requires |
|------|----------|
| Per-request, client-verified E2EE | client code (sidecar / WASM SDK) — **not** "0 code" |
| 0 client code + confidentiality | TLS terminated **inside** the enclave |
| 0 client code + *verifiability* | confidentiality (above) **+** out-of-band validation |

So "0 client code" fixes the shape of the whole design: confidentiality is a
**transport** property (TLS into the TEE), and verifiability is a **separate**
property (validate the endpoint out of band).

## 3. Architecture: two planes

```
                          ┌─────────────────── attested CVM (TEE) ───────────────────┐
 plain browser / OpenAI   │  TLS terminates HERE (key never leaves the TEE)           │
 SDK  ──── HTTPS ─────────┼─▶ gateway = client-core + server shell                    │
 (0 client code)          │     • unseal N/A: receives plaintext inside the enclave   │
                          │     • seal request to the pinned provider enclave (§ wire)│──▶ router ──▶ provider TEE
                          │     • open the sealed response; stream plaintext back     │◀── (sealed) ─┘
                          └───────────────────────────────────────────────────────────┘
        ▲
        │  (separate, out-of-band)
   validation step  ──▶  quote API + cert-binding + transparency log  ──▶  "endpoint == attested measurement X"
```

- **Data plane**: browser → TLS (terminated in the enclave) → gateway does the
  E2EE hop to the provider (reusing the sidecar's client core) → plaintext
  streamed back over the same TLS. Nothing on the client but standard HTTPS.
- **Control plane**: anyone who cares verifies, out of band, that the endpoint
  is a genuine enclave running the expected code.

## 4. Where this sits in the trust hierarchy

| Tier | Client | Transport | Who *cannot* see the prompt | Client can *verify* the enclave? |
|------|--------|-----------|-----------------------------|----------------------------------|
| 1 | plain browser | TLS terminates at the **LB** | — (LB sees plaintext) | ❌ no privacy — a plaintext proxy |
| **2.5 (this design)** | **plain browser** | TLS terminates **in the enclave** | LB / cloud infra / operator's other systems | **❌ not per-request** — cheating is *publicly detectable* out of band |
| 3 | WASM/SDK | app-layer seal to the enclave | everyone but the enclave | ✅ per-request |

This design delivers **tier 2.5: confidential by default, cheating publicly
detectable** — analogous to Certificate Transparency / key transparency. It is
**weaker than tier 3 in exactly one way: detection, not prevention**, and it
relies on *someone* actually running the validation. A user who never runs the
extra step trusts by default. Market it as *verifiable / auditable*, never as
"your browser verified this request".

## 5. Data plane (inference) — details

### 5.1 The gateway *is* the sidecar, in a TEE — not a new server

In the 0-client-code model the browser sends **plaintext over TLS** and gets
plaintext back, so the gateway's client-facing side is **identical to the
sidecar's** (plaintext OpenAI in/out), and the only sealed hop is
gateway→provider — which is `client/core` verbatim. The gateway therefore needs
**no new server wrapper and no browser-facing sealing**; it reuses the sidecar's
HTTP handler.

**Structure.** Extract the sidecar's OpenAI-compatible HTTP handler (today in
`cmd/sidecar`'s `package main`) into a shared, importable package (e.g.
`client/openaiproxy`); `cmd/sidecar` and `cmd/gateway` both mount it. The gateway
adds only what the sidecar lacks:

- **attestation** — derive the enclave enc/signing keys and expose the quote API
  (§6);
- **multi-tenant concerns** — auth, per-user billing attribution, rate limiting,
  abuse handling, and logging that never records plaintext (the sidecar is
  single-user and needs none of these);
- **dstack packaging** — TLS-in-enclave + fleet, mostly runtime not app code (§7).

> Browser-facing **sealing** (the gateway unsealing a request the browser
> app-layer-sealed to it) is a **tier-3-only** concern — a browser running our
> WASM SDK. The 0-client-code path here has none: the browser is plaintext over
> TLS, so that "double seal" does not apply.

### 5.2 What sees plaintext

The gateway enclave **necessarily sees the prompt in plaintext** — it must, to
seal it to the provider. So "E2EE" here means:

```
user  ──TLS──▶  [gateway TEE]  ──HPKE seal──▶  [provider TEE]
```

plaintext exists **only inside the two enclaves**. This is **one more attested
party than sealing directly to the provider** (two TEEs vs one). That extra
exposure is the price of moving the client core into the cloud; it is acceptable
because the gateway is *attested* (a verifiably-trusted party, not a blind one).
If a client *can* run crypto and reach providers directly, direct-seal is
strictly less exposure — see §8.

### 5.3 TLS must terminate in the enclave

If TLS terminates at a load balancer (the default for managed HTTPS LBs), the LB
sees plaintext and the TEE buys nothing — the leak already happened upstream.
So the TLS session **must terminate inside the enclave**, with the private key
**generated in and never leaving** the TEE. This needs an **L4 / passthrough**
load balancer (encrypted TCP forwarded to the enclave), not an L7 HTTPS LB.
dstack provides this as a managed feature — see §7.

### 5.4 Response direction

Only the gateway→provider hop is sealed. The provider seals the response to a
gateway-held key; the gateway opens it (SPEC §7, reusing `client/core`) and
streams **plaintext** back to the browser over the in-enclave TLS. In the
0-client-code model the gateway does **not** re-seal to the browser (there is no
browser-side key) — re-sealing to the client is the tier-3 (WASM SDK) path only.

## 6. Validation plane — details

The validation step answers one question: **"is the endpoint I (or an auditor)
am talking to a genuine enclave running measurement X, and is its TLS cert
controlled only by that enclave?"**

### 6.1 Mechanism

1. **Quote API** (like the broker's): the gateway exposes its attestation quote
   / RA report. Reuses the §4 (`protocol/attest`, issue #7) verification path.
2. **Bind the TLS cert key into the quote**: put a hash of the enclave's TLS
   certificate public key in the quote's `report_data`, so the quote proves
   "measurement X controls *this* cert".
3. **Publish `measurement X ↔ cert fingerprint`** in a transparency log / on
   chain, and rely on **Certificate Transparency** for the cert itself.
4. **Continuous monitoring** (ideally run by 0G and/or a third party), so the
   guarantee is not left solely to end users.
5. **Per-request response signature** (like the broker's, SPEC §8): the gateway
   signs each response with its enclave key. A plain browser **cannot verify it
   live** — verifying a signature is crypto, i.e. client code — but the signature
   makes each response **individually auditable out of band** (verify later, by a
   tool / extension / monitor) and is **forward-compatible**: a client that later
   runs a little code verifies the *same* signature live (tier 3). It only
   *complements* — does not replace — the one-time attestation that vouches for
   the signing key (broker model = attest the key once + sign every response).

### 6.2 What it proves / does not prove

- **Proves**: a genuine enclave with measurement X exists and controls the cert;
  swapping in a different endpoint requires either a different cert (**visible in
  CT**) or extracting the enclave key (**attestation says impossible**) — so
  cheating is **publicly detectable**.
- **Does not prove**: that *this specific browser request* went to that enclave.
  A plain browser only checks WebPKI, so the binding between "what the auditor
  validated" and "what the user connected to" is **detected, not enforced**.
- **On per-request signatures**: a *gateway* signature attests "the attested
  gateway enclave handled this response", not "the inference is genuine" — the
  gateway relays, it does not run the model. For inference authenticity, carry
  the *broker's* signature (SPEC §8) through to the client. Verifying either is
  client code, so for a 0-code browser both are out-of-band / after-the-fact
  artifacts, not live checks.

Closing the "which endpoint did my request hit" gap is exactly what tier 3
(client code) does; by choosing "0 client code" we accept detection instead of
prevention.

## 7. Deployment: use dstack, not hand-rolled confidential TLS

The hard parts of §5.3/§6 — terminating TLS in a TEE, proving the cert is
TEE-controlled, keeping the key in the enclave, doing this across a scaled fleet
— are exactly what **dstack** (the runtime the broker already uses) provides as
managed features:

- **ZT-HTTPS / Zero-Trust TLS**: dstack-gateway terminates TLS inside a TEE,
  auto-provisions ACME certs, and cryptographically proves the cert is
  controlled only by the verified TEE app; the private key never leaves the TEE
  (keys derived via dstack-kms). **[verify]**
- **Fleet + LB**: dstack load-balances across replicas by app id, with TLS
  passthrough available — so the "which instance holds the key" routing problem
  is handled by the runtime rather than by us. **[verify]**
- **Runs on Phala Cloud, and on GCP / AWS**: dstack is one framework across
  clouds, so scaling on GCP does **not** require hand-building confidential TLS
  — run **dstack on GCP** to get GCP's scale *and* dstack's confidential
  plumbing. **[verify]**

### 7.1 Consequence: one attestation format

The broker already runs on Phala CVM (dstack, Intel TDX). Running the gateway on
dstack too means **the gateway and the broker emit the same TDX quote format**,
so the client's `attest` verification (issue #7) supports **one** flavor. Hand
-rolling on raw GCP would have added a second (Google attestation-token) flavor
— avoided by using dstack.

### 7.2 GCP vs Phala, honestly

Choosing GCP for *scale* is reasonable, but the confidential-TLS / attestation
work is the part GCP makes **more** DIY (managed HTTPS LBs terminate TLS at the
edge — the wrong place). The resolution is not "GCP vs Phala" but **dstack as
the framework** (on Phala Cloud to start; on GCP when scale demands), which
gives scale without the DIY confidential-TLS burden and keeps the single
attestation format.

## 8. When NOT to host the gateway

The gateway adds convenience/reachability (0-code clients, centralized routing/
fallback) but **adds one attested party that sees plaintext** and delivers only
tier 2.5. So:

- **Client can run our crypto (sidecar or WASM SDK)** → prefer **direct-seal to
  the provider** (tier 3, one fewer plaintext-seeing party). The gateway's only
  remaining value is centralizing routing or reachability (e.g. browsers that
  cannot reach provider endpoints directly due to CORS / network).
- **Client is a plain browser and tier 2.5 is acceptable** → the gateway is
  worth it, and this design (dstack ZT-HTTPS + out-of-band validation) is how.

Do not host the gateway expecting it to *increase* privacy over direct-seal; it
does not.

## 9. Relationship to existing components

- Reuses **`client/core`** (`Complete` / `CompleteStream`) unchanged for the
  gateway→provider hop.
- Reuses **`protocol/wire`** for sealing to the provider and opening the sealed
  response.
- Depends on **`protocol/attest`** (issue #7) for the quote the gateway exposes
  and (for tier-3 clients) for verifying it.
- The **router** must accept the sealed request (0g-router#618) regardless of
  which client form produced it; the gateway is just another such client.

## 10. Phasing

1. **Gateway = the shared sidecar handler (`openaiproxy`) in a dstack CVM** with
   ZT-HTTPS (TLS in the TEE). 0-code inference works; validation not yet
   published. (Tier "2, un-auditable" — internal / testing only.)
2. **Quote API + cert-key binding in `report_data` + per-request response
   signature.** An operator/CLI can now validate out of band, and each response
   is individually auditable. (Tier 2.5.)
3. **Publish `measurement ↔ cert` (transparency log / on-chain) + monitoring**,
   so cheating is publicly detectable without per-user effort.
4. **Optional tier-3 path**: a WASM verify+seal SDK for clients that want
   per-request verification (reuses `attest` + `wire`); these may also bypass the
   gateway and seal directly to the provider.

## 11. Limitations & caveats

- **Tier 2.5, not tier 3**: detection, not prevention; relies on someone running
  validation; default-trust for users who skip it. State this in product copy.
- **Two enclaves see plaintext** (gateway + provider), vs one for direct-seal.
- **Metadata** (model, sizes, timing) is visible as in the router path.
- Cloud/runtime specifics marked **[verify]** must be confirmed against current
  GCP / dstack documentation before implementation.

## 12. Open questions

- Per-instance keys vs a shared fleet key (via attestation-gated KMS): dstack's
  model likely dictates this — confirm how dstack-kms scopes derived keys across
  replicas. **[verify]**
- Where to publish `measurement ↔ cert` — reuse the on-chain registry the broker
  uses, or a dedicated transparency log?
- ~~Does the gateway pin one provider per request (like the sidecar) or offer
  provider selection to the 0-code client via a request field/header?~~
  **Resolved:** the gateway always routes (`client/route`). Per request it asks
  the router's route-preview API (`POST /v1/routing/preview`) which provider to
  use, then fetches that provider's enc key **and** signer address from the
  broker (`GET /v1/e2ee/pubkey`) — so nothing about the provider (endpoint, enc
  key, signer) is configured up front. The sealed fields are withheld from the
  preview call, so the prompt stays confidential. The sealed request itself is
  still POSTed to the **router** (`/v1/chat/completions`, the centralized
  auth/billing point), pinned to the chosen provider (`X-0G-Provider-Address`,
  fallback off) so the router forwards to exactly the provider whose key it was
  sealed to; the provider `endpoint` from preview is used only to fetch the enc
  key. A caller selects a specific provider by setting `X-0G-Provider-Address`,
  which the gateway forwards to preview so it returns that provider (this
  replaces a separate "pin/direct" mode). Client-side fallback over the
  remaining candidates, verifying the enc key out of an attestation quote, and
  resolving the provider **endpoint on chain** rather than trusting the router's
  reply are later steps (the last tracked in issue #18).
- Streaming through the in-enclave TLS + L4 LB — confirm no buffering is
  introduced on the dstack path (the sidecar already sets `X-Accel-Buffering:
  no`; the router's nginx sets `proxy_buffering off`).
