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
   validation step  ──▶  cert-binding quote (dstack-ingress) + transparency log  ──▶  "endpoint == attested measurement X"
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

- **attestation** — the CVM's cert-binding quote, supplied by dstack-ingress
  (§6/§7), not a gateway-issued quote API; the gateway adds no attestation
  surface of its own;
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

> **Deployment decision (resolved).** The cert binding that point 2 asks for is
> **supplied by dstack-ingress's `/evidences`, not by a self-issued gateway
> quote.** The gateway runs in one dstack app (one CVM) behind dstack-ingress
> (see `deploy/phala/docker-compose.yml`), whose `/evidences` quote has
> `report_data = SHA-256(sha256sum.txt)` covering the served certificate, and a
> `mr_config_id` committing to `compose_hash = SHA-256(the whole app-compose)`
> (`app_id` is its leading 20 bytes). That register is part of the signed TD
> report, so it needs no event-log replay — see
> `attest.ComposeHashFromMRConfigID`. Because the compose hash covers the whole
> app-compose, it attests **every** container in the CVM at once — ingress and
> gateway on the request path, plus the `cvm-identity` init container and the
> `prometheus-agent` sidecar.
>
> What that quote proves is "a CVM running exactly this app-compose obtained this
> certificate inside the TEE". Getting from there to "the endpoint I am talking to
> is that CVM" needs one step the quote cannot carry: the verifier's own handshake
> with the domain, compared against `cert-<DOMAIN>.pem` in the bundle (the CAA
> record dstack-ingress pins to its own ACME account is what stops a third party
> obtaining a different cert for the name). So this closes point 2 and moves point
> 1 rather than deleting it: the artifact exists, but it is **not** consumable by
> §4's `protocol/attest` path as written. That parser expects
> `enc_pub‖signer_addr‖version` in `report_data` and fails closed on anything
> else, so verifying `/evidences` needs a second verifier. That verifier now
> exists: `attest.EvidenceReportData` / `VerifyEvidenceReportData` for the
> cert-binding layout, and `client/evidence` for the bundle, the handshake and the
> certificate comparison — driven by `pcverify -gateway` (§10 step 2).
>
> The gateway therefore needs no quote of its own and exposes **no `/quote`
> route**. The only thing that could have required a distinct gateway quote — a
> value the cert quote cannot carry — was a gateway-issued per-response signature
> binding its own signing key; we have **decided not to add gateway response
> signing** (see §6.2), so no gateway quote is needed at all. Inference
> authenticity rides the provider's own SPEC §8 signature instead.

1. **Cert-binding quote**: a TDX quote from inside the CVM that commits to the
   served cert and to `app_id`. Emitted by **dstack-ingress** (`/evidences`, see
   the decision box above), not by a gateway-issued quote API.
2. **Bind the TLS cert into that quote**: dstack-ingress puts
   `SHA-256(sha256sum.txt)` (which covers the served cert) in the quote's
   `report_data`, so the quote proves "measurement X controls *this* cert".
3. **Publish `measurement X ↔ cert fingerprint`** in a transparency log / on
   chain, and rely on **Certificate Transparency** for the cert itself.
4. **Continuous monitoring** (ideally run by 0G and/or a third party), so the
   guarantee is not left solely to end users.

### 6.2 What it proves / does not prove

- **Proves**: a genuine enclave with measurement X exists and controls the cert;
  swapping in a different endpoint requires either a different cert (**visible in
  CT**) or extracting the enclave key (**attestation says impossible**) — so
  cheating is **publicly detectable**.
- **Does not prove**: that *this specific browser request* went to that enclave.
  A plain browser only checks WebPKI, so the binding between "what the auditor
  validated" and "what the user connected to" is **detected, not enforced**.
- **On response signatures**: the gateway signs **no** response of its own. A
  gateway signature would only attest "the attested gateway enclave handled this
  response", not "the inference is genuine" — the gateway relays, it does not run
  the model — and endpoint identity is already covered by the cert binding, so it
  would add only a transferable, after-the-fact proof (a tier-3 nicety) at the
  cost of a second enclave key to attest. We skip it. Inference authenticity comes
  from the **provider's** own SPEC §8 signature, which the gateway verifies
  (`ZG_GATEWAY_VERIFY_RESPONSES`) and can carry through to the client; verifying
  that is client code, an out-of-band / after-the-fact check for a 0-code browser,
  not a live one.

Closing the "which endpoint did my request hit" gap is exactly what tier 3
(client code) does; by choosing "0 client code" we accept detection instead of
prevention.

## 7. Deployment: use dstack, not hand-rolled confidential TLS

The hard parts of §5.3/§6 — terminating TLS in a TEE, proving the cert is
TEE-controlled, keeping the key in the enclave, doing this across a scaled fleet
— are exactly what **dstack** (the runtime the broker already uses) provides as
managed features:

- **ZT-HTTPS / Zero-Trust TLS**: dstack-gateway terminates TLS inside a TEE and
  auto-provisions ACME certs, on the platform hostname
  `<app-id>-<port>.<base_domain>`. **Verified, with a caveat that decided the
  deployment:** the cert it serves is a *shared cluster wildcard*
  (`CN=*.<base_domain>`), so it proves the **gateway app** controls it — nothing
  about *our* app. The only link from the TLS session to our measured code is that
  the hostname carries our `app_id` and the gateway routes by it, i.e. trust in
  the platform's routing rather than a cryptographic binding.
- **What we deploy instead**: dstack-ingress inside our own CVM, on our own
  domain, with dstack-gateway doing **L4 passthrough** (the `…-<port>s` form, and
  the default for any SNI the gateway holds no cert for). TLS then terminates in
  *our* enclave and the cert is bound to *our* `app_id` (§6.1). One platform-side
  prerequisite: the host front end forwards only SNI suffixes Phala has
  allowlisted. See `deploy/phala/README.md`.
- **Fleet + LB**: dstack selects among replicas by app id, with TLS passthrough
  available — so the "which instance holds the key" routing problem is handled by
  the runtime rather than by us. **Verified in the gateway source, with a caveat
  that matters for capacity planning:** the custom-domain (passthrough) path uses
  the *same* selection as the platform hostname, but that selection is neither
  round-robin nor load-aware — it takes the few instances with the freshest
  WireGuard handshake, caches that candidate set for ~30s, races a TCP connect
  against them and keeps the first to answer, **per TCP connection** (so a
  keep-alive client stays pinned to one replica). Treat replicas as HA and
  headroom, not as an even split. See `deploy/phala/blue-green.md` "Scaling one
  side".
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
  worth it, and this design (in-CVM TLS via dstack-ingress on our own domain, §7,
  + out-of-band validation) is how.

Do not host the gateway expecting it to *increase* privacy over direct-seal; it
does not.

## 9. Relationship to existing components

- Reuses **`client/core`** (`Complete` / `CompleteStream`) unchanged for the
  gateway→provider hop.
- Reuses **`protocol/wire`** for sealing to the provider and opening the sealed
  response.
- Depends on **`protocol/attest`** (issue #7) for quote verification on the
  gateway→provider hop. The gateway's *own* cert-binding quote comes from
  dstack-ingress's `/evidences` (§6.1); its `report_data` layout is a second,
  separate entry point in `attest` (`VerifyEvidenceReportData`) precisely because
  the §4.2 parser must keep failing closed on it.
- The **router** must accept the sealed request (0g-router#618) regardless of
  which client form produced it; the gateway is just another such client.

## 10. Phasing

1. **Gateway = the shared sidecar handler (`openaiproxy`) in a dstack CVM**, TLS
   terminated in that CVM by dstack-ingress on our own domain (§7,
   `deploy/phala/`). 0-code inference works, and the cert-binding quote is already
   published at `/evidences/`. (Tier "2, un-auditable" until step 2 — internal /
   testing only.)
2. **A verifier for that cert-binding quote.** The cert binding itself is done
   (§6.1); what was missing is code that checks it. **Endpoint identity is now
   done** — `pcverify -gateway <domain>` (`client/evidence`, `client/cmd/pcverify`)
   verifies the bundle against its own `sha256sum.txt`, DCAP-verifies
   `/evidences/quote.json`, recomputes the `report_data` binding
   (`attest.VerifyEvidenceReportData`), and compares the **served** certificate
   against the bundle's, so an operator or auditor validates out of band with one
   command that exits non-zero on failure. Inference authenticity is the provider's
   SPEC §8 signature, verified independently on the gateway→provider hop; the
   gateway issues no signature of its own.

   **Code identity is also done**, via a shorter route than this doc first
   assumed. The verified quote's **`mr_config_id`** carries the dstack
   `compose_hash` directly — `0x01 ‖ SHA-256(app-compose.json) ‖ padding`
   (`dstack-types/src/mr_config.rs`, `MrConfig::V1`) — and that register is inside
   the signed TD report, so **no event-log replay is needed**: whatever verified
   the quote already authenticated it. `attest.ComposeHashFromMRConfigID` reads it
   (failing closed on the V2/V3 layouts, which commit to the hash inside a digest
   rather than carrying it), and `attest.AppIDFromComposeHash` derives the `app_id`
   the platform labels by. The `compose-hash` runtime event in RTMR3 carries the
   same value and is kept only as a cross-check in the KAT.

   From there `pcverify -gateway` closes the chain with no extra arguments: it
   derives the platform base domain from the served domain's CNAME chain
   (`evidence.DeriveBaseDomain` — dstack points a served name at `_.<base_domain>`),
   fetches the app-compose from the guest agent of the `app_id` **the quote itself
   names**, and checks `sha256 == compose_hash` (`evidence.VerifyAppCompose`) before
   believing anything in it. `-app-compose` supplies those bytes from a file
   instead — a deploy record, a release asset, a copy-paste — because the compose
   hash anchors them; no Phala Cloud API access is required.

   Naming what *should* be running defaults to the newest 5 published releases
   (`-releases`), so the report says which release is live and flags "none of them";
   `-expect-compose-file` overrides that with a single pinned manifest. Neither DNS
   nor GitHub is trusted to decide anything: DNS only *locates* the app-compose (a
   wrong or hijacked answer yields a failed lookup or a failed binding, never a false
   pass), and a release asset is only ever compared against text the quote already
   authenticated. Both lookups are advisory when they happen by default and fatal when
   explicitly requested, so a network problem is never reported as a verification
   failure — nor silently as a pass.

   **Code identity's remaining dependency — the OS image — is now pinned.**
   `mr_config_id` is host-chosen, so the compose hash is truthful only because the
   guest OS refuses to boot when it disagrees with the app-compose delivered; the
   verifier therefore also compares the quote's image registers — `MRTD` + `RTMR1` +
   `RTMR2`, via `attest.BootChainPolicy`, excluding `RTMR3` (`compose_hash` pins the app
   more precisely) and `RTMR0` (the VM shape, which this check does not need to
   establish) — against an allowlist embedded in the binary
   (`client/evidence/osimages.json`). **That allowlist is now populated** for the image
   the deployment runs, derived from the published guest-OS release and confirmed
   against a live quote, so the step checks rather than reports. An image that is not
   listed is a failure, so a new OS image version needs an entry before it is deployed
   — per version, not per deployment. Hop 3's broker allowlist in `trust-chain.md` is a
   separate, still-open task.
3. **Publish `measurement ↔ cert` (transparency log / on-chain) + monitoring**,
   so cheating is publicly detectable without per-user effort.
4. **Optional tier-3 path**: a WASM verify+seal SDK for clients that want
   per-request verification (reuses `attest` + `wire`); these may also bypass the
   gateway and seal directly to the provider.

## 11. Limitations & caveats

- **Tier 2.5, not tier 3**: detection, not prevention; relies on someone running
  validation (`pcverify -gateway`); default-trust for users who skip it. The
  user-facing statement of exactly this — what a pass proves, what remains trusted,
  and the current limits — is [`../verifying-the-gateway.md`](../verifying-the-gateway.md);
  keep product copy consistent with it rather than restating it.
- **The gateway CVM's OS measurement is pinned, with two stated caveats.**
  `mr_config_id` is
  host-supplied, and what makes it truthful is the guest refusing to boot when it
  disagrees with the real `app-compose.json`
  (dstack `config_id_verifier.rs`) — a check whose integrity rests on `MRTD` / `RTMR1` /
  `RTMR2` being the audited dstack OS. Those three measure the firmware, kernel and
  rootfs, i.e. every piece of code performing that check; `RTMR0` is excluded because it
  records the VM shape, which the check does not depend on, and pinning it would have
  cost an entry per (image, shape) pair rather than per image. The allowlist
  (`attest.BootChainPolicy`, `client/evidence/osimages.json`) carries the deployed
  image, computed with `dstack-mr` from the published guest-OS release matched to the
  CVM's `os_image_hash` and confirmed against a live quote — so a modified OS image that
  skipped the boot check no longer passes. The two caveats: the values come from the
  published release rather than a source rebuild, so that tarball is in the trust path
  until `reproduce.sh` runs in CI; and `MRTD` also depends on the host's page-add mode
  (`two_pass_add_pages`), recorded per entry. Both are properties of the derivation, not
  of what a match proves about the image.
- **Two enclaves see plaintext** (gateway + provider), vs one for direct-seal.
- **Metadata** (model, sizes, timing) is visible as in the router path.
- **The browser origin allowlist is not authentication.** Serving no-install
  browser clients requires CORS, so the gateway ships an allowlist (default: the 0G
  first-party app origins — a subset of what the router accepts — overridable per
  deployment via `ZG_GATEWAY_ALLOWED_ORIGINS`). It constrains which *web pages* a browser will let
  talk to the gateway; it constrains nothing else, because only browsers enforce it
  — any non-browser caller simply omits or forges `Origin`. Authorization remains
  the front-door credential gate plus the router's authoritative validation.
- **A second container in the CVM opens the dstack guest-agent socket** —
  `cvm-identity`, an init container that reads this CVM's `instance_id` / `app_id`
  once at boot, writes them to a shared volume, and exits
  (`deploy/phala/docker-compose.yml`, `client/cmd/cvmid`). That socket is a
  privileged surface: the same agent derives keys and issues quotes. **dstack-ingress
  already mounts it** — it must, for the cert binding §6.1 rests on — and it is
  long-lived, so the socket is not and never was exclusive to one container. The
  narrower claim this design does support: the socket is kept off the **gateway**,
  the long-lived container that sees user prompts (it reads a plain JSON file
  instead), and adding `cvm-identity` introduces no new long-lived holder. Every
  mount is part of the measured compose, so a verifier sees exactly which
  containers hold it and for how long.
  It buys the one thing a replica cannot otherwise have: a name. Without it,
  replicas of one `app_id` produce unattributable interleaved logs and colliding
  Prometheus series (identical external and target labels), which makes running
  more than one CVM per side impractical.
  It does **not** change §6: the gateway still publishes no quote of its own and
  still exposes no `/quote` route, and endpoint identity still rests on
  dstack-ingress's cert-binding attestation. Note the identifiers are **not merely
  self-reported** — `dstack-util` extends both `app-id` and `instance-id` into
  RTMR3 at boot, so a verifier replaying the event log against a quote can confirm
  them. We do not verify them here (they feed operational labels, not decisions),
  but the attested path exists should they ever need to be evidence.
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
