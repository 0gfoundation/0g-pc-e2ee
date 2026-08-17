# 0g-pc-e2ee/client

Client for **0G Private Computer** — end-to-end-encrypted (E2EE) inference on the
0G Compute Network. E2EE here is the broad sense, both halves of a secure channel
to an attested provider enclave: **authenticity** — verify that a response really
came from an attested TEE provider — and **confidentiality** — on the router path,
keep your prompt unreadable to everything between you and the provider enclave.

> Status: **beta** — the gateway form is deployed; interfaces will change. The design
> lives in [`docs/design`](../docs/design): `cloud-gateway.md` (the deployed form),
> `trust-chain.md`, `router-e2e.md`, `request-envelope-and-integrity.md`.

## One core, three forms

The same client core (verify attestation quote → verify response signature →
optional payload sealing → provider pin + fallback → key cache) ships in three
shapes:

| Form | What it is | Use when |
|------|-----------|----------|
| **Sidecar** | A local process exposing the OpenAI API on `localhost` | You want zero code change — just point your existing OpenAI SDK at it |
| **In-process SDK** | The core imported as a library | You want it inside your app, no extra process |
| **Cloud-TEE gateway** | The same core run as an attested server | Browser / thin / no-install clients (introduces one attested trust party) |

> **Which of the three is offered today:** the **gateway** — it is what 0G deploys
> and what [`docs/verifying-the-gateway.md`](../docs/verifying-the-gateway.md)
> teaches users to verify. The sidecar and the in-process SDK are built and tested
> here, but are not currently offered as supported entry points; the table above
> describes the architecture, not a menu.

Sealing (end-to-end confidentiality) is **required on the router path** (an L7
reseller router terminates TLS there by design) and **optional on the direct
path** (direct TLS terminates inside the provider CVM, and every response is
signed — see the design doc).

> **Scope, stated explicitly.** This client is the **E2EE layer**. On the router
> path that means both halves — sealing *and* verification. On the direct path
> with sealing off, confidentiality is already provided by the CVM-terminated
> TLS, so the client's distinctive job there is **authenticity** (attestation +
> response-signature verification). A caller who wants *neither* can talk to the
> provider directly and skip this client entirely — that is a deliberate product
> boundary (we do not wrap plain, unverified passthrough), not a missing feature.

## Layout

```
core/            # client core: quote + response-signature verification, seal, pin, fallback, key cache
route/           # gateway route mode: pick the provider per request via the router's route-preview + broker pubkey APIs
evidence/        # verify a deployed gateway's OWN attestation: /evidences bundle, served cert, code identity, OS image
openaiproxy/     # shared OpenAI-compatible HTTP handler over core (used by both server forms)
dstack/          # CVM identity: read instance_id/app_id from the dstack guest agent, and pass it between containers as a file
cmd/
  sidecar/       # local sidecar binary (OpenAI-compatible proxy on localhost) — user-operated, no new trust party
  gateway/       # cloud-TEE gateway — SAME core, but SERVER-RUN + 0G-operated, runs in an attested CVM (adds one attested trust party)
  cvmid/         # init container shipped in the gateway image: publishes the CVM's identity to its sibling containers, then exits
  mockupstream/  # load-test FIXTURE (never deployed): a protocol-exact stand-in for the router, broker and provider enclave — see ../loadtest/
sdk/
  go/            # in-process Go SDK (thin wrapper over core; shares the Go core)
  ts/            # (planned) TS / WASM build for the browser — aligns to protocol/SPEC.md, does NOT import the Go core
```

> **On the layout:** `core/` is the center of gravity — all three forms are thin
> shells over it and must not reimplement seal/verify. The two server forms
> (`cmd/sidecar`, `cmd/gateway`) share one more layer: `openaiproxy/`, the
> OpenAI-compatible HTTP handler over `core` (seal request → open response,
> buffered and streaming). The sidecar serves it as-is; the gateway adds `GET /healthz`,
> a catch-all `/` that proxies to the router for non-inference routes, and — on a
> separate internal listener the compose never publishes — `GET /metrics` plus an
> optional pprof (see `-metrics-listen` / `-pprof`). `cmd/sidecar`,
> `cmd/gateway` and `sdk/go` are Go and share `core/`; `cmd/gateway` is the one
> form that is **server-run and 0G-operated** (attested), not user-side, despite
> living here — it runs client-core logic on behalf of browser/thin clients.
> `sdk/ts` is a separate language stack that cannot share the Go core and stays
> byte-for-byte aligned only through the frozen wire spec (`protocol/SPEC.md`).

Design docs live at the repo root under [`docs/design`](../docs/design):
`cloud-gateway.md`, `trust-chain.md`, `router-e2e.md` and
`request-envelope-and-integrity.md`. The user-facing verification guide is
[`docs/verifying-the-gateway.md`](../docs/verifying-the-gateway.md).

Depends on **`github.com/0gfoundation/0g-pc-e2ee/protocol`** — the shared wire
format and verification/sealing crypto used by the broker, the router, and this
client, so all three agree byte-for-byte. (Provider scoring is not part of the
protocol; the router owns it and exposes the best provider + fallback list via
its candidate API.)

## Quickstart (sidecar)

```bash
# run the sidecar (details TBD)
0g-pc-e2ee-sidecar --listen localhost:8787
```

Point any OpenAI SDK at it:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8787/v1", api_key="<your 0G key>")
resp = client.chat.completions.create(model="gpt-4o", messages=[...])
```

The sidecar transparently verifies attestation and the per-response signature,
and (where enabled) seals the sensitive request fields (prompt, tool defs) to the
provider enclave.

Your `api_key` is forwarded verbatim as the `Authorization` header on the
request to the provider, so the router/broker can authenticate and bill it. It
travels in cleartext alongside the other routing/billing fields — it is
**not** one of the sealed (confidential) fields, since the provider needs it to
identify the caller. Send no key and the request goes upstream unauthenticated.

Any request header in the **`X-0G-*`** namespace is forwarded verbatim to the
provider — the router's cleartext routing directives (`X-0G-Provider-Address`
to pin a provider, `-Sort`, `-Trust-Mode`, `-Allow-Fallbacks`,
`-Require-Parameters`, and the `-Max-Price-Usd-{Prompt,Completion,Image}` caps,
which the router accepts as headers only). No other header is forwarded: arbitrary client headers
(cookies, app-internal metadata) must not leak to the router, which terminates
TLS on the router path.

## What it verifies

- **Attestation** — the provider quote is genuine TEE hardware (DCAP-verified;
  enforced). Whether it runs an *audited* image is checked against
  `attest.BootChainPolicy` — one entry per OS image — but that allowlist is empty today,
  so the deployed gateway runs that part in warn mode; `pcverify -provider` prints the
  observed boot chain in the shape an entry wants. See
  [`trust-chain.md`](../docs/design/trust-chain.md) hop 3.
- **Response authenticity** — each response carries a §8 TEE signature, checked
  fail-closed against the **quote-bound** signer. Opt-in in the library
  (`-verify-responses`, off by default); the deployed gateway turns it on, so a response
  whose signature does not verify is not returned. Whether that signer is the one
  *registered on chain* is a separate hop, and it currently only warns — see
  [`trust-chain.md`](../docs/design/trust-chain.md) hops 5 and 11.
- **Routing / confidentiality** — on the router path, the sensitive request
  fields (prompt, tool defs) are sealed to the provider enclave; the router reads
  only the cleartext fields — routing params (model, sampling) and billing
  (`usage`, on the response) — not your prompt.

See [`docs/design/router-e2e.md`](../docs/design/router-e2e.md) for the full trust
model, the control-plane / data-plane split, and the encryption-key lifecycle.

## Checking the trust chain yourself

**If you are a user of a 0G-hosted gateway and want to verify it, start here:**
[**docs/verifying-the-gateway.md**](../docs/verifying-the-gateway.md) — what each check
proves, what you have to trust and what you do not, and the by-hand procedure for
auditors who would rather not run our binary.

`cmd/pcverify` is a read-only diagnostic with one mode per attested party:

```sh
pcverify -provider 0x…            # a provider: DCAP quote + on-chain signer (trust-chain hops 2–5)
pcverify -gateway <domain>        # the cloud-TEE gateway: its /evidences bundle + served certificate
```

The gateway mode matters for the third form above, which adds one attested trust
party: it verifies the dstack-ingress cert-binding quote, confirms the certificate
the domain **actually serves** is the one that quote committed to, and — given the
CVM's `app-compose.json` — establishes which configuration booted and whether its
compose text is the manifest you published (`evidence/`):

```sh
pcverify -gateway <domain>   # the whole chain, incl. which release is live
```

`compose_hash` comes from the verified quote's `mr_config_id`; the platform base
domain is derived from the served domain's CNAME chain and the `app_id` from the
quote, so the app-compose is located without anything being typed in — and its bytes
can come from anywhere (`-app-compose <file>`), because the hash anchors them. The
compose text is then matched against the newest 5 published releases by default
(`-releases N`, `0` to disable); `-expect-compose-file` pins one manifest instead.

Both modes exit non-zero on a failed check, so either works as a deploy gate, and both
separate "failed" (1) from "did not run" (3) so a skipped check cannot read as a full
pass. `-strict` makes every check mandatory and turns the latter into the former. Note
that **provider mode returns 3 on every run today**: hop 3's audited allowlist is empty,
so the boot chain is never compared — the code root is not doing its job yet, and the
exit code says so rather than rounding up to 0. See
[`docs/design/cloud-gateway.md`](../docs/design/cloud-gateway.md) §10 for what the
result does and does not cover.

`-allow-untrusted-cert` (gateway mode) is for a hostname on the ACME staging CA. Every
check runs either way — the evidence fetch does not verify PKI, since it rides the same
connection whose certificate is being compared — so what the flag decides is whether the
reported chain-trust failure blocks the verdict. It relaxes no attestation check, but
chain trust is what ties the connection to the domain you named: waive it and an
interceptor running its own attested CVM passes everything else. Smoke-test your own
deployment with it; never audit someone else's.

`-pccs-url` applies to whichever mode verifies a quote, pointing DCAP collateral
fetches at a PCCS mirror (e.g. `https://pccs.phala.network`) instead of Intel PCS.
It defaults to Intel PCS — the authority — rather than to a mirror, since a mirror
can serve older-but-still-valid CRL / TCB Info. Pass it when Intel PCS rate-limits
a repeated or CI run, or to match the deployment's own collateral source.

## Related repositories & products

This repo (**`0g-pc-e2ee`**) holds two Go modules:

| Module (this repo) | Role |
|------|------|
| `protocol` | shared wire format + verification/sealing crypto — the E2EE contract |
| `client` (this) | client core + its forms: sidecar, in-process SDK, and the 0G-operated gateway |

External:

| Repo/Product | Role |
|------|------|
| `0g-serving-broker` | provider-side broker (server) |
| `Private Computer` | L7 aggregating router (product: Private Computer) |