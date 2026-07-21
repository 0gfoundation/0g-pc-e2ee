# 0g-pc-client

Client for **0G Private Computer** — verifiable and (optionally) confidential
inference on the 0G Compute Network. It lets you verify that a response really
came from an attested TEE provider, and — on the router path — keep your prompt
unreadable to everything between you and the provider enclave.

> Status: early / design-stage. The design lives in [`docs/design`](../docs/design)
> (see `router-e2e.md`). Interfaces will change.

## One core, three forms

The same client core (verify attestation quote → verify response signature →
optional payload sealing → provider pin + fallback → key cache) ships in three
shapes:

| Form | What it is | Use when |
|------|-----------|----------|
| **Sidecar** | A local process exposing the OpenAI API on `localhost` | You want zero code change — just point your existing OpenAI SDK at it |
| **In-process SDK** | The core imported as a library | You want it inside your app, no extra process |
| **Cloud-TEE gateway** | The same core run as an attested server | Browser / thin / no-install clients (introduces one attested trust party) |

Sealing (end-to-end confidentiality) is **required on the router path** (an L7
reseller router terminates TLS there by design) and **optional on the direct
path** (direct TLS terminates inside the provider CVM, and every response is
signed — see the design doc).

## Layout

```
core/            # client core: quote + response-signature verification, seal, pin, fallback, key cache
openaiproxy/     # shared OpenAI-compatible HTTP handler over core (used by both server forms)
cmd/
  sidecar/       # local sidecar binary (OpenAI-compatible proxy on localhost) — user-operated, no new trust party
  gateway/       # cloud-TEE gateway — SAME core, but SERVER-RUN + 0G-operated, runs in an attested CVM (adds one attested trust party)
sdk/
  go/            # in-process Go SDK (thin wrapper over core; shares the Go core)
  ts/            # (planned) TS / WASM build for the browser — aligns to protocol/SPEC.md, does NOT import the Go core
```

> **On the layout:** `core/` is the center of gravity — all three forms are thin
> shells over it and must not reimplement seal/verify. The two server forms
> (`cmd/sidecar`, `cmd/gateway`) share one more layer: `openaiproxy/`, the
> OpenAI-compatible HTTP handler over `core` (seal request → open response,
> buffered and streaming). The sidecar serves it as-is; the gateway serves it
> plus its own operational routes (`/healthz`, `/quote`). `cmd/sidecar`,
> `cmd/gateway` and `sdk/go` are Go and share `core/`; `cmd/gateway` is the one
> form that is **server-run and 0G-operated** (attested), not user-side, despite
> living here — it runs client-core logic on behalf of browser/thin clients.
> `sdk/ts` is a separate language stack that cannot share the Go core and stays
> byte-for-byte aligned only through the frozen wire spec (`protocol/SPEC.md`).

Design docs live at the repo root under
[`docs/design`](../docs/design) (currently `router-e2e.md`).

Depends on **`github.com/0gfoundation/0g-pc/protocol`** — the shared wire
format, verification/sealing crypto, and route-scoring logic used by the broker,
the router, and this client, so all three agree byte-for-byte.

## Quickstart (sidecar)

```bash
# run the sidecar (details TBD)
0g-pc-sidecar --listen localhost:8787
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
`-Require-Parameters`). No other header is forwarded: arbitrary client headers
(cookies, app-internal metadata) must not leak to the router, which terminates
TLS on the router path.

## What it verifies

- **Attestation** — the provider quote is genuine TEE hardware running the
  expected measurement (anchored on-chain / against a published baseline).
- **Response authenticity** — each response is signed by the TEE key and the
  signer matches the on-chain `teeSignerAddress`.
- **Routing / confidentiality** — on the router path, the sensitive request
  fields (prompt, tool defs) are sealed to the provider enclave; the router reads
  only the cleartext fields — routing params (model, sampling) and billing
  (`usage`, on the response) — not your prompt.

See [`docs/design/router-e2e.md`](../docs/design/router-e2e.md) for the full trust
model, the control-plane / data-plane split, and the encryption-key lifecycle.

## Related repositories & products

| Repo/Product | Role |
|------|------|
| `0g-pc-client` (this) | user-side sidecar / SDK / gateway |
| `0g-pc/protocol` | shared wire format + crypto + route logic |
| `0g-serving-broker` | provider-side broker (server) |
| `Private Computer` | L7 aggregating router (product: Private Computer) |