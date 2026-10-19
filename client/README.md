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
> the public attestation bundle at `/evidences/`, its own self-description at
> `GET /v1/gateway/identity` (display material, not evidence — see `identity.go`),
> what it verified about each provider it sealed to at
> `GET /v1/providers/{address}/identity` (relayed verdicts, not evidence — see
> `provideridentity.go`),
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
and `X-0G-Provider-Identity` to pin a provider, `-Sort`, `-Trust-Mode`,
`-Allow-Fallbacks`, `-Require-Parameters`, and the
`-Max-Price-Usd-{Prompt,Completion,Image}` caps, which the router accepts as
headers only). In route mode the resolved candidate's address is written over any
forwarded one, so the pin always names a candidate this client actually resolved
and sealed to. The identity is written over only when the router reported one for
that candidate (either a value or an explicit "none"); when the router's preview
does not carry the field at all, a forwarded `X-0G-Provider-Identity` is left
alone — it still narrowed the preview, so clearing it would drop a pin that is
working. No other header is forwarded: arbitrary client headers
(cookies, app-internal metadata) must not leak to the router, which terminates
TLS on the router path.

## What it verifies

- **Attestation** — the provider quote is genuine TEE hardware (DCAP-verified;
  enforced). Whether it runs an *audited* image is checked against
  `attest.BootChainPolicy` — one entry per OS image, from the embedded
  `client/evidence/brokerimages.json`. Off by default in the library (`-attest-enforce`),
  and **on** in the deployed gateway, where a provider on an unlisted image is refused
  rather than warned about; `pcverify -provider` prints the observed boot chain in the
  shape an entry wants. See
  [`trust-chain.md`](../docs/design/trust-chain.md) hop 3.
- **Response authenticity** — each response carries a §8 TEE signature, checked
  fail-closed against the **quote-bound** signer. Opt-in in the library
  (`-verify-responses`, off by default); the deployed gateway turns it on, so a response
  whose signature does not verify is not returned. Whether that signer is the one
  *registered on chain* is a separate hop, also opt-in in the library
  (`-onchain-enforce`) and also enforced by the deployed gateway, so a provider the
  registry does not vouch for is skipped rather than sealed to — see
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
pcverify -provider 0x…            # a provider: DCAP quote + on-chain signer (trust-chain hops 2–5), then its hash-gated app-compose
pcverify -gateway <domain>        # the cloud-TEE gateway: its /evidences bundle + served certificate
```

Provider mode goes one step past the hops: hop 3 pins the provider's **OS image** and
says nothing about the containers inside it, so the run also checks the provider's
`app-compose` against the `compose_hash` its verified quote binds, then prints what it
authenticated — each service's image reference, whether it is digest-pinned, whether it
is ours or upstream, and a structural review of the manifest (unpinned images,
`privileged`, host mounts, `allowed_envs` that hand the host a way in, and every field
the review has no rule for). A manifest that does not match the hash fails the run; a
provider that publishes none makes the run incomplete (exit 3). The review itself
**gates nothing** — it exists so a per-service baseline can be written from a real
deployment, and that baseline, compared byte-exact, is what adjudicates.

Each service also carries its **canonical block** fingerprint, and `-blocks` prints the
canonical text. That is the form the baseline is written and compared in:
comments, indentation and quoting are dropped, everything that changes what runs is kept,
and the image **identity** is held out separately so a broker release does not force a
gateway release.

Both the review and the blocks read the compose text **with docker compose's own
loader**: compose-go v2.0.2, the version dstack's docker compose v2.26.0 links, held at
that build's versions of the dependencies that parse port specs and image references
(`evidence/compose/composeload.go`; a test fails if either module drifts). Every YAML
document is merged as docker compose merges them, compose's `!reset` / `!override` tags
and anchors are applied, interpolation's type casts run (`privileged: "true"` is the
boolean docker compose sees), and its short syntax is rewritten long. Whatever docker
compose refuses — a duplicate key, a wrong shape, a key its schema does not know — is
refused as a whole file, and a recorded deployment cannot be compared against it (exit 1).
Three stages are deliberately not run: `${VAR}` substitution, since the values are in the
CVM's encrypted environment (every `$` is reported as provider-controlled instead), and
`include` and `extends`, which compose-go resolves by reading files on whatever machine
runs it; both are reported as blocking. A short-syntax mount, port or ulimit that holds a
template is not parsed either, since docker compose parses it only after substitution: it
is kept as written (so `/data:/d:${MODE}` cannot reduce to `/data:/d`), and a templated
mount is blocking. The canonical form is therefore key-sorted and in long syntax except
for those entries, and services are listed by name. Where docker compose de-duplicates a
list by an identity a template decides (a mount's target, an environment variable's key)
and the list holds other entries, which of them run is the environment's choice, and the
block has no canonical form. The loading runs docker compose's own per-document loop with
compose-go's functions — validation before the transforms, as docker compose does, so a
malformed manifest is refused rather than crashing the verifier — and is held to
compose-go's loader by a differential test. A manifest past 16 YAML documents (docker
compose re-validates after each one) is not read, and a recorded deployment then reports
the comparison as not run (exit 3). Every reviewed key whose value holds a template is
reported at the worst its rule can find. The loader lives in its own package, which
only pcverify imports: the gateway's and sidecar's linked dependencies do not change.

Identity rather than the `image` key, because a real manifest defeats the simpler
version: cn-20's broker services copy the digest into an environment variable
(`IMAGE_DIGEST=sha256:…`), so deleting the key left the copy behind and the held-out
fingerprint moved on every release anyway. The reference and its digest are erased
wherever they appear in the block — and no further: a value that merely looks like a
digest is left alone, because erasing too much hides a real change while erasing too
little only churns. See `evidence/compose/composeblock.go`.

Those blocks are then compared against the **deployment the per-service baseline records
for this provider** (`evidence/compose/brokercompose.json`, keyed by contract and provider
address) — the check that adjudicates, and the only part of the manifest section that can
fail a run. Every direction: a recorded service the manifest does not declare, a declared
service the deployment does not record (an unlisted container runs in the same guest as
the reviewed ones), a service declared twice, a differing block, an image outside its
rule. A mismatch carries no severity — it is not a review finding; either the deployment
is the one we recorded or it is not.

**A provider with no recorded deployment is not compared**, and the run says so and exits
3. It is never held against some other provider's record: an earlier version did that, and
on the 2026-10-10 sweep six healthy providers out of seven exited 1 for the sole reason
that nobody had recorded them. Not recorded is unverified, not refuted.

Two deployments are recorded: mainnet **compute-network-20** and testnet
**compute-network-20-dev**, each taken from that provider's own `-blocks` output and
checked back against the live provider. The other mainnet providers are deliberately not
recorded yet — their broker builds are not ones the release policy accepts, and the v0.5.4
rollout will change their manifests anyway.

0G's broker image is the one image allowed to move without a new record, and only between
**released builds, judged by their signed provenance at run time**
(`provenance`). pcverify — and the gateway and the sidecar, for the build a provider runs
now — fetches the Sigstore bundle attached to the digest
in the registry and accepts the build only when its SLSA provenance verifies against
Sigstore's trust root and was signed by the broker repository's release workflow
(`build.yml`) on a release tag, on a GitHub-hosted runner, at or above v0.5.4 — the first
release carrying the controller's container-creation limits (#759) and the change that
lets broker-ingress drop `dstack.sock` (#763). No list is edited when the broker ships.
v0.5.1 and v0.5.2 are signed by the same workflow and refused by the version floor;
manual branch builds (`docker-publish.yml`) are refused by the workflow check. So cn-20,
on v0.5.1, matches nine of its twelve recorded services and fails on the three that run
the broker image. When the registry cannot be read, those services are reported as not
checked and the run exits 3, never 0.

Sigstore's trust root is fetched each run over TUF (`tuf-repo-cdn.sigstore.dev`, as
cosign does), so a Sigstore key rotation needs no pcverify release either. If TUF cannot
be reached, pcverify falls back to a snapshot embedded in the binary; a bundle that does
not verify against that snapshot is reported as not checked (exit 3) rather than refused,
since it may be signed under a newer key. What the broker repository must keep doing for
its releases to verify is written down in 0gfoundation/0g-serving-broker#765, and
`.github/workflows/broker-release.yml` checks the broker's newest release this way every
day and files an issue when it stops verifying.

pcverify is its own Go module (`cmd/pcverify/go.mod`), so that Sigstore's verifier and
the dependency versions it requires never enter the gateway's build. Build it from that
directory: `cd client/cmd/pcverify && go build .`

**Recording is not approval.** The review reports on every run whatever it finds; a
record only means the services cannot change unseen. The one finding the review relaxes
is `0g-controller`'s `docker.sock`, reported as *justify* rather than *blocking* when the
controller runs a verified release as the `0g-controller` program, using only the service
keys, environment variables and healthcheck every controller on the fleet uses, with
nothing interpolated in its own service, no host path beyond the two sockets, only
declared local volumes, and `ZG_CONTROLLER_ENGINES` absent — the conditions under which
#759 limits what it does with the socket. On any other build it stays blocking and says
which condition failed (`evidence/compose/composecontroller.go`). What it does NOT bound: the
repository image swaps pull from is `controller.imageRepo` in the controller's config
file, which the provider supplies and can rewrite at runtime, so what broker and event
run after boot is bounded by the RTMR3 replay below, not by the review.

**What runs now, not only what booted.** The controller records every image swap and
config change in RTMR3 before making it. `pcverify -provider` replays the event log from
the provider's `/v1/quote` reply into the verified quote's RTMR3. A log that does not
replay fails the run. It then reads the controller's records as the broker repository
specifies them (`doc/rtmr3-records.md`). This is an independent implementation in
`evidence/rtmr3.go`, tested against the broker's own vector and two live replies, not an
import of the broker's code. The last `zg-image-update` names the build broker and event
run now. That build must be an accepted release by the same provenance policy, for every
provider whether a deployment is recorded or not, and its signer and enc_pub must equal
the quote's report_data. A `zg-engine-set` record fails the run. Several things leave the
run incomplete (exit 3): a reply without an event log, a record name this reader does not
know, an upstream set the controller marked `invalidated`, an aborted instance change,
and a release check that could not run. The upstream set (where plaintext may go, inside
or outside the CVM) and the config hash are printed, not judged. The records are only as
trustworthy as the confinement of `dstack.sock`, which only a matching recorded deployment
establishes, and the report says so when there is none. On 2026-10-16 this check found
cn-19, cn-20 and cn-41 running manual branch builds swapped in after boot, behind
manifests pinning v0.5.2, v0.5.1 and a branch build.

The baseline also records each deployment's **top-level sections** — `volumes`,
`networks`, and anything else besides `services` and `x-` extensions — and compares them
the same way. A service block names a volume; the declaration says what it is, and
changing only the declaration (to an `nfs` driver, `external: true`, another device)
would move the data behind the name while every service block still matched.

`-app-baseline <file>` reads a candidate instead of the embedded one, which is how a
deployment gets checked against a live provider before it is committed.

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
pass. `-strict` makes every check mandatory and turns the latter into the former. In
provider mode a 3 means one of four things — hop 3's allowlist held no entry, the
provider published no app-compose, no deployment is recorded for the provider, or
`-no-quote` skipped hops 2–4 by request — and the verdict line names every one that
applies. The third applies to most of the fleet as shipped, so `-strict` fails every
provider nobody has recorded. See
[`docs/design/cloud-gateway.md`](../docs/design/cloud-gateway.md) §10 for what the
result does and does not cover.

A deployed gateway also *describes itself* at `GET /v1/gateway/identity` — the same
`app_id`, `compose_hash`, OS image, container list and matching release, assembled
server-side so a browser panel can display them (`cmd/gateway/identity.go`). That
endpoint is **not** a substitute for this tool and does not try to be: it verifies
nothing, signs nothing, and exists only so there is something to show. `pcverify`
rederives every one of those values independently — and does the endpoint binding, the
one step no web page can perform. If the two disagree, `pcverify` is right.

The provider side is a different kind of claim, and has its own route: `GET
/v1/providers/{address}/identity` reports what the gateway **verified** about a
provider — the DCAP verdict on that provider's quote, the on-chain signer
comparison, the boot-chain verdict against the audited allowlist (hop 3), its `compose_hash`
(`cmd/gateway/provideridentity.go`, `route/provideridentity.go`). Those checks really
happened, on a third party, before any seal; what the endpoint cannot do is make them
*yours*. It answers only for providers it has checked itself — the ones it has sealed
to, plus every provider the `-warm` sweep covers, which is what lets a panel describe
the catalog before the first prompt — never fetches a quote for an address on demand,
and returns no quote bytes: anyone re-verifying should fetch that provider's
`/v1/quote` direct, which is what the response's `verify` string names.

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