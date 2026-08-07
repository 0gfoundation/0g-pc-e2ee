# Phala Cloud deployment (cloud-TEE gateway)

Deploys the [`gateway`](../../client/cmd/gateway) to [Phala Cloud](https://phala.com)
via [dstack](https://docs.phala.com), on **our own domain**. This is the
server-run, 0G-operated, cloud-TEE form of the client core — see
[`docs/design/cloud-gateway.md`](../../docs/design/cloud-gateway.md) for the trust
model (tier 2.5: confidential by default, cheating publicly detectable).

## How it works

Two containers, one CVM, one measured compose file:

```
client ──TLS──> platform host front end ──> dstack gateway ──passthrough──┐
               (SNI-suffix allowlist)        (L4, no decryption)          │
                                                                          v
                                       ┌──────────────── this CVM ────────────────┐
                                       │ dstack-ingress ──plaintext──> gateway    │
                                       └──────────────────────────────────────────┘
```

- [dstack-ingress](https://github.com/Dstack-TEE/dstack-examples/tree/main/custom-domain)
  terminates TLS **inside this CVM**: it generates the key in the enclave, gets a
  Let's Encrypt certificate for our hostname, and forwards plaintext to the
  gateway over the compose network. The dstack gateway only passes the encrypted
  TCP through, so **plaintext never exists outside our own enclave**.
- The gateway therefore serves **plaintext HTTP** on `:8443` and does no TLS. It
  is not published to the host — only dstack-ingress is reachable from outside.
- The gateway has a Docker **healthcheck** (`gateway -health`, which probes its
  own `/healthz` — the image is distroless, so the binary is its own probe), and
  dstack-ingress `depends_on` it with `condition: service_healthy`. So ingress
  only comes up once the gateway is actually serving, closing the first-boot race
  where HAProxy resolves the `gateway` backend before it exists. (A *later*
  recreation of the gateway with a new address still needs an ingress restart —
  `depends_on` covers startup only.)
- dstack-ingress serves `/evidences/` (`quote.json`, `cert-<DOMAIN>.pem`,
  `acme-account.json`, `sha256sum.txt`). The quote's `report_data` holds
  `SHA-256(sha256sum.txt)`, and `sha256sum.txt` covers the served certificate;
  its RTMR chain commits to this app's `app_id`, the hash of the app-compose
  manifest that embeds this compose file verbatim. So one quote proves *"a CVM
  running exactly this app-compose obtained this certificate inside the TEE"*,
  covering both containers. See [Verify](#verify) for the step the quote cannot do
  for you.

## Serving domain

Set these in the CVM's **encrypted environment** (the Phala Cloud dashboard's
secrets field, or `-e KEY=VAL` / an env file passed to the CLI at deploy time).
The Cloudflare token is a secret: never commit it, and scope it to the delegation
zone alone — it needs no access to the served domain's own zone.

| Variable | Example | Notes |
|---|---|---|
| `DOMAIN` | `pc-gateway.example.com` | the hostname we serve |
| `GATEWAY_DOMAIN` | `_.<cluster>.phala.network` | dstack gateway of the target cluster |
| `DELEGATION_ZONE` | `delegation.example.net` | zone the container writes into |
| `CLOUDFLARE_API_TOKEN` | — | DNS edit permission, **`DELEGATION_ZONE` only** |

All four are declared `${VAR:?…}` in the compose file, so a missing one fails the
deploy immediately instead of silently degrading. They must also be listed in the
app's `allowed_envs` — dstack drops any encrypted variable that is not, and the
only symptom is an interpolation error at boot.

Only variables the compose file actually references reach the container. Setting
anything else in the CVM environment does nothing; changing what the compose
references means editing the file, which changes `app_id`. Two optional
dstack-ingress variables are therefore commented out in the compose rather than
listed above — `ACME_EMAIL` (optional, and published in the evidence bundle, so
the address would be world-readable at
`https://<DOMAIN>/evidences/acme-account.json`) and `ACME_STAGING` (see
[Deploy](#deploy)).

Whoever runs the served zone's DNS creates three CNAMEs **once, before the first
boot**. They all point into the delegation zone, so they never change again — not
even when the app id changes, because the container keeps the delegated records
up to date itself:

```
pc-gateway.example.com                      CNAME  pc-gateway.example.com.<DELEGATION_ZONE>
_dstack-app-address.pc-gateway.example.com  CNAME  _dstack-app-address.pc-gateway.example.com.<DELEGATION_ZONE>
_acme-challenge.pc-gateway.example.com      CNAME  _acme-challenge.pc-gateway.example.com.<DELEGATION_ZONE>
```

The first is the serving alias (the container republishes it to `GATEWAY_DOMAIN`,
and attaches a CAA record pinning issuance to its own ACME account, which stops a
*third party* getting a cert for the name — it does not constrain whoever holds
the DNS token); the second is how the dstack gateway learns which app to route to;
the third delegates certificate issuance. That is the point of the delegation: the
enclave's DNS token never needs access to the served domain's own zone.

Two platform-side prerequisites, both of which fail in ways the logs do not
explain:

- The dstack host front end only forwards SNI suffixes it has been configured
  for, so **ask Phala to allow the new domain suffix** before deploying. Until
  they do, the connection is dropped before it reaches the dstack gateway and the
  client sees a bare TLS handshake failure — while the DNS records and the
  certificate all look perfectly fine.
- The three CNAMEs must exist before the container starts. It waits for them
  (`DNS_SETUP_MODE=wait`) but gives up after `DNS_SETUP_TIMEOUT`, 30 minutes by
  default, and then exits without a certificate.

## Deploy

Reference [`docker-compose.yml`](./docker-compose.yml) from the Phala Cloud
dashboard, or via the CLI, passing the environment above:

```sh
phala cvm create --compose deploy/phala/docker-compose.yml
```

When bringing up a **new** hostname, do the first round trips against Let's
Encrypt's staging CA by setting `ACME_STAGING=true` in the CVM's encrypted
environment. Keep `ACME_STAGING` **permanently listed in `allowed_envs`** (its
default is `false`) and switch between staging and real by the **value**, not by
adding/removing the key: `allowed_envs` is part of the measured app-compose, so
editing the list changes `app_id`. Every *successful* issuance for the same
hostname counts against the 5-duplicate-certificates-per-week limit, and each
fresh CVM issues again from an empty `cert-data` volume, so iterating on
production directly can leave the hostname uncertifiable for days. Staging's
limits are far higher; its certs are untrusted, so use them for smoke tests only,
then set `ACME_STAGING=false` (or drop the value) for the real certificate.
Because only the injected *value* changes and `allowed_envs` stays constant, the
measured compose is identical either way — a staging run and the production run
share `app_id`, and the served cert's issuer (LE staging vs real) is what tells
them apart.

## Verify

Liveness — does traffic reach the gateway at all:

```sh
curl https://<DOMAIN>/healthz
```

Attestation — this is the part that actually proves something. Fetching the
bundle is not enough; the load-bearing step is comparing the **served**
certificate with the one the quote commits to:

```bash
# 1. the cert the endpoint actually serves
openssl s_client -servername <DOMAIN> -connect <DOMAIN>:443 </dev/null 2>/dev/null \
  | openssl x509 -outform pem > served.pem

# 2. the whole evidence bundle (all of it — sha256sum.txt covers
#    acme-account.json too, so omitting that file fails the check)
for f in quote.json sha256sum.txt acme-account.json cert-<DOMAIN>.pem; do
  curl -sO "https://<DOMAIN>/evidences/$f"
done
sha256sum -c sha256sum.txt

# 3. the served cert must be the one in the bundle. Compare public keys: the
#    bundle carries the full chain, `s_client` gives the leaf.
diff <(openssl x509 -in served.pem -noout -pubkey) \
     <(openssl x509 -in cert-<DOMAIN>.pem -noout -pubkey) && echo "cert matches evidence"
```

Then DCAP-verify `quote.json` and check its `report_data` — the first 32 bytes are
`SHA-256(sha256sum.txt)`, right-padded to 64. Finally confirm the code: replay the
event log against the verified quote to recover `app_id`, fetch the CVM's
`app-compose.json` (Phala Cloud dashboard / API), check its `docker_compose_file`
is byte-identical to the **`docker-compose.release.yml` from the GitHub Release
you deployed** (the digest-pinned manifest), and that hashing the manifest
reproduces that `app_id`. The [`docker-compose.yml`](./docker-compose.yml) checked
in here carries the floating `:latest` gateway tag for development and will **not**
match a production `app_id` — the Release asset is the attested artifact.

Skip step 3 and the quote only proves *some* CVM obtained *some* certificate — it
says nothing about the endpoint you are talking to. Skip the `app-compose.json`
comparison and you have proven the CVM is a genuine TEE without knowing what it
runs.

Point an OpenAI-compatible client's `base_url` at `https://<DOMAIN>`.

### Without a domain (dev / smoke test)

To boot a build in a CVM without owning a zone, deploy the gateway *alone* — drop
the `dstack-ingress` service entirely (its `${VAR:?…}` guards would otherwise
fail the deploy) and publish the port, so the platform hostname serves it:

```yaml
# dev only — a complete compose, not an override
services:
  gateway:
    image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:18e78717954d02f821d91292d86e611fe5cd31836360fe2fce233369cf987072
    restart: unless-stopped
    ports:
      - "8443:8443" # reachable at https://<app-id>-8443.<base_domain>
    environment:
      - "ZG_GATEWAY_LISTEN=0.0.0.0:8443"
      - "ZG_GATEWAY_ATTEST=true"
      - "ZG_GATEWAY_PCCS_URL=https://pccs.phala.network"
```

Keep this in step with the real compose when the gateway's own variables change,
or a smoke test exercises a different code path than production does.

TLS then terminates in the Phala-operated dstack gateway under a shared cluster
wildcard certificate, so there is **no binding to our app** and none of the
attestation above applies. Development only.

## Pin the image digest

> **Development phase:** the checked-in compose currently references the gateway
> as `ghcr.io/0gfoundation/0g-pc-e2ee-gateway:latest` so a fresh build is picked
> up on redeploy without editing the file. This intentionally **breaks the
> attestation guarantee below** and must be reverted to a digest pin before any
> attested / production deploy. dstack-ingress stays digest-pinned throughout.

`app_id` hashes the app-compose manifest, which embeds this compose file
verbatim — so a floating `:latest` tag keeps the attestation identical while the
code underneath changes, and anyone who can push to the registry could swap the
gateway binary inside an "attested" CVM undetectably. Both images are therefore
pinned by digest for production, and both have to be re-pinned deliberately on
upgrade:

```sh
# what :latest points at RIGHT NOW — compare it with the digest in the compose
# file to see whether the pin is still the current build (a difference is
# expected and fine; it just means the pin is older than the tag)
docker buildx imagetools inspect ghcr.io/0gfoundation/0g-pc-e2ee-gateway:latest
```

Changing either digest changes `app_id`, which is the point: it is a new
deployment, and verifiers have to re-audit it.

## Release (automated)

[`.github/workflows/release.yml`](../../.github/workflows/release.yml) (manual
`workflow_dispatch`) automates the pin step above and publishes the attested
artifact as a GitHub Release. It does **not** edit the checked-in compose: `main`
stays on `:latest` for development, and the digest-pinned manifest lives only on
the Release. That artifact — not any git tree — is the audit reference; the
authoritative record of what a CVM runs is still Phala's `app-compose.json` + the
quote (see "Verify"), and the Release is the convenience copy you compare against.

**Input** — `ref`: branch, tag, or commit SHA to release (default `main`).
Because every push to `main` publishes a per-commit `sha-<full-sha>` gateway
image, you can release **any** past main commit (e.g. `main~1` or an explicit
SHA), not just the tip. For a ref with no published image yet — a feature branch,
or a garbage-collected build — the workflow builds and pushes it first
(build-if-missing); an image that still exists is reused, never rebuilt (a rebuild
is not guaranteed bit-identical, so reuse preserves the original digest).

**What it does:**

1. Resolves `ref` to a full commit SHA and **checks the tree out at that commit**,
   so the pinned image and the compose come from the same commit (an old image
   paired with today's compose could carry mismatched env vars).
2. Resolves that commit's gateway image digest (`sha-<full-sha>` tag →
   `@sha256:…`).
3. Generates `docker-compose.release.yml` by replacing **only** the gateway
   `image:` line with the `@sha256:` pin — every other byte (env, ingress,
   prometheus) is identical to the compose at that commit, so the two cannot
   drift. A guard fails the run if the gateway is still on a floating tag.
4. Computes a version `release-YYYY.MM.DD.N` (UTC date; `N` auto-incremented from
   that day's existing releases/tags) and creates a GitHub Release at that commit
   with `docker-compose.release.yml` attached.

Deploy the attached asset to Phala; its bytes are what `app_id` attests. The tag
is intentionally **not** `v*`, so it does not retrigger `docker.yml`'s build
(which would produce a divergent digest). The per-commit `sha-` tag uses the full
40-char SHA (`type=sha,format=long` in `docker.yml`) so any input commit maps to
its image tag deterministically.

## Metrics (Prometheus)

The gateway exports Prometheus metrics, but **not on the public endpoint**. It
serves `/metrics` on a separate internal listener (`ZG_GATEWAY_METRICS_LISTEN`,
set to `0.0.0.0:9464` in the compose). That port is never published to the host
and dstack-ingress does not front it, so — like the gateway's `:8443` — it is
reachable only over the compose network. This keeps operational telemetry off the
same edge as the OpenAI API and avoids adding a side channel to the confidential
enclave.

Shipping the samples out follows the same shape other 0G services use — a
co-located Prometheus that scrapes locally and `remote_write`s to a central
store — but in **agent mode**:

- A `prometheus-agent` container (`prom/prometheus --enable-feature=agent`)
  scrapes `gateway:9464` over the compose network and `remote_write`s to your
  central Prometheus (or any `remote_write`-compatible store). Agent mode keeps
  no local TSDB and no query API — this CVM is ephemeral; the durable copy lives
  in the remote store. A self-hosted Prometheus receiving `remote_write` must run
  with `--web.enable-remote-write-receiver`.
- The agent also **self-scrapes**, so `remote_write` health (queue length, send
  failures) is visible even though the CVM has no local query API — important
  because an outbound break inside the enclave is otherwise hard to see.

### Telling replicas apart

Every series the gateway exports carries `instance_id` and `app_id`, read once at
boot from the dstack guest-agent socket the compose mounts into the gateway
container (`ZG_GATEWAY_DSTACK_SOCKET`). The same `instance_id` is attached to
every log line the process writes.

This is a prerequisite for running more than one CVM per side, not a nicety.
Replicas of one `app_id` are identical CVMs running identical Prometheus agents,
so their external labels (`service`, `env`) and target labels (`gateway:9464`) are
identical too — without a per-CVM label they write the **same series** to the
shared store and the samples collide. `app_id` additionally separates a blue side
from a green one, which `env` cannot.

Two caveats:

- **The `prometheus-agent` self-scrape still collides** across replicas. Compose
  interpolation happens at deploy time and cannot see a value the runtime assigns
  per CVM, so those ~30 agent-health series have no per-instance source. Gateway
  telemetry — what alerting runs on — is unaffected.
- **A missing mount degrades silently in the data path and loudly in the log.**
  If the socket is absent or the agent does not answer, the gateway logs
  `dstack identity unavailable` at WARN and serves normally, without the labels.
  Grep for that line after a deploy if a replica's metrics go missing.

To attribute a *specific request* to a replica (e.g. while measuring how the
platform distributes connections), set `ZG_GATEWAY_INSTANCE_HEADER=true` and the
gateway returns `X-0G-Gateway-Instance` on every response. It is **off by
default**: the id is public, but a per-response header lets any caller enumerate
the fleet behind the domain. Toggle it by value — keep the key permanently in
`allowed_envs`, since editing that list changes `app_id`. Note that selection is
per TCP connection, so a keep-alive client sees one replica no matter how many
requests it sends; see `blue-green.md` "Scaling one side".

### Configuring remote_write

You pass three values, not a hand-built config:

| Variable | Secret? | Example |
|---|---|---|
| `ZG_PROM_REMOTE_WRITE_URL` | no | `https://prometheus.example.com/api/v1/write` |
| `ZG_PROM_REMOTE_WRITE_USERNAME` | no | `0g-pc-gateway` |
| `ZG_PROM_REMOTE_WRITE_PASSWORD` | **yes** | — |
| `ZG_PROM_ENV` | no | `staging` / `mainnet` |

Set all four in the CVM's **encrypted environment** — the Phala env file, the
same channel as `CLOUDFLARE_API_TOKEN` — and list them in the app's
`allowed_envs`, or dstack drops them.

`ZG_PROM_ENV` becomes an `env` label stamped on every series (alongside a fixed
`service=0g-pc-gateway`), so when staging and mainnet remote_write into the **same
store** their metrics stay distinguishable — the dashboard filters on it. Set it
per environment (`staging` in the staging env file, `mainnet` in the other); a
missing value fails the deploy loudly (`:?`), but note it is not validated against
the two names, so a typo yields a wrong-but-accepted label. Only `${VAR}` *references* live in the
measured compose text, never the values, so nothing sensitive enters the
attestation.

Prometheus does not expand env vars in its own config, so `agent.yml` is a
compose **`config`** whose `remote_write` url/username/password are `${VAR}` —
interpolated by **compose** from the env file when it renders, then mounted
read-only (0444, so the agent's `nobody` user can read it). No init container and
no docker `secret`: Phala's env injection is already encrypted to the enclave,
and the rendered password only ever lives inside this single-tenant CVM's own
config — adequate for a write-only metrics credential. (A docker `secret` would
only narrow in-CVM exposure — keep the value out of the container env and out of
the config file — which is not worth an extra compose dependency here.)

Scrape targets use docker **service names** on the compose network: `gateway:9464`
for the app and `localhost:9090` for the agent's own metrics.

> This uses top-level `configs:`, standard in Docker Compose / recent dstack. If
> your runtime rejects it, render `agent.yml` with a small init container instead
> (write it from the same env vars to a shared volume before the agent starts).
> A password containing YAML-special characters (`"` or `\`) also wants the
> init-container form (or a `password_file`) rather than the inline value.

### Metric hygiene

Labels are deliberately low-cardinality and content-free (route templates, HTTP
methods, status codes, fixed outcome enums) — the same redaction discipline the
access log keeps, so metrics never leak the plaintext the E2EE seal protects. See
[`client/metrics`](../../client/metrics) for the full metric set (HTTP RED,
completion outcome by source/stage, E2EE open failures, §8 response-signature
verification failures, quote verify latency, quote/collateral cache hit ratios,
and warmer liveness).

## Notes

- **Secrets.** The Cloudflare token and the `remote_write` password (see Metrics)
  are the secrets to supply, but the `cert-data` volume holds material just as
  sensitive — the TLS private key and the ACME account key. It never leaves the
  CVM; do not snapshot or export it. The `evidences` volume is public by design.
- **Attestation** comes entirely from dstack-ingress's `/evidences/`. The gateway
  exposes no attestation endpoint of its own and signs no responses of its own:
  its `app_id`-covered image is already attested by the ingress cert-binding
  quote, and inference authenticity rides each provider's own SPEC §8 signature
  (verified via `ZG_GATEWAY_VERIFY_RESPONSES`). See
  [`cloud-gateway.md`](../../docs/design/cloud-gateway.md) §6.
- The gateway holds no pinned provider key: it routes per request and derives
  each provider's enc key + signer from the broker. The router base URL is
  `${ZG_GATEWAY_ROUTER_URL:-https://router-api.0g.ai}` — unset it (production) to
  use the 0G production router, or inject `ZG_GATEWAY_ROUTER_URL` via the CVM's
  **encrypted environment** (staging) to point at a different router. The
  variable must be listed in the app's `allowed_envs` for the override to reach
  the container. Since the *measured* text is the `${…}` form, staging and
  production share `app_id`; that is safe only because the router is untrusted by
  construction (see the provider-verification note below).
- **Browser origins (CORS).** The gateway answers cross-origin browser calls only
  from the origins in `ZG_GATEWAY_ALLOWED_ORIGINS`, whose compose default is the 0G
  first-party app origins — a page allowed to call the router directly can point its
  base URL at this gateway instead — and deliberately *not* every origin the router
  accepts, since its list also carries third-party-hosted preview/deploy origins
  that do not get to drive sealed inference through an enclave by default. The list is
  spelled out in the measured compose text on purpose (which web origins may drive
  sealed inference through the enclave is trust-relevant, so `app_id` should commit
  to it), and the `${…}` form still lets an **encrypted-environment** override win
  at boot, provided the variable is listed in `allowed_envs`. Patterns are exact
  origins, a leading `*.` wildcard (`https://*.0g.ai` — subdomains only, never the
  apex, which must be listed separately), or `*` for any; an empty value allows no
  origin and turns browser access off, and a malformed pattern (a trailing slash, a
  missing scheme) fails the boot rather than silently blocking the app it was meant
  to allow. Non-browser callers (SDKs, server-side code, `curl`) send no `Origin`
  header and are unaffected by any of this. The default carries two `localhost`
  ports as development conveniences — drop them via the override on a deployment
  that does not need dev hosts reaching this enclave.
- **Provider verification** is on in verify-and-warn mode. Each provider's TDX
  quote is DCAP-verified (`ZG_GATEWAY_ATTEST`), its quote-bound signer is
  cross-checked against the on-chain `teeSignerAddress`
  (`ZG_GATEWAY_ONCHAIN`), and each response's §8 TEE signature is verified
  fail-closed against that signer (`ZG_GATEWAY_VERIFY_RESPONSES`). A background
  warmer (`ZG_GATEWAY_WARM`) pre-verifies quotes so requests hit a warm cache.
  The measurement and on-chain-signer checks only *warn* on a mismatch rather
  than reject, because their enforce switches (`ZG_GATEWAY_ATTEST_ENFORCE`,
  `ZG_GATEWAY_ONCHAIN_ENFORCE`) are off — the audited-image allowlist is not
  wired yet, so enforcing measurements would reject every provider. Response
  signatures are always fail-closed.
- If the gateway container is recreated with a new address, restart
  dstack-ingress too — HAProxy resolves the backend name once, at startup.
- **Zero-downtime upgrades.** A new gateway image is a new `app_id` (above), i.e.
  a separate CVM. To roll one out without downtime and with instant rollback, run
  the old and new builds as two sides and flip a single DNS pointer between them
  — see [`blue-green.md`](./blue-green.md) and [`switch.sh`](./switch.sh).
