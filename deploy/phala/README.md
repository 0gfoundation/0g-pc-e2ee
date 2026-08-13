# Phala Cloud deployment (cloud-TEE gateway)

Deploys the [`gateway`](../../client/cmd/gateway) to [Phala Cloud](https://phala.com)
via [dstack](https://docs.phala.com), on **our own domain**. This is the
server-run, 0G-operated, cloud-TEE form of the client core — see
[`docs/design/cloud-gateway.md`](../../docs/design/cloud-gateway.md) for the trust
model (tier 2.5: confidential by default, cheating publicly detectable).

## How it works

One CVM, one measured compose file, four containers — the two on the request path
plus two that only support them:

```
client ──TLS──> platform host front end ──> dstack gateway ──passthrough──┐
               (SNI-suffix allowlist)        (L4, no decryption)          │
                                                                          v
                                       ┌──────────────── this CVM ────────────────┐
                                       │ dstack-ingress ──plaintext──> gateway    │
                                       │                                          │
                                       │ cvm-identity (init, exits)               │
                                       │ prometheus-agent ──metrics out──▶        │
                                       └──────────────────────────────────────────┘
```

The two support containers are covered below: [`cvm-identity`](#telling-replicas-apart)
writes this replica's `instance_id`/`app_id` once at boot and exits, and
[`prometheus-agent`](#metrics-prometheus) ships telemetry out.

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
  `SHA-256(sha256sum.txt)`, and `sha256sum.txt` covers the served certificate; its
  `mr_config_id` commits to `compose_hash`, the SHA-256 of the app-compose manifest
  that embeds this compose file verbatim (`app_id` is its leading 20 bytes). So one
  quote proves *"a CVM running exactly this app-compose obtained this certificate
  inside the TEE"*, covering all four containers. See [Verify](#verify) for the steps
  the quote cannot do for you.

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
dstack-ingress variables are therefore handled differently from the four above.
`ACME_EMAIL` is **commented out** in the compose — it is optional, and it is published in
the evidence bundle, so any address there would be world-readable at
`https://<DOMAIN>/evidences/acme-account.json`. `ACME_STAGING` **is** referenced
(`${ACME_STAGING:-false}`), precisely so it can be switched by value without editing the
measured text — see [Deploy](#deploy).

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
certificate with the one the quote commits to.

> This section is the operator's view. The **user-facing** version — what each check
> proves, which trust assumptions remain, and the by-hand procedure — is
> [`docs/verifying-the-gateway.md`](../../docs/verifying-the-gateway.md). Point beta
> users at that, not at this file.

`pcverify -gateway` does all of that in one command — bundle integrity, DCAP
verification of `quote.json`, the `report_data` binding, the served-certificate
comparison, code identity, and the OS image the compose binding rests on — and exits
non-zero on any failed check, so it drops into a deploy gate:

```sh
# The whole chain, no extra arguments: it derives the platform base domain from the
# served domain's CNAME chain, fetches app-compose.json for the app_id the quote
# names, and matches the compose text against the newest 5 published releases.
cd client && go run ./cmd/pcverify -gateway <DOMAIN> -pccs-url https://pccs.phala.network
```

The last step defaults to `-releases 5`: the `docker-compose.release.yml` asset from
the newest 5 published releases of this repo (`-repo` / `-release-asset` to override;
drafts and prereleases are skipped). It reports **which** release is live, and its
interesting answer is "none of them". The repo is public, so no credentials are
needed — set `GITHUB_TOKEN` only for a private repo or to lift the unauthenticated
rate limit.

Two ways to change what the compose text is compared against:

```sh
# a gate: it must be exactly the manifest you deployed
… -expect-compose-file docker-compose.release.yml

# no comparison at all (offline, or GitHub deliberately out of the loop)
… -releases 0
```

Because `-releases` has a default, its failure mode depends on whether you asked for
it: an unreachable or rate-limited GitHub on a **default** run is reported as
advisory (`-`) and does not fail, since it says nothing about the deployment, while an
explicit `-releases N` that cannot be satisfied is fatal. Passing
`-expect-compose-file` simply overrides the default; passing it *and* an explicit
`-releases` is rejected, since they answer different questions.

An advisory skip is not a clean pass, though, and the exit code says so: **0** every
check ran and passed, **1** a check failed, **2** caller mistake, **3** nothing failed
but something did not run. A `3` prints `PASS (INCOMPLETE)` and names the gap. Use
`-strict` in a gate to make every check mandatory — it turns a `3` into a `1` and
demands the checks without demanding their inputs, so DNS and release discovery still
supply them. `-strict` with `-releases 0` is rejected as a contradiction.

Nothing about the app-compose lookup has to be typed in: the base domain comes from
DNS (`-base-domain` overrides it, `-no-dns-discovery` turns it off) and the `app_id`
comes from **the quote**, never from you or from DNS. That last part matters under
blue/green, where both sides are live under different `app_id`s and picking one by
hand is how you end up verifying the standby. Use `-app-compose <file>` when the
guest agent is unreachable or the app's `public_tcbinfo` is off; the bytes are
anchored by the quote's `compose_hash`, so their source does not have to be trusted.

`-no-dns-discovery` with no `-app-compose` / `-base-domain` leaves the app-compose
stage with nothing to run on, so code identity is reported as **not checked** — the run
can still pass on endpoint identity (declining a check is not a failure), exiting 3
rather than 0, and the closing note says which case it is in. Combining it with an
explicit `-expect-compose-file` / `-releases N` — or with `-strict` — is a contradiction
and fails: a comparison was demanded that cannot be performed.

Add `-allow-untrusted-cert` when checking a hostname brought up against the ACME
staging CA (`ACME_STAGING=true`): its certificate is correctly bound by the quote but
deliberately signed by an untrusted CA, so the chain-trust step fails on purpose. Every
other check runs without the flag; what it decides is whether that one failure blocks
the verdict.

It relaxes no attestation check, but it is **not** free: chain trust is what ties
the connection to the domain you named, so waiving it lets an interceptor running
its *own* attested CVM satisfy every other check — its own quote, its own
consistent bundle, its own certificate, which then matches that bundle because it
controls both. The claim narrows to "a genuine TEE minted the certificate served on
this connection". Fine for smoke-testing a deployment you operate; never for
auditing an endpoint you do not control, and never on the production hostname. The
tool prints this caveat on any run that uses the flag.

The equivalent by hand, for reference or when the tool is unavailable:

```bash
# 1. the cert the endpoint actually serves
openssl s_client -servername <DOMAIN> -connect <DOMAIN>:443 </dev/null 2>/dev/null \
  | openssl x509 -outform pem > served.pem

# 2. the whole evidence bundle (all of it — sha256sum.txt covers acme-account.json
#    too, so omitting that file fails the check). ONE curl call, not a loop: it reuses
#    a single connection, and dstack picks a CVM per connection — separate requests can
#    land on different replicas, each with its own cert, sha256sum.txt and quote, which
#    fails the check below on a perfectly healthy deployment.
curl -s --remote-name-all \
  "https://<DOMAIN>/evidences/"{quote.json,sha256sum.txt,acme-account.json,cert-<DOMAIN>.pem}
sha256sum -c sha256sum.txt

# 3. the served cert must be the one in the bundle. Compare the WHOLE certificate (the
#    bundle carries the full chain, `s_client` gives the leaf). A renewal can change the
#    bytes while the two sides are briefly out of step, which is a half-applied renewal
#    rather than a match.
diff <(openssl x509 -in served.pem -noout -fingerprint -sha256) \
     <(openssl x509 -in cert-<DOMAIN>.pem -noout -fingerprint -sha256) && echo "cert matches evidence"

# If that differs, re-run rather than reading the public keys: the ingress regenerates
# the evidence BEFORE reloading haproxy (scripts/dns01.sh run_pass), so mid-renewal the
# SERVED cert is the stale side — and whether a renewal reuses the key depends on an
# unpinned certbot default, so a key comparison proves nothing either way. A replica
# split (the curl above and the s_client here are two connections) also clears on a
# re-run; a foreign certificate does not. If it survives ten minutes, haproxy_reload is
# failing — check the ingress log. pcverify avoids the replica half by keeping the whole
# run on one connection.
```

Then DCAP-verify `quote.json` and check its `report_data` — the first 32 bytes are
`SHA-256(sha256sum.txt)`, right-padded to 64.

Then code identity. `compose_hash` is in the verified quote's **`mr_config_id`** —
`0x01 ‖ SHA-256(app-compose.json) ‖ zero padding` — so it is read straight out of
the signed TD report, with no event-log replay (the `compose-hash` runtime event in
RTMR3 carries the same value if you want a cross-check). `app_id` is its leading 20
bytes:

```bash
# app-compose.json, from the platform guest agent (public_tcbinfo defaults on).
# APP is the app_id from the quote's mr_config_id — not one you pick.
APP=<app_id>
curl -s "https://$APP-8090.<cluster>.phala.network/prpc/Info" > info.json
jq -r '.tcb_info' info.json > tcb.json
jq -j '.app_compose' tcb.json > app-compose.json   # -j: no trailing newline

# it must hash to the quote's compose_hash — this is what makes the bytes trustworthy
shasum -a 256 app-compose.json

# then its embedded compose text must be the manifest you deployed
jq -j '.docker_compose_file' app-compose.json > deployed-compose.yml
diff deployed-compose.yml docker-compose.release.yml
```

Finally the OS image, which is what makes the step above mean anything: `mr_config_id`
is written by the untrusted host, and the compose hash is truthful only because the
guest OS refuses to boot when that register disagrees with the app-compose it actually
received (dstack `config_id_verifier.rs`). So the OS doing that check is part of the
chain, and the quote's `MRTD` + `RTMR1` + `RTMR2` are what identify it — the virtual
firmware, the kernel, and the cmdline (carrying the rootfs verity hash) plus initrd,
i.e. every piece of code that performs that boot-time check. Compute them from the
published guest-OS release and compare:

```bash
# the release must be the one this CVM runs: vm_config.os_image_hash IS digest.txt.
# Run this INSIDE the unpacked image directory — the evidence bundle has a sha256sum.txt
# too, and comparing that one against the image's digest.txt fails every time.
cd dstack-<version>/
test "$(sha256sum sha256sum.txt | awk '{print $1}')" = "$(cat digest.txt)"

# from github.com/Dstack-TEE/dstack: tdx::tdx_measurements_for_image_dir_without_rtmr0,
# which needs no QEMU. The `measure` subcommand also computes RTMR0 and so shells out
# to dstack-acpi-tables.
```

Two traps: `MRTD` depends on the host's page-add mode (the deployment is **two-pass**;
`vm_config.qemu_single_pass_add_pages` is false), and the Go `dstack-mr` models no
page-add mode so it returns the single-pass value. `-c`/`-m` only affect RTMR0.

> **Where the artifact lives depends on flavour and version**, which is easy to get
> wrong — `meta-dstack` publishes no `dstack-nvidia` asset below v0.5.6, and it is
> tempting to conclude the image is unpublished. It is not: nvidia images **before
> v0.5.6** come from
> [`nearai/private-ml-sdk`](https://github.com/nearai/private-ml-sdk/releases). That is
> the split Phala's own verifier encodes (`trust-center`
> `packages/verifier/src/utils/imageDownloader.ts`, `getNvidiaRepo`). Base and dev
> flavours below 0.6.0 come from `meta-dstack`; 0.6.0 and later from dstack's own
> `guest-os-*` releases. Each entry in `osimages.json` records the exact source it was
> computed from, so a reviewer can fetch the same artifact without rediscovering this.

Two registers are deliberately excluded. `RTMR3` holds the per-app and per-instance
events, which `compose_hash` already covers more precisely. `RTMR0` records the **VM
shape** (vCPU, RAM, ACPI/device layout), which this check does not need to establish —
so an entry is **one per image**, not one per (image, shape) pair, and the `-c`/`-m`
values above do not affect the result. Once the three values are derived and confirmed
against a live quote they belong in
[`client/evidence/osimages.json`](../../client/evidence/osimages.json), which
`pcverify` embeds so no user ever supplies it.

The [`docker-compose.yml`](./docker-compose.yml) checked in here carries the floating
`:latest` gateway tag for development and will **not** match a production deployment
— the Release asset is the attested artifact. And note what a floating tag costs even
when every check above passes: `compose_hash` stays identical while the image behind
the tag changes, so code identity is only ever as strong as the pinning in the compose
text it authenticates.

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
binary inside an "attested" CVM undetectably. Every image is therefore pinned by
digest for production, and each has to be re-pinned deliberately on upgrade.

> **The gateway image appears on TWO service lines** — `gateway` and
> `cvm-identity`, which runs the `cvmid` binary out of the same artifact. Pinning
> by hand means editing **both**, to the **same** digest. Pinning only the gateway
> leaves `cvm-identity` floating on `:latest`, which is the exact hole this section
> exists to close — and in the container that runs as root with the guest-agent
> socket mounted. [Release (automated)](#release-automated) does both for you and
> refuses to publish a manifest with any gateway line still on a tag; prefer it to
> hand-editing.

```sh
# what :latest points at RIGHT NOW — compare it with the digest in the compose
# file to see whether the pin is still the current build (a difference is
# expected and fine; it just means the pin is older than the tag)
docker buildx imagetools inspect ghcr.io/0gfoundation/0g-pc-e2ee-gateway:latest

# after hand-editing: both gateway-image lines must carry the same digest and
# none may be on a tag
grep -nE '^\s*image:\s*ghcr\.io/0gfoundation/0g-pc-e2ee-gateway' deploy/phala/docker-compose.yml
```

Changing any digest changes `app_id`, which is the point: it is a new deployment,
and verifiers have to re-audit it.

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
   `image:` lines — both of them, `gateway` and `cvm-identity`, in one substitution
   so they cannot disagree — with the `@sha256:` pin; every other byte (env, ingress,
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

Running more than one CVM per side requires this; it is not a nicety. Replicas of
one `app_id` are identical CVMs running identical Prometheus agents, so their
external labels (`service`, `env`) and target labels (`gateway:9464`,
`localhost:9090`) are identical too — without a per-CVM label they write the
**same series** to the shared store and the samples collide. `app_id` additionally
separates a blue side from a green one, which `env` cannot.

Nothing inside a CVM can work its identity out for itself: the answer lives behind
the dstack guest-agent socket, and compose interpolation happens at deploy time,
before the runtime has assigned one. So a small init container,
**`cvm-identity`**, does it once at boot and exits:

```
cvm-identity ──/var/run/dstack.sock──▶ guest agent (Info)
     │
     ├─▶ /run/identity/identity.json          ──▶ gateway    (log fields + X-0G-Gateway-Instance)
     ├─▶ /run/identity/sd/gateway.json        ─┐
     └─▶ /run/identity/sd/prom-agent.json     ─┴▶ prom agent (file_sd target labels, one per job)
```

Both consumers mount the `identity` volume **read-only** and reach the guest agent
not at all. That is deliberate: the agent also derives keys and issues quotes, so
the container that holds user prompts for the life of the CVM should not be able
to reach it. `cvm-identity` runs from the **same image** as the gateway (different
`entrypoint`), so the compose gains no second digest to pin.

To be precise about what that does and does not buy: **`dstack-ingress` also mounts
this socket, and always has** — it needs it for the cert binding that the whole
attestation story rests on ([Verify](#verify)). So the socket is not exclusive to
`cvm-identity`, and this scheme does not make it so. What it does is keep the
socket off the **gateway**, and add no new long-lived holder: `cvm-identity` makes
one call and exits.

**Both** jobs get the labels the same way — as **target labels**, from their own
`file_sd` document. Nothing is labelled exporter-side, and each job needs its own
file (two jobs pointing at one document would each discover the other's target).

That uniformity is required, not tidiness. Prometheus synthesises `up`,
`scrape_duration_seconds`, `scrape_samples_scraped`,
`scrape_samples_post_metric_relabeling` and `scrape_series_added` from **target
labels alone** — they never pass through the scraped process — so a label an
exporter stamps on its own series cannot reach them. `up` is the extreme case: it
exists precisely when the exposition could *not* be read. Leaving a job on
`static_configs` would therefore leave all five byte-identical between two
replicas, putting the collision on the signal you would most want to alert on per
replica. (`client_golang` says the same thing about its own API: `WrapRegistererWith`
"should not be used to add fixed labels to all metrics exposed".)

Prometheus watches the `file_sd` paths and reloads on change, so no restart is
involved — that is what lets a container that has already exited supply them.

Failure behaviour:

- **Guest agent unreachable** → `cvm-identity` exits **0** having written both
  file_sd documents with their targets but no labels, and no identity file. Both
  jobs are still scraped, just unattributed; the gateway logs
  `dstack identity unavailable` at WARN, serves normally, and sends no
  `X-0G-Gateway-Instance`. A telemetry dimension is lost; nothing else is. Grep
  for that line after a deploy if a replica's metrics turn up unlabelled.
- **Volume not writable** → `cvm-identity` exits **non-zero**, and because both
  consumers gate on `service_completed_successfully` the app does not come up.
  That is intentional: it means the compose is wrong, and blue/green will simply
  never cut traffic to a side that never became healthy.

To attribute a *specific request* to a replica, read **`X-0G-Gateway-Instance`**
off the response. The gateway sets it unconditionally whenever it knows its own
id — the same convention as a CDN's `X-Served-By` — so it is there during an
incident without anyone having to have turned it on first. There is no switch:
the setting would have lived in the encrypted environment, so flipping it means
restarting the deployment, and a knob that is off exactly when you want it is
worse than a decision. What it discloses is the fleet shape; the id itself is
already public, since the platform routes to it by name at
`<instance_id>-443s.<PLATFORM_BASE>`.

To measure how traffic *distributes* across replicas, don't use the header —
query the metrics, which carry the same dimension and need no client-side
plumbing:

```promql
sum by (instance_id) (rate(zg_gateway_http_requests_total[5m]))
```

Note that selection happens per TCP connection, so a keep-alive client sees one
replica no matter how many requests it sends; see `blue-green.md`
"Scaling one side".

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
- **Provider verification** is on, part enforced and part verify-and-warn. Each provider's TDX
  quote is DCAP-verified (`ZG_GATEWAY_ATTEST`), its quote-bound signer is
  cross-checked against the on-chain `teeSignerAddress`
  (`ZG_GATEWAY_ONCHAIN`), and each response's §8 TEE signature is verified
  fail-closed against that signer (`ZG_GATEWAY_VERIFY_RESPONSES`). A background
  warmer (`ZG_GATEWAY_WARM`) pre-verifies quotes so requests hit a warm cache.
  Two checks only *warn*, for **different** reasons — worth keeping apart, because one
  is a switch and the other is not:
  - the **on-chain signer** check (trust-chain hop 5) is wired and observed;
    `ZG_GATEWAY_ONCHAIN_ENFORCE` is simply off, so turning it on is a config change.
  - the **boot-chain** check (hop 3) has an empty allowlist, so
    `ZG_GATEWAY_ATTEST_ENFORCE` would reject every provider. It now compares the boot
    chain (MRTD + RTMR1 + RTMR2) rather than all five registers — the same split the
    gateway's own OS-image check makes — so an entry pins one audited image instead of
    one CVM, and the allowlist can be filled. What is still open is where the values are
    published (see `trust-chain.md` hop 3).

  Response signatures are always fail-closed.
- If the gateway container is recreated with a new address, restart
  dstack-ingress too — HAProxy resolves the backend name once, at startup.
- **Zero-downtime upgrades.** A new gateway image is a new `app_id` (above), i.e.
  a separate CVM. To roll one out without downtime and with instant rollback, run
  the old and new builds as two sides and flip a single DNS pointer between them
  — see [`blue-green.md`](./blue-green.md) and [`switch.sh`](./switch.sh).
