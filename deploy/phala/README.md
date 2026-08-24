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
- dstack-ingress **produces** the evidence bundle (`quote.json`, `cert-<DOMAIN>.pem`,
  `acme-account.json`, `sha256sum.txt`) onto the shared `evidences` volume, and the
  **gateway serves it** at `/evidences/` from a read-only mount of that volume
  (`EVIDENCE_SERVER=false` / `ZG_GATEWAY_EVIDENCE_DIR` in the compose). Same path,
  same bytes, plus the `Access-Control-Allow-Origin: *` that the upstream image had no
  way to send — see [Public evidence bundle](#public-evidence-bundle-evidences) below.
  The quote's `report_data` holds
  `SHA-256(sha256sum.txt)`, and `sha256sum.txt` covers the served certificate; its
  `mr_config_id` commits to `compose_hash`, the SHA-256 of the app-compose manifest
  that embeds this compose file verbatim (`app_id` is its leading 20 bytes). So one
  quote proves *"a CVM running exactly this app-compose obtained this certificate
  inside the TEE"*, covering all four containers. See [Verify](#verify) for the steps
  the quote cannot do for you.
- The gateway also **describes itself** at `/v1/gateway/identity` — the `app_id`,
  OS image, container list and matching release read out of the same quote and
  manifest — so a browser panel can display what it is connected to. That endpoint
  is convenience, not proof: see
  [Gateway self-description](#gateway-self-description-v1gatewayidentity) below.
- And it reports what it **verified about the provider** it sealed to at
  `/v1/providers/{address}/identity` — the DCAP verdict on that provider's quote, the
  on-chain signer comparison, its `compose_hash`. Those are real verifications, made
  by this gateway on your behalf rather than by you: see
  [Provider identity](#provider-identity-v1providersaddressidentity) below.

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

### CVM shape — and the one setting that depends on it

> **⚠️ Unverified.** The intended mainnet shape is **16 vCPU / 32 GiB**, but
> nothing in this repository can confirm what a given CVM was actually created
> with — the shape is chosen at `cvm create` time, not declared in the compose.
> Confirm it against the deployment before trusting the arithmetic below.

| Setting | Value | Depends on the shape? |
|---|---|---|
| `GOMEMLIMIT` | `24GiB` | **Yes — hardcoded.** 32 GiB less ~2 for guest OS/kernel, ~1 for `dstack-ingress` + the metrics agent, ~5 of slack so the *host* never reaches an OOM kill (which takes the whole CVM, not just one container). |
| in-flight cap | derived, **~409** | Indirectly: it is `GOMEMLIMIT / 2 / ~30 MiB`, so it follows the line above. Printed as `max_inflight` on the gateway's startup line and published as `zg_gateway_inflight_limit`. |

`ZG_GATEWAY_MAX_INFLIGHT` is deliberately left unset so the cap has a single
source. Set it only to replace that arithmetic with a **measured** value — an L3
run is what produces one ([`../../loadtest/`](../../loadtest/)), and measurement
should beat estimation. Until then the signal to watch is
`zg_gateway_requests_shed_total`: any sustained non-zero rate means real traffic
is being turned away. There are no dashboard panels for it yet, so read it off
`/metrics`.
| `GOMAXPROCS` | unset | No. A CVM is a VM, so the guest sees its own vCPUs and Go reads them correctly. Only a *container CPU quota* would need it pinned. |

**On resize, `GOMEMLIMIT` must be re-derived by hand.** It is the one number here
that does not scale itself, and getting it wrong is quiet in both directions:

- **Set above physical RAM** (e.g. `24GiB` left in place on a 16 GiB CVM) and it
  stops existing — the runtime never reaches a limit it cannot allocate up to, so
  the OOM killer arrives first, and the derived in-flight cap stays sized for
  memory the CVM does not have. Both defences fail together, and the compose still
  *reads* as if they were configured.
- **Set too low** and the gateway sheds traffic it could have served, since the
  cap is derived from it.

Neither shows up as an error — the first surfaces as the container disappearing
under load, the second as `zg_gateway_requests_shed_total` climbing while the CPU
is idle. Check both after any resize.

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
explicit `-releases N` that cannot be satisfied is fatal — exit **1**, a check that could
not be made, not exit 2, which is reserved for a mistake in the invocation. Passing
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

## Public evidence bundle (`/evidences/`)

The four files are **produced by dstack-ingress** and **served by the gateway**. Two
compose settings make that split:

| Setting | Container | Effect |
|---|---|---|
| `EVIDENCE_SERVER=false` | dstack-ingress | stops its built-in `mini_httpd` **and** the HAProxy path ACL in front of it. Bundle *generation* is unconditional upstream, so the volume's contents are unchanged. |
| `ZG_GATEWAY_EVIDENCE_DIR=/evidences` | gateway | serves that volume (mounted `:ro`) at `/evidences/`, with `Access-Control-Allow-Origin: *`. |

**Why.** The upstream ingress image sends no CORS header on those responses and
exposes no knob to add one — it is a pinned digest — so no web page could read the
bundle whose entire purpose is public verification ([#73](https://github.com/0gfoundation/0g-pc-e2ee/issues/73)).
`curl` and `pcverify` were unaffected, which is why it stayed invisible. The move
also drops a connection-level routing quirk: the HAProxy ACL matched on the **first
16 bytes of a connection**, so on a reused keep-alive connection a bundle fetch and
an API call could not both be served.

**Why the wildcard is safe, and why it is separate from `ZG_GATEWAY_ALLOWED_ORIGINS`.**
The bundle is static public data with no cookie, no credential, and no per-caller
variation; `*` is mutually exclusive with `Access-Control-Allow-Credentials`, so
browsers send these requests without ambient credentials. Anyone can already `curl`
the same bytes. The origin allowlist, by contrast, governs *who may drive sealed
inference through the enclave* — a narrower, trust-relevant decision — so the two
policies are deliberately not the same list, and the evidence route is wired ahead of
the CORS middleware rather than through it.

**Why serving it from the gateway is not a trust regression.** The bundle is
self-authenticating: the quote is TDX-signed, its `report_data` commits to
`sha256sum.txt`, which covers the certificate and the ACME account, and the
endpoint-binding step compares the published certificate against the one the
caller's *own* TLS session negotiated. Tampering fails verification and withholding
fails closed, so which container hands over the bytes is not part of what is proven.
The mount is read-only: the container that serves the bundle cannot rewrite what the
ingress attested to.

**Operationally:** files are read per request, so a certificate renewal is picked up
with no restart. `pcverify` and every published `curl` recipe are unchanged — the path
is `/evidences/` and must stay there; it is hardcoded in `client/evidence` and in
third-party verifiers.

**What a first deploy looks like.** The gateway comes up before dstack-ingress has
finished its first ACME run (it must — the ingress gates on the gateway's health), so
for the first minutes the bundle is empty. In that window:

| request | answer |
|---|---|
| `/evidences/` | **200** with an empty directory index — *not* a 404 |
| `/evidences/quote.json` | 404, and likewise for the other three files |

(Previously HAProxy answered 503 here, because the ingress does not start its evidence
server until the bundle is finalized.) A file that exists but the gateway cannot read
answers **403**, not 404 — so the access log separates "not written yet" from "written
and unreachable" without anyone having to guess.

**Fail-loud on a bad mount.** A `ZG_GATEWAY_EVIDENCE_DIR` that is missing, not a
directory, or unreadable **fails the gateway's boot** rather than serving 404s quietly:
an unreachable bundle has no signal otherwise, which is how #73 survived as long as it
did. The check also opens `quote.json` and `sha256sum.txt` when they exist, because
upstream chmods 644 onto `acme-account.json` and `cert-<DOMAIN>.pem` but writes those
two with a bare shell redirect — their mode rides the ingress container's umask, so
they are the two the gateway's `nonroot` uid could lose access to without anything else
changing, and they are the two that matter most (the quote, and the manifest its
`report_data` commits to). Absent files are skipped, so the empty and partially-written
states above still pass; it is presence and readability only, never contents. Note it
is a *boot*-time check: a renewal rewrites both files under the same umask, so a mode
regression at ~60 days shows up as 403s rather than a failed boot. Note also the blast
radius — the gateway exiting takes the endpoint down entirely, not just this route,
which is the right trade for a path that sits in the measured compose next to the
volume it names (a mismatch is a deploy error, caught on the first staging boot), but
it is why the check stays that narrow.

**Still browser-unreachable:** endpoint binding. JS cannot read the peer certificate
of its own TLS connection — no API exposes it — so a web page can establish *code*
identity from the bundle but not *endpoint* identity. `pcverify` remains the only
complete check.

Neither variable is a `${…}` reference, so **`allowed_envs` is unchanged** and blue /
green stay identical on that axis (`blue-green.md`). Both sides do need the same
compose, as always. Smoke-test after deploying:

```sh
# the header must be present, and identical from any origin (or none)
curl -sSI -H 'Origin: https://example.invalid' "https://<DOMAIN>/evidences/quote.json" \
  | grep -i access-control-allow-origin      # expect: access-control-allow-origin: *

# and the unchanged command-line path must still work end to end
pcverify -gateway <DOMAIN>
```

## Gateway self-description (`/v1/gateway/identity`)

A public, unauthenticated route that answers "what is this CVM?" in one request, so a
browser panel can show it without reimplementing `pcverify` in JavaScript — which it
could not do anyway, since JS cannot see its own connection's peer certificate
([#78](https://github.com/0gfoundation/0g-pc-e2ee/issues/78)).

| Setting | Container | Effect |
|---|---|---|
| `-out-app-compose /run/identity/app-compose.json` | cvm-identity | publishes this CVM's `app-compose.json` verbatim on the shared `identity` volume, from the same guest-agent call that yields the identity file. |
| `ZG_GATEWAY_APP_COMPOSE_FILE=/run/identity/app-compose.json` | gateway | where the container list comes from. Spelled out here, not defaulted in the binary, because the path is a contract between containers: it appears three times in the compose, and splitting it between YAML and Go is how a renamed volume becomes a silently empty list. |
| `ZG_GATEWAY_PLATFORM_BASE_DOMAIN=${GATEWAY_DOMAIN}` | gateway | fallback source for the same manifest, consulted only when the file is unreadable. Empty disables it. |

Two more knobs are left at their built-in defaults and appear in the compose only as
commented-out lines, per this file's convention of stating what *differs* from the
default: `ZG_GATEWAY_IDENTITY_ENDPOINT` (on — set `false` to remove the route
entirely) and `ZG_GATEWAY_IDENTITY_RELEASES` (`5`, matching pcverify's own default —
set `0` for a CVM with no egress to GitHub, which then reports `matched_release:
null`).

**It is not evidence, and the code is written to keep it that way.** The gateway signs
nothing here and does not DCAP-verify its own quote; the response carries no
`"verified"` field. Every value is independently rederivable with `pcverify -gateway
<DOMAIN>`, which is the artifact to point anyone at who asks whether it is *true*
rather than what it *is*. See `docs/verifying-the-gateway.md` and
`client/cmd/gateway/identity.go`.

**Assembled once, in the background.** Nothing blocks startup and nothing is computed
per request: the document is built after boot, cached in memory, and served with
`Cache-Control: public, max-age=300`. A source that is not available yet — the quote
appears only after dstack-ingress's first ACME run — is retried with backoff, and the
route answers 200 with `null` fields meanwhile. It never 500s, and it never consumes a
slot from the sealed path's in-flight cap.

**The container list is hash-checked before it is published.** The `app-compose.json`
must hash to the `compose_hash` in the quote; a mismatch (a stale volume, a redeploy
whose init container did not re-run) reports `containers: null` and logs an error
rather than publishing a list from unauthenticated bytes.

**CORS differs from `/evidences/` on purpose.** The bundle answers every origin (`*`)
because any verifier must be able to fetch it; this route rides
`ZG_GATEWAY_ALLOWED_ORIGINS` instead, since it is a convenience for the first-party
panel and its values are always obtainable from the bundle regardless.

`GATEWAY_DOMAIN` was already referenced by dstack-ingress, so **`allowed_envs` is
unchanged**. Smoke-test after deploying:

```sh
curl -s "https://<DOMAIN>/v1/gateway/identity" | jq

# the app_id it reports must be the one pcverify derives from the quote
pcverify -gateway <DOMAIN>
```

## Provider identity (`/v1/providers/{address}/identity`)

The provider half of the same panel: what this gateway **verified** about the provider
it sealed a request to
([#80](https://github.com/0gfoundation/0g-pc-e2ee/issues/80)). The address to ask about
is the one the response carried in `X-Provider`.

No new setting is required — the route is on by default and reads results the request
path already produced. Three settings govern whether it can answer anything, and what
it can say:

| Setting | Effect |
|---|---|
| `ZG_GATEWAY_ATTEST` | **required.** Without quote verification nothing is verified, so there is no verdict to report and the route is not mounted at all. |
| `ZG_GATEWAY_ONCHAIN` | when off, `verdicts.onchain_signer` is `not_checked` rather than a comparison result. When on but the chain could not be read, it is `unavailable` — a chain-RPC problem is never reported as a finding against the provider. |
| `ZG_GATEWAY_PROVIDER_IDENTITY_ENDPOINT` | on by default; set `false` to remove the route entirely. Appears in the compose only as a commented-out line, per this file's convention. |

**This endpoint does report verdicts, unlike the self-description above — and that is
the intended difference.** There the gateway describes *itself*, so a verdict would be
self-vouching; here it reports a DCAP verification and an on-chain signer comparison it
genuinely performed on a *third party* before sealing a user's prompt to it. They are
still **relayed** verdicts: they are worth what the reader's verification of this
gateway is worth (`pcverify -gateway <DOMAIN>`), which is why every response carries
that caveat inline and a panel must render them as "the gateway verified this for you".

**It fetches nothing.** Only providers this gateway has checked while serving a request
are reportable, records expire after a few minutes, and no address triggers a quote fetch — so the route cannot be
turned into a quote proxy or a fleet scanner. It returns no raw quote and no
measurement registers either: anyone wanting to re-verify should fetch the quote direct
from the provider, and the `verify` field names that URL.

**`containers` lists what `compose_hash` commits to** — the provider's services in
file order, each with its image and the digest the compose pins. It is populated only
when the app-compose in the provider's quote reply hashes to the `compose_hash` in its
verified quote; a mismatch, a reply that carries no app-compose, or an unparseable
manifest all report `null` (never `[]`, which would claim the enclave runs no
containers). An entry with an **empty digest** is worth reading: that image is pinned
by tag, so `compose_hash` commits to a name whose contents can be republished under
it. There is no `source` label here, unlike the gateway's own list — no per-provider
manifest is published, so there is no release to trace an image back to.

Expect `verdicts.measurement: "no_baseline"` on every deployment today — that is hop
3's empty audited allowlist (`docs/design/trust-chain.md`), the same gap `pcverify`
reports as an incomplete run, and it must be rendered as "observed only" rather than as
a failure. Smoke-test after deploying:

```sh
# the address the sealed request was pinned to
ADDR=$(curl -sSD - -o /dev/null -X POST "https://<DOMAIN>/v1/chat/completions" \
  -H "Authorization: Bearer $ZG_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"…","messages":[{"role":"user","content":"hi"}]}' \
  | awk 'tolower($1)=="x-provider:"{print $2}' | tr -d '\r')

curl -s "https://<DOMAIN>/v1/providers/$ADDR/identity" | jq
# an address never used must 404
curl -sS -o /dev/null -w '%{http_code}\n' "https://<DOMAIN>/v1/providers/0x0000000000000000000000000000000000000000/identity"
```

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
- **Attestation** comes entirely from dstack-ingress's evidence bundle — it *produces*
  every byte of it, including the quote; the gateway only *serves* the finished bundle
  over HTTP (see [Public evidence bundle](#public-evidence-bundle-evidences), and note
  that a self-authenticating bundle does not trust whoever transports it). The gateway
  emits no quote of its own and signs no responses of its own: its `app_id`-covered
  image is already attested by the ingress cert-binding quote, and inference
  authenticity rides each provider's own SPEC §8 signature (verified via
  `ZG_GATEWAY_VERIFY_RESPONSES`). See
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
    Read `onchain_grounding_total` from `/metrics` before flipping it: warn mode is
    the baseline that says whether enforce is safe here, since every outcome other
    than `ok`/`ok_stale` becomes a skipped candidate. The negatives are counted apart
    because they need different responses — `mismatch`/`not_acknowledged` are verdicts
    about the provider and are what enforce is for, while `lookup_failed` is our own
    chain RPC. Both fail-closed under enforce, with no opt-out for the second, so
    enforce means the chain was actually read rather than merely consulted; if a
    chain-RPC outage ever has to be ridden out, the lever is turning enforce off. A
    blip will not get that far — `eth_call` retries, the reading is cached 5m, the
    warmer refreshes ahead of expiry, a 30m grace window serves the last known-good
    value, and a 30s cooldown after a failed lookup keeps an ongoing outage from
    costing every request the retry budget — so watch `lookup_failed` and
    `warmer_signer_refreshes_total{result="failed"}` for the sustained case. A provider
    is never rejected on a stale or cached reading without a live re-read first, so a
    broker upgrade rotating its signer does not read as an attack (see
    `trust-chain.md`, "What hop 5 concludes, and what it does not"). Read a `mismatch`
    together with the log line beside it rather than on its own: the counter cannot say
    whether the recovery re-verification ran, and only a mismatch that survived one is
    an accusation. The three are logged apart — "could not re-verify … the mismatch
    stands on the cached quote" (throttled or the quote fetch failed), "the cached quote
    had rotated" (benign, and it resolves), and "the quote signer had not rotated and
    the mismatch stands" (live quote, live chain read, still disagreeing).
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
- **When a PROVIDER upgrades its broker**, expect a brief window where that
  provider is skipped, and order the rollout to keep it brief. A broker upgrade
  rotates the provider's `enc_pub` and `signer_addr` together and changes its
  measurement, while the on-chain registry has room for exactly one
  `teeSignerAddress` — so it cannot mark old and new both valid, and the chain and
  the quote necessarily disagree for a moment in whichever order the provider does
  it (`trust-chain.md`, "What is *not* in the trust chain"). The gateway narrows
  that window by re-reading live rather than ruling on a cached value, and cannot
  close it. So:
  1. **Update the measurement allowlist before the rollout.** New code means new
     MRTD/RTMR values, and with `ZG_GATEWAY_ATTEST_ENFORCE` on an unlisted boot
     chain rejects the upgraded broker outright. (The allowlist is empty and
     enforce is off today, so this is a future dependency, not a live one.)
  2. **Keep the on-chain acknowledgement close to the roll** — the gap between the
     two is the window.
  3. **Expect the provider to be skipped during it.** With several providers
     registered, candidate fallback covers it; **a single-provider deployment has
     no fallback**, so there the window is user-visible and wants scheduling.
