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

When bringing up a **new** hostname, do the first round trip against Let's
Encrypt's staging CA by uncommenting `- ACME_STAGING=true` in the compose file —
it has to be the file, not an environment variable, because a variable the
compose does not reference never reaches the container. Every *successful*
issuance for the same hostname counts against the 5-duplicate-certificates-per-week
limit, and each fresh CVM issues again from an empty `cert-data` volume, so
iterating on production directly can leave the hostname uncertifiable for days.
Remove the line for the real certificate; note that both edits change `app_id`,
so the staging run and the production run are separate deployments.

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
is byte-identical to [`docker-compose.yml`](./docker-compose.yml) here, and that
hashing the manifest reproduces that `app_id`.

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

`app_id` hashes the app-compose manifest, which embeds this compose file
verbatim — so a floating `:latest` tag keeps the attestation identical while the
code underneath changes, and anyone who can push to the registry could swap the
gateway binary inside an "attested" CVM undetectably. Both images are therefore
pinned by digest, and both have to be re-pinned deliberately on upgrade:

```sh
# what :latest points at RIGHT NOW — compare it with the digest in the compose
# file to see whether the pin is still the current build (a difference is
# expected and fine; it just means the pin is older than the tag)
docker buildx imagetools inspect ghcr.io/0gfoundation/0g-pc-e2ee-gateway:latest
```

Changing either digest changes `app_id`, which is the point: it is a new
deployment, and verifiers have to re-audit it.

## Notes

- **Secrets.** The Cloudflare token is the only secret to supply, but the
  `cert-data` volume holds material just as sensitive — the TLS private key and
  the ACME account key. It never leaves the CVM; do not snapshot or export it.
  The `evidences` volume is public by design.
- **Attestation** comes from dstack-ingress's `/evidences/`. The gateway's own
  `/quote` route is a 501 stub pending issue #19; it is not part of this
  deployment's trust story and is not needed for the certificate binding.
- The gateway holds no pinned provider key: it routes per request and derives
  each provider's enc key + signer from the broker. The router base URL is
  `${ZG_GATEWAY_ROUTER_URL:-https://router-api.0g.ai}` — unset it (production) to
  use the 0G production router, or inject `ZG_GATEWAY_ROUTER_URL` via the CVM's
  **encrypted environment** (staging) to point at a different router. The
  variable must be listed in the app's `allowed_envs` for the override to reach
  the container. Since the *measured* text is the `${…}` form, staging and
  production share `app_id`; that is safe only because the router is untrusted by
  construction (see the provider-verification note below).
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
