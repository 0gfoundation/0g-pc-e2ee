# tapp deployment — draft for the PoC

Runs the [`gateway`](../../client/cmd/gateway) in a confidential VM under
[0G tapp](https://github.com/0gfoundation/0g-tapp), **alongside** the Phala deployment in
[`deploy/phala`](../phala), which is unchanged. Everything here is what the attestation
measures, so it is public. The infrastructure around it (VMs, load balancer, firewall, CI)
lives in a private repository.

**Cloud-neutral.** tapp runs on GCP, Alibaba Cloud and bare metal, and these files assume
none of them. What the platform must supply:

- an **L4 load balancer** that forwards TCP to port 443 without decrypting it and prepends a
  PROXY header, v1 or v2 (GCP's global TCP proxy load balancer sends v1, many others send v2);
- a **firewall** that lets only that load balancer reach 443 and 8080.

Status: **draft**. The first PoC runs on GCP (Intel TDX, project `pc-gateway-staging`). Not used in
production, and not yet verifiable the way the Phala deployment is (see
[Open items](#open-items)).

## Shape

```
client ──TLS──▶ L4 load balancer (forwards bytes, never decrypts; adds a PROXY header)
                 │
                 ▼  this CVM (tapp)
            haproxy :443 ── TLS ends here, PROXY v1/v2 in ──▶ gateway :8443 (PROXY v2, plaintext)
                 ▲
            tls-init (one-shot): the app's KMS-derived TLS key, over the tapp socket
            preflight (one-shot): no gateway without its secrets
```

| File | Measured | What it is |
|---|---|---|
| `docker-compose.yml` | yes | four containers: `tls-init`, `preflight`, `haproxy`, `gateway` |
| `haproxy.cfg` | yes (uploaded because it is mounted) | TLS termination, PROXY v1 → v2, LB health port |
| `env/<target>.env` → `.env` | yes (uploaded because it is mounted) | compose variables; **no secrets**, so a verifier can recompute its hash |
| `secrets.env` | yes, as a hash only | the gateway's secrets (`secrets.env.example`); written by the deploy pipeline, never committed |
| `tls/fullchain.pem` | yes (uploaded because it is mounted) | CA certificate for the app's key; written by the deploy pipeline, not committed |

Every byte of these, comments included, is part of what tapp measures and the TappRegistry
records. tapp publishes a mounted file's hash, not its contents, so secrets may go in
`secrets.env` and nowhere else; everything else stays public and reproducible. A hash does
not protect a guessable value: fine for a random HMAC key, weaker for a list of domains.

## How TLS works here

- `claim-config --tls-key-source kms` makes the TLS key come from the KMS cluster as
  `(app_id, "tls")`: the same on every node of the app and stable across restarts. One CA
  certificate therefore serves every replica in every region, and a reboot or a host
  maintenance does not cost a new certificate (Let's Encrypt allows 5 per week per name).
- The certificate comes from a CSR the node produces without exposing the key:
  `tapp-cli get-app-csr --app-id <id> --domain <name>`, signed by any ACME client in CSR
  mode. "Change the name, keep the key" — 0g-tapp `docs/APP_TLS.md`.
- The key reaches haproxy through `/run/<app-id>-certs`, which is tmpfs: it never touches
  disk.

## Secrets and restarts

- `preflight` checks `secrets.env` before the gateway may start: `ZG_GATEWAY_CLIENT_IP_KEY`
  must be hex of at least 32 bytes, `ZG_GATEWAY_ALLOWED_ORIGINS` non-empty. Without them the
  gateway would start healthy and degrade silently (one rate-limit bucket for everyone, no
  browser access); with the check it does not start, the health port stays 503, and the
  deploy pipeline fails. The equivalent of Phala's `CVM_REQUIRED_KEYS`.
- `tls-init` and `preflight` run once, at `start-app`. Docker restarting a container on its
  own does not rerun them, and does not need to: within a boot the key stays in `/run`
  (tmpfs) and `secrets.env` does not change, and after a VM reboot there is nothing to
  restart, since tapp recreates Docker's data-root empty at every boot.

## Client address

The gateway still requires a PROXY v2 header (`ZG_GATEWAY_PROXY_PROTOCOL=true`, unchanged
from Phala). haproxy reads whichever version the load balancer sends (`accept-proxy`) and
re-emits v2 (`send-proxy-v2`), so the gateway is the same on every platform.

The header is only as trustworthy as the path to port 443: **the platform's firewall must
allow 443 only from the load balancer** (on GCP, the ranges `35.191.0.0/16` and
`130.211.0.0/22`). Port 8080 is the load balancer's health check (no PROXY header; 200 while
the gateway is up, 503 otherwise).

Checked locally against the pinned haproxy image: a PROXY v1 + TLS connection reaches the
backend with the client address in a v2 header; a connection without a PROXY header is
refused; the health port turns 503 about 15 s after the gateway stops and back to 200 when
it returns.

## Deploying (PoC, by hand)

From this directory, on a claimed node (`claim-config --tls-key-source kms`):

```bash
cp env/staging.env .env
# secrets.env from the secret store, in the format of secrets.env.example
tapp-cli -s <node> get-app-csr --app-id pc-gateway-staging --domain <name> --out gw.csr
# sign gw.csr with an ACME client in CSR mode (Let's Encrypt staging first), then:
mkdir -p tls && cp <issued fullchain> tls/fullchain.pem
tapp-cli -s <node> <signer flags> start-app -f docker-compose.yml --app-id pc-gateway-staging \
  --register-onchain --rpc-url <rpc> --contract <TappRegistry>
```

On a node that already runs the app: `stop-app` first. After a reboot or host maintenance
the node's signer changes; with more than one node, pass `--old-signer <that node's previous
signer>` so the record is replaced (`updateNode`) rather than added (`addNode`).

## Open items

1. **Self-verification.** Phala's evidence bundle, the nonce-bound quote (`GET /evidence`),
   the identity file and the app-compose self-description all read dstack's guest agent and
   are switched off here. They need a tapp adapter in the gateway (`client/dstack`), and
   `docs/verifying-the-gateway.md` / `pcverify` need a tapp path, before this deployment can
   be verified by a third party.
2. **`env_file` upload.** `secrets.env` is mounted into `preflight` so that `start-app`
   uploads it; the PoC confirms `env_file` then finds it next to the compose.
3. **`tls-init` digest.** It holds the tapp socket, so it is pinned like every other image,
   but the registry is not anonymously readable yet: the compose carries an all-zero digest
   that fails to pull, on purpose, until the real one is filled in. The node also needs
   `docker-login` for that registry. Building it ourselves from 0g-tapp
   `docker/tls-init/Dockerfile` would remove both dependencies.
4. **Certificate renewal.** The certificate is a mounted file, uploaded at `start-app`, so a
   renewed one (about every 60 days) means a rolling redeploy of every node. Any deployment of
   the same app id can reuse the live certificate, since the KMS gives them all the same key.
   If redeploying every 60 days proves too costly, fetch the certificate at runtime instead:
   it is public and only works with the key inside the TEE.
5. **Metrics.** No `prometheus-agent` yet.
