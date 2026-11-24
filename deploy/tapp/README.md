# tapp (GCP) deployment — draft for the PoC

Runs the [`gateway`](../../client/cmd/gateway) in an Intel TDX Confidential VM on GCP,
under [0G tapp](https://github.com/0gfoundation/0g-tapp), **alongside** the Phala
deployment in [`deploy/phala`](../phala), which is unchanged. The infrastructure around it
(VMs, load balancer, firewall, CI) lives in a private repository; everything here is what
the attestation measures, so it is public.

Status: **draft**, for a first PoC on the `pc-gateway-staging` GCP project. Not used in
production, and not yet verifiable the way the Phala deployment is (see
[Open items](#open-items)).

## Shape

```
client ──TLS──▶ GCP global TCP proxy LB (L4: forwards bytes, never decrypts; PROXY v1)
                 │
                 ▼  this CVM (tapp, Intel TDX)
            haproxy :443 ── TLS ends here, PROXY v1 in ──▶ gateway :8443 (PROXY v2, plaintext)
                 ▲
            tls-init (one-shot): the app's KMS-derived TLS key, over the tapp socket
```

| File | Measured | What it is |
|---|---|---|
| `docker-compose.yml` | yes | three containers: `tls-init`, `haproxy`, `gateway` |
| `haproxy.cfg` | yes (uploaded because it is mounted) | TLS termination, PROXY v1 → v2, LB health port |
| `env/<target>.env` → `.env` | yes (uploaded because it is mounted) | compose variables; **no secrets** |
| `tls/fullchain.pem` | yes (uploaded because it is mounted) | CA certificate for the app's key; written by the deploy pipeline, not committed |

Every byte of these, comments included, is part of what tapp measures and the TappRegistry
records. Do not put anything secret in any of them.

## How TLS works here

- `claim-config --tls-key-source kms` makes the TLS key come from the KMS cluster as
  `(app_id, "tls")`: the same on every node of the app and stable across restarts. One CA
  certificate therefore serves every replica in every region, and a reboot or a GCP host
  maintenance does not cost a new certificate (Let's Encrypt allows 5 per week per name).
- The certificate comes from a CSR the node produces without exposing the key:
  `tapp-cli get-app-csr --app-id <id> --domain <name>`, signed by any ACME client in CSR
  mode. "Change the name, keep the key" — 0g-tapp `docs/APP_TLS.md`.
- The key reaches haproxy through `/run/<app-id>-certs`, which is tmpfs: it never touches
  disk.

## Client address

The gateway still requires a PROXY v2 header (`ZG_GATEWAY_PROXY_PROTOCOL=true`, unchanged
from Phala). The GCP proxy load balancer sends v1; haproxy reads it (`accept-proxy`) and
re-emits v2 (`send-proxy-v2`).

The header is only as trustworthy as the path to port 443: **the VPC firewall must allow 443
only from the GCP load balancer ranges** (`35.191.0.0/16`, `130.211.0.0/22`). Port 8080 is the
load balancer's health check (no PROXY header; 200 while the gateway is up, 503 otherwise).

Checked locally against the pinned haproxy image: a PROXY v1 + TLS connection reaches the
backend with the client address in a v2 header; a connection without a PROXY header is
refused; the health port turns 503 about 15 s after the gateway stops and back to 200 when
it returns.

## Deploying (PoC, by hand)

From this directory, on a claimed node (`claim-config --tls-key-source kms`):

```bash
cp env/staging.env .env
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
2. **Secrets.** Two values are secret on Phala and passed through its encrypted environment:
   `ZG_GATEWAY_CLIENT_IP_KEY` (without it the router puts every gateway user in one
   rate-limit bucket) and the full `ZG_GATEWAY_ALLOWED_ORIGINS`. Every file here is measured
   and uploaded, so neither can go in `.env`. Both are empty or defaulted for the PoC; the
   delivery mechanism is to be settled with the tapp owners.
3. **`tls-init` image.** Not pinned by digest (the registry is not anonymously readable) and
   needs `docker-login` on the node. Pin it, or build it from 0g-tapp
   `docker/tls-init/Dockerfile` and publish it ourselves.
4. **Certificate renewal.** The certificate is a mounted file, so a renewed one changes the
   measured mounts. How it reaches a running node (redeploy vs. in-place reload) is to be
   confirmed in the PoC.
5. **Metrics.** No `prometheus-agent` yet.
