# Phala Cloud deployment (cloud-TEE gateway)

Deploys the [`gateway`](../../client/cmd/gateway) to [Phala Cloud](https://phala.com)
via [dstack](https://docs.phala.com). This is the server-run, 0G-operated,
cloud-TEE form of the client core — see [`docs/design/cloud-gateway.md`](../../docs/design/cloud-gateway.md)
for the trust model (tier 2.5: confidential by default, cheating publicly
detectable).

## How it works

- The gateway serves **plaintext HTTP** on `:8443`. TLS is terminated by
  dstack's **ZT-HTTPS** front end *inside the enclave* — the private key is
  derived by dstack-kms and never leaves the TEE — so the container itself does
  no TLS.
- dstack's `tproxy` gateway exposes container ports at a public HTTPS URL using
  the ingress pattern:

  | Ingress hostname | Maps to CVM port |
  |------------------|------------------|
  | `<app-id>.<base_domain>` | 80 / 443 |
  | `<app-id>-8443.<base_domain>` | **8443** (this deployment) |
  | `<app-id>-8443s.<base_domain>` | 8443 with TLS passthrough (app terminates TLS — not used here) |

  So once deployed the gateway is reachable at
  `https://<app-id>-8443.<base_domain>` — point an OpenAI-compatible client's
  `base_url` there, e.g. health check: `curl https://<app-id>-8443.<base_domain>/healthz`.

## Deploy

Reference [`docker-compose.yml`](./docker-compose.yml) from the Phala Cloud
dashboard, or via the CLI:

```sh
phala cvm create --compose deploy/phala/docker-compose.yml
```

## Pin the image digest

In a TEE the compose file is **measured** into the CVM's attestation, so a
floating `:latest` tag makes the measurement change unpredictably. For a
reproducible, verifiable deployment, pin the image to an immutable digest:

```yaml
image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:<digest>
```

Get the digest for a tag with:

```sh
docker buildx imagetools inspect ghcr.io/0gfoundation/0g-pc-e2ee-gateway:latest
```

## Metrics (Prometheus)

The gateway exports Prometheus metrics, but **not on the public ingress**. It
serves `/metrics` on a separate internal listener (`ZG_GATEWAY_METRICS_LISTEN`,
set to `0.0.0.0:9464` in the compose). That port is deliberately **absent from
the `ports:` block**, so dstack `tproxy` never maps it to a public URL — it is
reachable only over the CVM-internal docker network. This keeps operational
telemetry off the same edge as the OpenAI API and avoids adding a side channel
to the confidential enclave.

Shipping the samples out follows the same shape other 0G services use — a
co-located Prometheus that scrapes locally and `remote_write`s to a central
store — but in **agent mode**:

- A `prometheus-agent` container (`prom/prometheus --enable-feature=agent`)
  scrapes `gateway:9464` over the CVM network and `remote_write`s to your
  central Prometheus/compatible store. Agent mode keeps no local TSDB and no
  query API (this CVM is ephemeral; the durable copy lives in the remote store).
- The agent also **self-scrapes**, so `remote_write` health (queue length, send
  failures) is visible even though the CVM has no local query API — important
  because an outbound break inside the enclave is otherwise hard to see.

### Remote-write credentials are a secret

The agent config carries the `remote_write` URL and its `basic_auth` password, so
it must **not** be pasted into this compose in cleartext: the `environment:`
block is *measured* into the CVM attestation and readable by anyone who can read
the compose. Instead the config is base64-encoded and injected via
`ZG_PROM_AGENT_CONFIG_B64` from a **dstack secret / KMS**, then a small init
container writes it into the shared volume before the agent starts. The compose
comments show the expected decoded `agent.yml` layout (scrape targets +
`remote_write`).

Scrape targets use docker **service names** on the CVM network: `gateway:9464`
for the app and `localhost:9090` for the agent's own metrics.

### Metric hygiene

Labels are deliberately low-cardinality and content-free (route templates, HTTP
methods, status codes, fixed outcome enums) — the same redaction discipline the
access log keeps, so metrics never leak the plaintext the E2EE seal protects. See
[`client/metrics`](../../client/metrics) for the full metric set (HTTP RED,
completion outcome by source/stage, E2EE open failures, quote verify latency,
quote/collateral cache hit ratios, and warmer liveness).

## Notes

- **No secrets or volumes for the gateway itself.** The gateway holds no pinned
  provider key: it routes per request and derives each provider's enc key +
  signer from the broker. It defaults to the 0G router; override with
  `--router-url` in the compose `command`. (The `prometheus-agent` sidecar does
  use a volume + an injected secret for its config — see Metrics above.)
- Attestation (`/quote`) is a stub until issue #19 lands; `/healthz` is live.
