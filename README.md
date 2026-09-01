# 0g-pc-e2ee

[![CI](https://github.com/0gfoundation/0g-pc-e2ee/actions/workflows/ci.yml/badge.svg)](https://github.com/0gfoundation/0g-pc-e2ee/actions/workflows/ci.yml)

End-to-end-encrypted inference on the **0G Private Computer**. Your prompt is
sealed to an attested provider enclave, and every response is signed by that
enclave — so the infrastructure carrying the request, including 0G's own router,
can route and bill it without being able to read it or forge a reply.

**"E2EE" here is the broad sense** — both halves of a secure channel to the
enclave: **confidentiality** (the prompt and tool definitions are sealed) *and*
**authenticity** (hardware attestation plus a per-response signature). Not
confidentiality alone.

## The shape of it

```mermaid
flowchart LR
    APP["your app / browser"]

    subgraph CVM["0G-operated CVM — attested"]
        direction LR
        ING["dstack-ingress<br/>TLS terminates HERE,<br/>inside the enclave"]
        GW["gateway<br/>(the client core,<br/>server-run)"]
        ING -->|"plaintext, never leaves the CVM"| GW
    end

    R["0G router<br/>UNTRUSTED — relays only"]

    subgraph PROV["provider enclave — TEE"]
        P["model inference"]
    end

    APP -->|"TLS"| ING
    GW -->|"request sealed to the provider (HPKE)"| R
    R -->|"forwards the sealed body opaquely"| P
    P -.->|"sealed response, relayed back"| R
    R -.->|"still sealed to the gateway"| GW
    P ---->|"response signature, fetched DIRECT<br/>(the router does not proxy it)"| GW
```

Two containers are omitted for clarity: `cvm-identity`, an init container that names this
replica and exits, and `prometheus-agent`. All four are inside the measured manifest — see
[`deploy/phala/README.md`](deploy/phala/README.md).

The gateway runs the **same client core** a caller would otherwise run locally — verify the
provider's attestation quote, seal the request to it, verify the signature on the way back
— just hosted, so browsers and thin clients get it with no install. The trade: one more
attested party to trust in exchange for zero client-side work, which is exactly why the
gateway publishes enough evidence to be checked rather than believed.

## Start here

| You are | Go to |
|---|---|
| **asking why the product is private** — where your prompt exists in plaintext, and who cannot read it | [`docs/why-this-is-private.md`](docs/why-this-is-private.md) — the claims and the mechanisms in three paragraphs, plus what stays visible. No tooling |
| **using a 0G-hosted gateway** and want to know whether to trust it | [`docs/verifying-the-gateway.md`](docs/verifying-the-gateway.md) — one command, what a `PASS` does and does not prove, and the same procedure by hand with `curl` / `openssl` / `jq` |
| **auditing the design** | [`docs/design/trust-chain.md`](docs/design/trust-chain.md) — every hop and where its trust bottoms out → [`protocol/SPEC.md`](protocol/SPEC.md) — the normative wire format → the **`docker-compose.release.yml` attached to a [Release](https://github.com/0gfoundation/0g-pc-e2ee/releases)**, which is the manifest actually hashed into the attestation. The [`deploy/phala/docker-compose.yml`](deploy/phala/docker-compose.yml) in git is the same file with the gateway image left on `:latest` for development — readable, but it will not match a deployment |

Those are the audiences this repository is written for, in rising depth — the first row is
the product's own answer to "why is this private", the second is how to check it, the
third is the design. The rest of it — the gateway
implementation, the deployment runbook, the load-test rig — is 0G's own engineering,
readable but not offered as an entry point.

## Layout

Two Go modules:

| | |
|---|---|
| [`protocol/`](protocol/) | the wire contract: sealing, response-signature verification, quote parsing, and [`SPEC.md`](protocol/SPEC.md), which is normative. Every participant depends on this one module so none of them can drift from the others |
| [`client/`](client/) | the client core and its forms. [`cmd/gateway`](client/cmd/gateway) is the 0G-operated, attested form that is actually deployed; [`cmd/pcverify`](client/cmd/pcverify) is the read-only verifier users run. The sidecar and in-process SDK forms exist here but are internal for now |

And four directories that are not modules:

| | |
|---|---|
| [`docs/`](docs/) | [`why-this-is-private.md`](docs/why-this-is-private.md) is the product-facing answer and [`verifying-the-gateway.md`](docs/verifying-the-gateway.md) the procedure behind it; [`design/`](docs/design/) for the trust model, the router path, and the request envelope |
| [`deploy/`](deploy/) | [`phala/`](deploy/phala/) is the CVM deployment — the source of the measured manifest, with the release/`:latest` distinction noted above; [`grafana/`](deploy/grafana/) is the operational dashboard |
| [`loadtest/`](loadtest/) | capacity measurement for the gateway. Internal |
| [`scripts/`](scripts/) | functional smoke tests against a deployed gateway — [`smoke-toolcall.sh`](scripts/smoke-toolcall.sh) exercises the tool-call path, the half of the sealed field set a prompt-only test never reaches. Internal |

## Status

**Beta.** Interfaces will change. The limits are stated in full under
[Current limits](docs/verifying-the-gateway.md#current-limits); in short:

- The hosted gateway is **tier 2.5** — cheating is *publicly detectable*, not *prevented*.
  Detection requires that somebody actually run the verification; a user who skips it is
  trusting 0G by default.
- **Endpoint identity is established for the connection that was checked.** One domain can
  be several CVMs, each with its own key, so a `PASS` does not automatically describe the
  certificate your browser negotiated.
- **Code identity is closed for the images we deploy on.** The OS-image allowlist
  ([`client/evidence/osimages.json`](client/evidence/osimages.json)) carries the deployed
  image, derived from the published guest-OS release and confirmed against a live quote. An
  image not on that list *fails*, so a new OS version needs an entry before deployment —
  and an entry added ahead of its first CVM records, in the file, what a quote has not
  confirmed yet.
- On the **provider** hop the gateway walks on your behalf, DCAP quote verification, the
  OS-image measurement allowlist, the on-chain signer cross-check and the §8 response
  signature are all **enforced** — a provider that fails any of them is refused before
  anything is sealed to it. The allowlist pins the provider's guest
  **OS image** — what runs in the containers above it is reported, not adjudicated.
  [`trust-chain.md`](docs/design/trust-chain.md) marks the status of every link.

## The other end

The protocol's provider side is [`0g-serving-broker`](https://github.com/0gfoundation/0g-serving-broker),
and the router the client seals *through* — and does not trust — is 0G's L7
aggregating router. Both are 0G's own implementations; there are no third-party
ones. So [`protocol/SPEC.md`](protocol/SPEC.md) is published to be **audited**,
not to be implemented against.
