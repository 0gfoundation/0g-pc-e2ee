# 0G Private Computer — Protocol Spec

Normative wire spec for the 0G Private Computer end-to-end-encrypted (E2EE)
inference protocol — **confidentiality** (field-level request/response sealing)
*and* **authenticity** (attestation binding + response-signature verification).
Every implementation (Go reference here, future TS/WASM, the broker, the router)
MUST agree on it. Keywords MUST / SHOULD / MAY per RFC 2119.

> Status: draft. This cut covers the **router path**: provider discovery +
> attestation binding, **field-level request sealing (E2E confidentiality of the
> sensitive fields)**, **response sealing**, and **response-signature
> verification**. Candidate scoring is the router's own internal concern
> (surfaced through its candidate API), not part of this protocol.

## 1. Scope

v1 targets the **router path**. The request stays a normal (OpenAI-shaped) JSON:
the client **encrypts only the sensitive fields** (the prompt, tool definitions)
into a self-contained `_e2ee` object and leaves the rest — `model`, sampling
params, `stream`, etc. — as cleartext so the router can route on them. The router
selects a provider, forwards the JSON, and the broker decrypts the sealed fields
**inside the TEE**, merges them back, and runs inference. The response is sealed
back to a client ephemeral key and carries the existing TEE signature.

**Why field-level, not whole-body.** The router routes on many request
parameters, not just `model`, and must reach a provider that supports them.
Leaving non-sensitive params cleartext lets the router read them directly, so a
newly added *non-sensitive* parameter needs **no client change** — the client
passes it through untouched and the router/broker handle it server-side. The
trade-off (accepted): a *future* field that is sensitive-by-nature is cleartext
until the client's sealed-field set is updated (§5.1). Everything cleartext is
still **integrity-protected** (§5.2), so the router can read but not tamper.

The **direct path** (no router) is the degenerate case: the client already knows
the provider, so discovery collapses to a single quote fetch. Everything else is
identical. Sealing is required on the router path and optional on the direct path.

## 2. Terminology

- **Enclave** — the attested TEE (Intel TDX / Phala CVM) the provider runs in.
- **Router** — the L7 party that ranks providers and forwards the request. It
  reads the cleartext fields, never the sealed ones.
- **Sealed field** — a top-level request field whose value is encrypted into
  `_e2ee.ciphertext` (e.g. `messages`, `tools`). §5.1.
- **Cleartext field** — every other top-level request field, left readable for
  routing but integrity-protected (§5.2).
- **Candidate** — a provider the router offers, with its attestation quote and
  on-chain identity.
- **Signer key** — the provider's ECDSA (secp256k1) key; its address is the
  on-chain `teeSignerAddress`. Signs responses. (Existing.)
- **Enc key** — the provider's X25519 key used as the HPKE recipient. New.
- **Quote** — the TDX attestation, carrying 64 bytes of `report_data`.
- **JCS** — JSON Canonicalization Scheme, RFC 8785. Used to get deterministic
  bytes for the AAD and for content hashing.

## 3. Crypto suite (v1)

HPKE per **RFC 9180**, single ciphersuite in v1:

| Role | Algorithm | ID |
|------|-----------|-----|
| KEM  | DHKEM(X25519, HKDF-SHA256) | `0x0020` |
| KDF  | HKDF-SHA256 | `0x0001` |
| AEAD | ChaCha20Poly1305 | `0x0003` |

- HPKE **mode**: `mode_base` (`0x00`) in v1 — no PSK, no sender auth.
- **Request** confidentiality: HPKE `Seal` of the sealed-field object to the
  provider enc key; cleartext fields are bound as AAD (§5, §6).
- **Response** confidentiality: a **fresh HPKE `Seal` from the enclave to the
  client's ephemeral X25519 key** carried in `_e2ee` (§7). Independent of the
  request context.
- **Signatures**: ECDSA secp256k1 over an **EIP-191 `personal_sign`** digest
  (unchanged from the broker's current scheme). See §8.
- **Determinism**: all AAD and content hashes are taken over **JCS**-canonical
  JSON, so Go/TS/Rust agree byte-for-byte.
- Hashes: SHA-256 unless stated. Binary fields on the wire are **base64url**
  (no padding).

## 4. Provider enc key & attestation binding

### 4.1 Derivation
The enclave MUST derive the X25519 enc key **inside the TEE**, from a key
derivation path distinct from the signer key (e.g. dstack `DeriveKey("enc")`).
The private key MUST NOT leave the enclave. (Signer and enc are **two separate
keys**: the signer is the stable on-chain identity; the enc key can be rotated
independently for prompt forward-secrecy. See the design doc.)

### 4.2 report_data layout (64 bytes)
The quote's `report_data` MUST be exactly:

```
offset  size  field
0       32    enc_pub        X25519 public key (RFC 7748 u-coordinate, little-endian)
32      20    signer_addr    secp256k1 Ethereum address (20 bytes)
52      4     version        uint32, big-endian; = 1 for this spec
56      8     reserved       MUST be zero
```

This binds **both** keys into the same attestation, and lets a verifier extract
`enc_pub` directly from a verified quote — no side channel.

> Migration note: the broker currently writes the signer address (hex) into
> `report_data`. Adopting this layout is a breaking change gated by `version`.

### 4.3 Key id
`key_id = SHA-256(enc_pub)[0:8]` (8 bytes, base64url on the wire). Lets the
enclave select the right key across rotations.

### 4.4 Provider discovery, pin & fallback (router path)

The router **ranks** candidates on its live fleet view; the client **pins** one
and does its own **fallback loop**. The router honors the pin and forwards the
JSON opaquely — it does not re-route or decrypt. (Phase i-a of
`../docs/design/router-e2e.md`.)

**Control plane (discovery).** The client calls the router's candidate API (model
+ constraints — no body). The router returns an **ordered candidate list**; for
each, the provider's attestation **quote** and on-chain `teeSignerAddress`. The
router only transports the quote; the client verifies it independently, so a
router that returns a bogus or swapped quote is caught, not trusted.

**Client obligations before sealing.** For the candidate it pins, the client
MUST:
1. Verify the quote — genuine TDX + expected measurement (trust model in
   `../docs/design/router-e2e.md`).
2. Extract `enc_pub` + `signer_addr` from `report_data`, check `version`.
3. Confirm `signer_addr` equals the provider's on-chain `teeSignerAddress`.

Only then is `enc_pub` trusted as the HPKE recipient. The client seals (§6) and
sets `_e2ee.provider_id = signer_addr` (the pin) and a fresh ephemeral key for the
response (§7).

**Data plane.** The client sends the JSON to the router; the router reads the
cleartext fields, re-authenticates as itself (its own billing account), honors
the pin, and forwards to the pinned provider without re-routing.

**Fallback is client-side.** If the pinned provider fails, the client pins the
next candidate, re-seals to its `enc_pub`, and retries. Verification is
fail-closed: a candidate that fails quote verification is skipped, never sealed to.

> The router cannot substitute its own key: it can only offer candidates whose
> quotes bind an on-chain `teeSignerAddress`, which it cannot forge.

## 5. Request envelope (v1 wire format)

The request is the original OpenAI JSON with the **sealed fields removed** and an
`_e2ee` object added. Example (client sealed `messages` and `tools`):

```json
{
  "model": "gpt-4o",
  "temperature": 0.7,
  "max_tokens": 1024,
  "stream": true,
  "_e2ee": {
    "v": 1,
    "kem_id": "0x0020",
    "key_id": "<base64url, 8 bytes>",
    "provider_id": "0x<40 hex>",
    "client_eph_pub": "<base64url, 32 bytes>",
    "enc": "<base64url, 32 bytes: HPKE encapsulated key>",
    "sealed_fields": ["messages", "tools"],
    "ciphertext": "<base64url: HPKE seal output over the sealed-field object>"
  }
}
```

- Every original top-level field **not** in `sealed_fields` stays cleartext.
- `client_eph_pub` is where the enclave seals the response (§7). It lives in the
  AAD-protected `_e2ee`, so the router cannot swap it (that would break `Open`).
- `provider_id` is the pinned provider (§4.4); the enclave rejects a request
  whose `provider_id` != its own `teeSignerAddress`.
- `unbound_fields` (optional, omitted when empty) lists cleartext fields
  **excluded from the AAD** — intermediary-mutable metadata; see §5.2.

### 5.1 Sealed-field set

- **Sealed plaintext** = a JSON object holding exactly the sealed fields with
  their original values, **serialized as JSON**. Canonicalization is **not**
  required here: the AEAD binds the exact ciphertext bytes and the §8 signature
  binds the ciphertext, so the pre-encryption byte layout is irrelevant.
  Example: `{"messages": <original>, "tools": <original>}`.
- v1 default sealed set: **`messages` and `tools`**. On the router path a client
  SHOULD seal `messages` (leaving it cleartext exposes the prompt, defeating the
  purpose). This is a recommended default, not a protocol-enforced invariant: a
  broker MAY reject a router-path request whose `sealed_fields` omits `messages`
  as a deployment policy, but is not required to. (The reference client library
  defaults to sealing `messages` and may enforce it as a stricter local choice.)
- A client MAY seal additional fields (e.g. `metadata`, `user`); it declares them
  in `sealed_fields`.
- **New / unknown fields default to cleartext.** A field only becomes sealed when
  a client version adds it to its sealed set. (Accepted trade-off, §1.)
- After `Open`, the enclave MUST verify the decrypted object's keys **exactly
  equal** `sealed_fields`, and that no sealed field name also appears as a
  cleartext top-level field (collision → reject). It reconstructs the original
  request = cleartext fields (minus `_e2ee`) merged with the decrypted fields.

### 5.2 AAD (integrity of the cleartext)

Cleartext fields are **authenticated, not encrypted**, so the router can read but
not tamper (e.g. downgrade `model`, inflate `max_tokens`, flip `sealed_fields`).

```
aad = JCS( envelope_json with _e2ee.ciphertext AND every field named in
           _e2ee.unbound_fields removed )
```

i.e. canonicalize the entire transmitted object minus the `ciphertext` value and
minus the intermediary-mutable fields. This binds every remaining cleartext
field and every `_e2ee` metadata field. The enclave recomputes `aad` the same
way over what it received; any tampered **bound** byte makes `Open` fail-closed.

**`unbound_fields`** is a denylist (default: empty = bind everything) of cleartext
fields an intermediary may add/modify/remove:
- The list **itself** stays in `_e2ee` and is therefore bound — an attacker
  cannot enlarge it (that changes the AAD and `Open` fails), so it cannot free a
  field the client bound.
- It MUST be a JSON **array of strings**; any other type (or a non-array) is
  rejected **before** unsealing. Absent/`null` means exclude nothing.
- It MUST be disjoint from `sealed_fields` and MUST NOT name `_e2ee`.
- Values in unbound fields are **unauthenticated**: nothing may trust them (see
  §8 — the signature covers only non-unbound content).

- HPKE `info` MUST be `"0g-pc/v1/seal"` (ASCII), domain-separating this usage.

## 6. Request seal / open

**Seal (client):**
```
sealed_obj = { field: original_value  for field in sealed_fields }
pt         = serialize(sealed_obj)          // JSON; canonicalization NOT required (§5.1)
(enc, ctx) = HPKE.SetupBaseS(enc_pub, info="0g-pc/v1/seal")
// build _e2ee with everything except ciphertext, drop sealed fields from the body
aad        = JCS(envelope_without_ciphertext_and_without_unbound_fields)
ciphertext = ctx.Seal(aad, pt)
```
The client MUST retain the ephemeral private key behind `client_eph_pub` to open
the response (§7).

**Open (enclave):**
```
select enc_key by key_id; verify v, kem_id
aad = JCS(received_envelope_without_ciphertext_and_without_unbound_fields)
ctx = HPKE.SetupBaseR(enc, enc_priv, info="0g-pc/v1/seal")
pt  = ctx.Open(aad, ciphertext)          // MUST fail-closed on error
verify keys(pt) == sealed_fields; pt has no _e2ee key; no collision with cleartext; provider_id == teeSignerAddress
reconstruct request = cleartext_fields ∪ pt
```
If `key_id` matches no current enc key, `Open` fails, or any check fails, the
enclave MUST reject (no plaintext fallback).

## 7. Sealed response envelope (v1)

The response is **field-level, symmetric with the request**: the enclave seals
only the sensitive fields (v1 default: **`choices`** — the generated content and
per-choice `finish_reason`), and leaves the rest cleartext so the router can bill
on them. Cleartext response fields (`usage`, `model`, `id`, `created`,
`system_fingerprint`) are:
- **readable** by the router (no decryption needed),
- **bound in the seal AAD**, so the client detects any tampering, and
- **covered by the TEE signature** (§8), so the router can trust `usage` for
  billing **without** decrypting — a lying router/provider is caught at verify.

Sealing is a **fresh HPKE setup**, enclave as sender, `client_eph_pub` as
recipient. Streaming frames are sealed under one response context (its internal
sequence increments per `Seal`, so frames MUST be opened in order).

```
(resp_enc, resp_ctx) = HPKE.SetupBaseS(client_eph_pub, info="0g-pc/v1/resp")
// per frame, in order:
sealed_obj = { field: value  for field in sealed_fields }   // e.g. { "choices": [...] }
aad        = JCS(frame_json without _e2ee.ciphertext and without _e2ee.unbound_fields)
ciphertext = resp_ctx.Seal(aad, serialize(sealed_obj))       // no JCS on the body (§5.1)
```

Response frames may also carry `unbound_fields` (same semantics as §5.2): the
denylist of cleartext frame fields an intermediary may inject/modify — e.g. a
router that folds a trace object into the final frame. Such fields are excluded
from the AAD and, per §8, are **not** covered by the signature, so nothing may
trust them.

**Non-streaming** — the response body is one frame:
```json
{
  "id": "chatcmpl-...",
  "model": "gpt-4o",
  "created": 1700000000,
  "usage": { "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30 },
  "_e2ee": {
    "v": 1,
    "enc": "<base64url resp_enc>",
    "sealed_fields": ["choices"],
    "final": true,
    "ciphertext": "<base64url>"
  }
}
```

**Streaming (SSE)** — one event per frame; `enc` on the first, `usage` on the
final (per `stream_options.include_usage`); each event seals that chunk's
`choices` delta:
```
data: {"model":"gpt-4o","_e2ee":{"v":1,"enc":"<resp_enc>","sealed_fields":["choices"],"final":false,"ciphertext":"<...>"}}
data: {"model":"gpt-4o","_e2ee":{"sealed_fields":["choices"],"final":false,"ciphertext":"<...>"}}
data: {"usage":{...},"_e2ee":{"sealed_fields":["choices"],"final":true,"ciphertext":"<...>"}}
```

**Client open:** `SetupBaseR(resp_enc, eph_priv, info="0g-pc/v1/resp")`, then
`Open` each frame **in order** (fail-closed), merge the decrypted `choices` back
with the cleartext fields. The client MUST receive a frame with `"final": true`
before treating the response as complete — a missing final frame is a truncation
and MUST be rejected. `final` is in the AAD, so a flipped flag is detected.

## 8. Response signature (unchanged, referenced here)

Each response carries a TEE signature the client verifies **over the request and
response content**:
1. Fetch the `ChatSignature { text, signature, signing_address }` (cleartext).
2. Recompute the content binding — the SHA-256 halves in `text` MUST equal the
   client's own request/response hashes. Those hashes are taken over the **on-wire
   byte artifacts** the client already holds: the request `aad ‖ ciphertext` and
   the response `aad ‖ ciphertext`. Hashing the ciphertext (not a re-derived
   canonical plaintext) means **no canonicalization of the sealed content is
   needed** for the binding — both sides hash identical bytes — and it is why the
   sealed body is not JCS'd (§5.1). The AEAD transitively binds ciphertext↔plaintext.
3. Recover the signer: `addr = ecrecover(EIP191(text), signature)`.
4. **Accept only if `addr == on-chain teeSignerAddress`** — never the
   self-reported `signing_address`.

**Invariant: the signature covers exactly the non-`unbound_fields` content.**
`aad` is the cleartext manifest minus the unbound set, and `ciphertext` is the
sealed content — together, everything except the intermediary-mutable fields.
The router can therefore verify the signature and trust `usage` (a bound
cleartext field) for billing without decrypting `choices`. **Corollary:** any
value that must be cryptographically trusted MUST NOT be `unbound` — e.g. a
billing/trace object is only trustworthy if the enclave produces it inside the
signed content, not if a router injects it as an unbound field (in which case
trust must come from elsewhere, e.g. on-chain settlement).

Verification MUST be fail-closed. (Detailed proof-text format and the routing-proof
evolution are tracked in `0g-serving-broker` #552, specified later.)

## 9. Versioning

- `_e2ee.v`, the response `v`, and the `report_data` `version` are independent and
  each bumped on a breaking change to their format.
- A new HPKE suite, a new AAD/`info` rule, or a new `report_data` layout MUST bump
  the relevant version; implementations MUST reject versions they do not implement.
- **Adding a routing field or a new sealed field is NOT a version bump** — cleartext
  fields are additive (unknown keys ignored by the router) and `sealed_fields` is
  self-describing. Only the crypto/format envelope is versioned.
- Consumers (broker, router, client) update in lockstep with a version bump.

## 10. Test vectors

TODO. Each release MUST ship KATs: fixed `enc_priv`/`enc_pub`, a fixed
`eph_priv`/`client_eph_pub`, a fixed original request, the expected **JCS** of the
sealed object and of the AAD, the expected `_e2ee` (incl. `ciphertext`), and fixed
response chunks with expected `resp_enc` + frame bytes — so Go/TS/Rust match
byte-for-byte. KATs MUST pin the JCS output to lock canonicalization.

## 11. Replay & out of scope

**Replay (client-side, per the design doc):** the client SHOULD include a
per-request nonce in a sealed field. Its hash is bound into the signed proof (§8),
so replay of a captured proof fails the content-binding check. A server-side
timestamp/nonce in the signed text is the belt-and-suspenders fix, tracked
separately.

Out of scope for v1 (tracked):

- Candidate scoring algorithm — the router's own internal concern, surfaced
  through its candidate API (§4.4); not a protocol contract.
- A "strict" client mode that seals unknown fields **by default** (inverts the
  §5.1 trade-off for high-privacy users).
- Sender-authenticated HPKE / PSK modes.
- A server-side freshness field in the signed proof.
