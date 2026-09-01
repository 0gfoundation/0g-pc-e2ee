# 0G Private Computer — Protocol Spec

Normative wire spec for the 0G Private Computer end-to-end-encrypted (E2EE)
inference protocol — **confidentiality** (field-level request/response sealing)
*and* **authenticity** (attestation binding + response-signature verification).
Every implementation (Go reference here, future TS/WASM, the broker, the router)
MUST agree on it. Keywords MUST / SHOULD / MAY per RFC 2119.

> Status: draft. This cut covers the **router path**: provider discovery +
> attestation binding, **field-level request sealing (E2E confidentiality of the
> sensitive fields)**, **response sealing**, and **response-signature
> verification**, for the **chat** and **image** request profiles (§5.1).
> Candidate scoring is the router's own internal concern
> (surfaced through its candidate API), not part of this protocol.
>
> The multipart endpoints (`speech-to-text`, `image-editing`) are **not covered**:
> their request has no top-level JSON object, so the §5.2 AAD rule (`JCS(envelope)`)
> and the §8 request binding have no defined input for them. They need their own
> section; until it exists an implementation MUST reject a sealed request on those
> endpoints rather than forward it (a body that cannot be parsed as an envelope
> must never be treated as "not sealed" and passed through in the clear).

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
sets `_e2ee.signer_addr` (the pin) and a fresh ephemeral key for the
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
    "signer_addr": "0x<40 hex>",
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
- `signer_addr` is the pinned provider's TEE signer address (§4.4); the enclave rejects a request
  whose `signer_addr` != its own `teeSignerAddress`.
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

#### Request profiles

Different endpoints carry their sensitive payload in different fields. A
**request profile** names one such request family and fixes its **payload
field** — the field a sealed envelope of that family MUST cover — plus the v1
defaults. (Distinct from the *signature* profile of §8/§9, which versions the
signed-text format.)

| Profile | Endpoint | Payload field (required) | Pinned cleartext field | Default request sealed set | Default response sealed set |
|---|---|---|---|---|---|
| `chat`  | `/v1/chat/completions` | `messages` | — | `messages`, `tools` | `choices` |
| `image` | `/v1/images/generations` | `prompt` | `response_format` = `b64_json` (§7.1) | `prompt` | `data` |

A **pinned cleartext field** is one that stays readable but may hold only one
value in a sealed request, because the other values direct the server to publish
the *result* outside the sealed channel. Sealing the payload does not cover this
— see §7.1 for the image case and why the field is required rather than
defaulted.

Whatever a profile seals, a response frame MUST leave `usage` and `model`
cleartext: the router reads them without a key to bill and attribute, so sealing
one makes the response unbillable rather than merely private.

**Cleartext is only half of it — `usage` MUST also stay BOUND, and a pinned
cleartext field MUST NOT be declared `unbound` either.** An unbound field is
excluded from the AAD, so an intermediary may rewrite it, `Open` still succeeds,
and — because the §8 binding hashes that same AAD — `respH`/`reqH` come out
byte-identical. Listing `usage` in `unbound_fields` would therefore let a router
restate the billable count with nothing detecting it, and listing a pinned field
there would let one flip `response_format` to `url` in transit and hand the
enclave a request that publishes the images in the clear. `unbound_fields` is the
one construct that can silently undo every other guarantee in this document, so
the fields whose *value* must be trusted are excluded from it by rule, not left
to the §8.2 corollary:

| Field | May be sealed? | May be unbound? |
|---|---|---|
| `usage` (response) | no — the router bills on it | **no** — its value must be authenticated |
| a pinned cleartext field (§5.1) | **no** — sealing it removes it from the cleartext the server reads, which then falls back to its own default | **no** — the pin would hold only at seal time |
| `model` | no — the router attributes on it | yes — the router rewrites the alias back; the resulting value is *not* authenticated (a known trade-off, see §9 and `DefaultUnboundFields`) |
| `x_0g_trace` | n/a — router-injected | yes — nothing may trust it (§8.2) |

**Both ends enforce this, and for the "may be unbound" column the RECEIVER is
the end that matters.** Checking only at seal time stops a conforming
implementation from misconfiguring itself; it does nothing about the case the
column exists for — a counterparty that declares the field unbound *on purpose*
so an intermediary can rewrite it while `Open` and the §8 verification both still
pass. Concretely:

- A **client** MUST reject a response frame whose `unbound_fields` names a field
  from the "no" column above — on **every frame**, since a sealer that varies the
  set could otherwise declare it only late in a stream.
- An **enclave** MUST reject a request whose pinned cleartext field is missing,
  wrong-valued, sealed, or declared unbound. It cannot delegate this to the
  client: a third-party client is under no obligation to run the check.

A request profile is **not carried on the wire and is not a version**: the
envelope format, crypto suite, AAD rule and §8 binding are identical across
profiles, and `sealed_fields` is already self-describing, so the enclave's §6
Open check (decrypted keys == declared `sealed_fields`) needs no profile
knowledge. Adding a profile is therefore additive (§9), not a `v` bump.

The guard has two independent halves, and both SHOULD be implemented:

- **Client side** — the only half that can stop a leak *before it is sent*: a
  client MUST NOT build an envelope whose `sealed_fields` omits the profile's
  payload field. (The reference library refuses to.)
- **Enclave side** — the half that does not depend on the sender's goodwill: an
  enclave serving a known endpoint SHOULD reject a sealed request whose
  `sealed_fields` omits that endpoint's payload field, since a third-party
  client is under no obligation to use the reference library. This is the same
  deployment policy as the `messages` one above, and it is what makes the
  requirement enforceable rather than merely advisory.

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
verify keys(pt) == sealed_fields; pt has no _e2ee key; no collision with cleartext; signer_addr == teeSignerAddress
reconstruct request = cleartext_fields ∪ pt
```
If `key_id` matches no current enc key, `Open` fails, or any check fails, the
enclave MUST reject (no plaintext fallback).

## 7. Sealed response envelope (v1)

The response is **field-level, symmetric with the request**: the enclave seals
only the sensitive fields (chat profile: **`choices`** — the generated content
and per-choice `finish_reason`; image profile: **`data`** — the generated
images), and leaves the rest cleartext so the router can bill
on them. Cleartext response fields (`usage`, `model`, `id`, `created`,
`system_fingerprint`) are:
- **readable** by the router (no decryption needed),
- **bound in the seal AAD**, so the client detects any tampering, and
- **covered by the TEE signature** (§8), so `usage` is authenticated to the
  client/auditor without decrypting `choices` — a lying provider is caught at
  verify. (Fee **settlement** itself is anchored by a separate on-chain-verified
  signature over the fee tuple, not by this response signature — see §8.2.)

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

### 7.1 Image responses

An image response is one non-streaming frame with `data` sealed:

```json
{
  "created": 1700000000,
  "model": "z-image",
  "usage": { "output_images": 2 },
  "_e2ee": { "v": 1, "enc": "…", "sealed_fields": ["data"], "final": true, "ciphertext": "…" }
}
```

Two constraints are specific to this profile:

- **`usage.output_images` is the billable count and MUST be cleartext.** The
  router bills per delivered image and cannot count a sealed `data[]`. The
  enclave writes the count of images it actually delivered (not the requested
  `n` — a provider may clamp it), bound in the AAD and covered by the §8
  signature, so the router bills without decrypting and a lying count is caught
  at verify. An enclave that cannot count them MUST reject rather than seal a
  response with no verifiable count.

  This is enforced on **both** sides, on the **final** frame (`usage` is a
  property of the whole response; a streaming profile may withhold it until the
  last frame). A sealer MUST refuse to emit a final frame that omits the count,
  and **a client MUST refuse a final frame that omits it** — the receiver half
  being the one that holds when the enclave is not running this library. The
  value MUST be a non-negative number; an explicit `0` is a valid count and is
  not an omission.

  The receiver half exists because omission has no loud failure anywhere else:
  a router parses such a frame perfectly well, counts zero images, and bills
  nothing. A missing count and a genuine zero are the same bytes downstream, so
  no component but the client can tell them apart, and only at open time.

  It lives inside `usage` because that is where a quantity billed on belongs,
  and is named `output_images` rather than `images` for two reasons: `usage` is
  an OpenAI-defined object (a token-billed image model such as `gpt-image-1`
  populates it with `input_tokens` / `output_tokens` / `input_tokens_details`,
  while a per-image model such as `dall-e-3` omits it entirely), so an
  extension to it should not squat an unqualified common word; and a future
  image-editing profile has *input* images, against which a bare `images` would
  read ambiguously. The `input_`/`output_` prefixes are OpenAI's own convention
  in this object. Any token fields the model reports are preserved alongside it;
  only `output_images` is written by the enclave.
- **A sealed image request MUST carry an explicit `response_format: "b64_json"`.**
  Not "must not be `url`" — **must be present and must be `b64_json`**. URL mode
  has the enclave persist the images and serve them from a plain URL, which puts
  the plaintext images (the generated content itself, a worse leak than the
  prompt) outside the sealed channel and defeats the profile.

  The field is **required, not defaulted**, because the default is the leak:
  OpenAI's `response_format` defaults to **`url`** for the DALL·E family (only
  `gpt-image-1` always returns `b64_json`). So an omitted field is a request to
  publish the images in the clear, spelled as silence — a rule phrased as "reject
  `url`" would let it through while looking correct.

  A client MUST refuse to seal a request that violates this, at seal time,
  before any ciphertext exists (`wire.SealRequestFor` does), and MUST NOT list
  `response_format` in `unbound_fields` — an unbound pin binds nothing after the
  seal (§5.1). An enclave MUST reject a violating request it receives, rather
  than silently downgrading to `b64_json` — the caller asked for a format this
  mode cannot honour and has to learn that. The enclave check is not redundant
  with the client one: it is the half that does not depend on the sender.

  The general rule this instantiates: **a cleartext field that directs the server
  to publish the RESULT outside the sealed channel is part of the profile's
  contract**, and sealing the payload is not sufficient on its own. A future
  profile that gains such a field must pin it the same way.

**Client open:** `SetupBaseR(resp_enc, eph_priv, info="0g-pc/v1/resp")`, then
`Open` each frame **in order** (fail-closed), merge the decrypted `choices` back
with the cleartext fields. The client MUST receive a frame with `"final": true`
before treating the response as complete — a missing final frame is a truncation
and MUST be rejected. `final` is in the AAD, so a flipped flag is detected.

## 8. Response signature

Each response carries a TEE signature that authenticates it as the enclave's
output for this exact request. It is a standalone artifact, fetched separately
from the response body: the response carries a `ZG-Res-Key: <chatKey>` header,
and the client GETs `<provider>/v1/proxy/signature/{chatKey}` **directly from the
provider's broker endpoint** (the router does not proxy this path). Because the
signature is content-bound and anchored on-chain, fetching it over an untrusted
path is safe — a forged or absent reply fails verification fail-closed.

The fetched `ChatSignature { text, signature, signing_address, signing_algo }`
is verified as:
1. **Parse the scheme** — `text = "<scheme>:<reqH>:<respH>"`. The scheme tag is
   inside the signed text (it cannot be relabeled by an intermediary). An
   implementation MUST reject a scheme it does not implement (fail-closed, §9).
2. **Recompute the content binding** — `reqH`/`respH` MUST equal the client's own
   hashes, computed by mode (below).
3. **Recover the signer** — `addr = ecrecover(EIP191(text), signature)` (ECDSA
   secp256k1, personal_sign).
4. **Accept only if `addr == on-chain teeSignerAddress`** — the quote-bound
   signer, grounded on-chain (§4.4 / hop 5); **never** the self-reported
   `signing_address` (a hint only).

### 8.1 Binding by transport mode

The binding hashes different artifacts depending on how the response travelled.
Every `‖` below joins only **fixed-width 32-byte** values (each variable-length
input is hashed first), so concatenation is injective — no separators, no length
prefixes. Define `H(aad, ct) = sha256( sha256(aad) ‖ sha256(ct) )`.

**E2EE (ciphertext binding)** — schemes `zg-sig-v1/e2ee-ct` (non-stream) and
`zg-sig-v1/e2ee-ct-stream` (streaming). The verifier hashes the **on-wire
artifacts it already holds** — `aad` (the JCS'd cleartext manifest minus
`unbound_fields`, §5.2) and `ciphertext` — with **no decryption and no
canonicalization of the sealed content** (both sides hash identical bytes; this
is why the sealed body is not JCS'd, §5.1; the AEAD transitively binds
ciphertext↔plaintext):

```
reqH  = H(aad_req,  ct_req)                          # request half, both modes
respH = H(aad_resp, ct_resp)                         # non-stream
respH = sha256( H(f_0) ‖ H(f_1) ‖ … ‖ H(f_{n-1}) )  # streaming, frames in send order, final last
        where H(f_i) = H(aad_i, ct_i)
```

The streaming `respH` is order-, count- and truncation-sensitive: a dropped,
reordered, or missing-final frame changes it (double-covering the §7 "final frame
required" rule).

**Plaintext (plaintext binding)** — scheme `zg-sig-v1/plain`, for a plaintext
(non-E2EE) exchange (e.g. a browser directly to the broker). There is no
ciphertext, so the binding is over the plaintext, one hash per half:

```
reqH = sha256( JCS(req) )     respH = sha256( JCS(resp) )
```

This is verified **out of band** by an auditor after the fact — a plaintext-mode
response never traverses the E2EE client — so its verifier is not part of the
E2EE client. (Streaming plaintext binding is owned by the broker/audit side.)

### 8.2 Invariant and trust

**The signature covers exactly the non-`unbound_fields` content.** `aad` is the
cleartext manifest minus the unbound set, and `ciphertext` is the sealed content
— together, everything except the intermediary-mutable fields. A party holding
only the on-wire artifacts (e.g. the router) can therefore verify an E2EE
signature and read a bound cleartext field like `usage` **without decrypting**
`choices`. **Corollary:** any value that must be cryptographically trusted MUST
NOT be `unbound` — a router-injected `x_0g_trace` is unauthenticated by
construction. Note that **response billing does not rely on this signature**: fee
settlement uses a separate on-chain-verified TEE signature over the fee tuple
(`0g-serving-broker` settlement path), so §8 exists for response authenticity and
the client/auditor's content check, not for the router to bill on.

Verification MUST be fail-closed. The signed-text format and binding are defined
once, byte-for-byte, in the shared `protocol/proof` package (imported by both the
broker signer and the client verifier) and locked by the §10 KATs.

## 9. Versioning

- `_e2ee.v`, the response `v`, the `report_data` `version`, and the signature
  **scheme tag** (§8, e.g. `zg-sig-v1/…`) are independent and each bumped on a
  breaking change to their format.
- A new HPKE suite, a new AAD/`info` rule, or a new `report_data` layout MUST bump
  the relevant version; implementations MUST reject versions they do not implement.
- The signature scheme tag is a self-describing **profile** carried inside the
  signed text: one tag pins {algo, hash, canonicalization, binding}. A breaking
  change to any of those (a different hash, the concat convention, the binding
  artifacts) bumps the profile version (`zg-sig-v1/…` → `zg-sig-v2/…`); a verifier
  MUST reject an unknown scheme fail-closed.
- **Adding a routing field, a new sealed/unbound field, or a new request profile
  (§5.1) is NOT a version bump** — cleartext fields are additive (unknown keys
  ignored by the router), `sealed_fields` is self-describing, and unbound fields
  are outside the signature anyway. Only the crypto/format envelope and the
  signature profile are versioned.
- Consumers (broker, router, client) update in lockstep with a version bump.

## 10. Test vectors

Each release MUST ship KATs so Go/TS/Rust — and the broker signer — match
byte-for-byte.

**Envelope KATs:** fixed `enc_priv`/`enc_pub`, a fixed `eph_priv`/`client_eph_pub`,
a fixed original request, the expected **JCS** of the sealed object and of the AAD,
the expected `_e2ee` (incl. `ciphertext`), and fixed response chunks with expected
`resp_enc` + frame bytes. KATs MUST pin the JCS output to lock canonicalization.

**Signature KATs (§8):** for the fixed request and response above, pin every
intermediate so the binding cannot drift between implementations — `aad`/`ct` per
sealed envelope, each `sha256(aad)` and `sha256(ct)`, `H(aad,ct)`, the per-frame
`H(f_i)` and the aggregate `respH` for streaming, the final signed `text` (incl.
its scheme tag), a broker-produced `signature` (EIP-191), and the recovered
`teeSignerAddress`. A shared fixture must exercise a known-answer recovery so the
client verifier and the broker signer are proven interoperable, not merely
self-consistent. (An initial recovery KAT against a broker go-ethereum signature
is already in `client/sig`; the full shared fixture is tracked with
`0g-serving-broker` #615.)

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

## 12. Where each invariant is enforced

Every rule above has a side that can *prevent* a violation and a side that can
only *detect* one, and they are not the same side. The recurring mistake this
table exists to stop is implementing a rule where it is convenient — the sender —
and calling it done, when the threat is a counterparty that violates it on
purpose and the only party who can refuse is the receiver.

The reading rule: **the sender's check protects a conforming implementation from
misconfiguring itself; the receiver's check is the one that holds against a
counterparty that is not conforming.** Where a rule protects one party from the
other, that party's column is the load-bearing one.

| Invariant | Sender must refuse to build | Receiver must refuse to accept |
|---|---|---|
| sealed set covers the request payload field (§5.1) | yes | **yes — enclave** (a third-party client is not obliged to check) |
| pinned cleartext field: correct value, not sealed, not unbound (§5.1/§7.1) | yes | **yes — enclave** |
| response sealed set covers the generated content (§7) | yes | **yes — client** (otherwise the content rides in the clear and Open still succeeds) |
| `usage` not sealed (§7) | yes | client (loud either way: the router cannot bill) |
| `usage` not unbound (§5.2/§7.1) | yes | **yes — client** (otherwise a rewritten count verifies) |
| final frame carries the profile's billable cleartext — image: `usage.output_images` (§7.1) | yes | **yes — client** (a router cannot distinguish an omitted count from a zero, so it bills nothing and reports nothing) |
| decrypted keys == declared `sealed_fields` (§5.1/§6) | by construction | **yes** |
| no sealed/cleartext collision (§5.1) | by construction | **yes** |
| envelope `v` / `kem_id` supported (§9) | by construction | **yes** |
| `signer_addr` is this enclave (§4.4/§6) | client pins | **yes — enclave** |
| final frame received (§7) | sealer emits | **yes — client** (its absence is a truncation). A non-streaming response is one frame, so the opener requires `final` on it directly. For a stream only the caller&#39;s read loop knows the stream ended, so that half is the caller&#39;s and cannot be delegated to a frame-at-a-time opener. |
| a receive-side check is not gated on a sender-controlled value (§7.1/§12) | n/a | **yes — client**. Obligations that fall due on the final frame are reachable only if `final` itself is checked; `final` is chosen by the sealer, so a check hung on it is a check the sender can decline. |
| frame order (§7) | sealer sequence | **yes — client** (the AEAD sequence enforces it) |
| response is sealed at all | n/a | **yes — client** (a frame with no `_e2ee` is not a sealed response) |

A new rule added to this spec MUST fill in both columns explicitly, including
when the honest entry is "cannot be checked here, and here is why".
