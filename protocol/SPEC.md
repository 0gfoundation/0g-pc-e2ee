# 0G Private Computer — Protocol Spec

Normative wire spec for the 0G Private Computer end-to-end-encrypted (E2EE)
inference protocol — **confidentiality** (field-level request/response sealing)
*and* **authenticity** (attestation binding + response-signature verification).
Every implementation (Go reference here, future TS/WASM, the broker, the router)
MUST agree on it. Keywords MUST / SHOULD / MAY per RFC 2119.

> Status: draft. This cut covers the **router path**: provider discovery +
> attestation binding, **field-level request sealing (E2E confidentiality of the
> sensitive fields)**, **response sealing**, and **response-signature
> verification**, for the **chat**, **image**, **anthropic** and **speech**
> request profiles (§5.1).
> Candidate scoring is the router's own internal concern
> (surfaced through its candidate API), not part of this protocol.
>
> The multipart endpoints reach this protocol by being **JSON-ified before
> sealing** (§5.3): their request has no top-level JSON object of its own, so the
> §5.2 AAD rule (`JCS(envelope)`) and the §8 request binding have no defined
> input, and §5.3 supplies one rather than canonicalizing multipart. Of the two,
> `speech-to-text` is covered (profile `speech`, §5.3.2, §7.3); `image-editing`
> is **not** — the same mechanism fits it and only its field table is missing.
>
> Until a multipart endpoint has a profile, an implementation MUST reject a
> sealed request on it rather than forward it, and on **every** multipart
> endpoint — covered or not — a body that cannot be parsed as an envelope MUST
> NOT be treated as "not sealed" and passed through in the clear (§5.3.1).

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
| `anthropic` | `/v1/messages` | `messages`, **and `system` whenever present** | — | `messages`, `system`, `tools` | per frame shape (§7.2) |
| `speech` | `/v1/audio/transcriptions` (JSON-ified, §5.3) | `file_base64` | `response_format` = `json` (§5.3.2); `stream` **refused** when `true` (§5.3.3) | `file_base64`, `filename`, `language`, `prompt` | `text` |

A **pinned cleartext field** is one that stays readable but may hold only one
value in a sealed request. Sealing the payload does not cover it, and two
distinct reasons put a field in this category:

- Its other values direct the server to publish the *result* outside the sealed
  channel — the image profile's `response_format`, where `url` has the enclave
  serve the generated images from a plain URL. See §7.1, including why the field
  is required rather than defaulted.
- Its other values select a response this protocol **cannot express** — the
  `speech` profile's `response_format`, where `text` / `srt` / `vtt` return a
  body that is not a JSON object, so there is no frame to seal and no `aad` for
  the §8 binding. See §5.3.2.

The first is a leak, the second is an impossibility, and they are worth telling
apart when adding a profile: the first argues for requiring the field (silence
means the leak), the second does not (silence may already be the safe value) and
argues instead for a legible refusal.

A **refused cleartext value** is the weaker sibling: the field may be absent —
the endpoint's default is what the profile wants — but one specific value is
rejected. See §5.3.3 for the case (`stream` on the `speech` profile) and for why
reusing the pinned-field machinery for it rejects every conforming request.

A **conditionally required payload field** is one that need not exist, but MUST
be sealed whenever the request carries it. `system` on `/v1/messages` is the
case: Anthropic puts the system prompt at the **top level** rather than as a
message with `role: "system"`, so it is payload of exactly the same kind as
`messages` while being optional. Neither of the other two categories covers it —
required-always rejects the (common) request that omits it, and a mere default is
droppable — and getting it wrong is silent: the request seals the conversation,
passes every unconditional check, and hands the system prompt to the router in
the clear. Because the requirement depends on the request rather than on the set
of field names, it is checked where the request is in hand: by the sender before
sealing, and by the enclave on the received envelope, where a field that was
sealed is already gone and one still present therefore arrived in the clear.

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
| the top-level field CONTAINING a billable value, when a profile nests one — Anthropic's `message` (§7.2 rule 4) | no — the router bills on what is inside it | **no** — same reason as `usage`, one level down |
| `model` | no — the router attributes on it | yes — the router rewrites the alias back; the resulting value is *not* authenticated (a known trade-off, see §9 and `DefaultUnboundFields`) |
| `x_0g_trace` | n/a — router-injected | yes — nothing may trust it (§8.2) |

**The rows above are field NAMES, and that is a trap for a profile that nests.**
`unbound_fields` names top-level fields, so a rule written as "`usage` must stay
bound" protects a top-level `usage` and nothing else: a profile carrying its
billable value at `message.usage.input_tokens` satisfies that rule while leaving
the value rewritable, because the name in the denylist and the name on the wire
are different. A profile that nests a value whose *value* must be trusted MUST
therefore name the top-level field that contains it (§7.2 rule 4 does), and any
new profile MUST answer this question explicitly rather than inheriting the
general rule and assuming it reaches.

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

### 5.3 Multipart endpoints (JSON-ified requests)

Some endpoints in the OpenAI surface carry their payload as
`multipart/form-data` rather than JSON — `/v1/audio/transcriptions` and
`/v1/images/edits`. Everything in this document above assumes the request is a
top-level JSON object: §5.2's AAD is `JCS(envelope)` and §8's `reqH` hashes that
AAD, so on a multipart body there is nothing to canonicalize and no defined
binding input. That is why those endpoints were excluded rather than merely
unimplemented.

**The rule: the request is converted to JSON before it is sealed, and back to
multipart inside the enclave.** A **JSON-ified request** is a top-level JSON
object whose fields are the endpoint's form fields, with each binary part
carried as a base64 string in a named field. From §5.2's point of view it is an
ordinary request, so the AAD rule, the §6 seal/open steps, the §8 binding and
the whole §12 table apply unchanged; nothing in the crypto or the envelope is
multipart-aware, and this is **not** a version bump (§9) — it is a profile.

```
caller ──multipart──▶ sender ──JSON envelope──▶ router ──▶ enclave ──multipart──▶ upstream
                      seals here                opaque       opens here, re-materializes
```

Two properties make this the cheap direction rather than a compromise:

- **The router never sees multipart on a sealed request**, so its multipart
  handling (form-field model extraction, boundary-preserving rewrites) is not on
  the sealed path at all.
- **A multipart part header is not a place to hide anything.** `filename` travels
  as a part header in the clear today; JSON-ifying it makes it an ordinary field
  that a profile can put in its sealed set. Filenames are payload
  (`board-meeting-2026Q3.m4a`), so this is a leak the conversion closes rather
  than a cost it imposes.

The enclave re-materializes multipart for the upstream because the upstream
speaks only multipart. It MUST generate its own boundary rather than carry one
from the request (no boundary crosses the sealed channel), and it SHOULD forward
the sealed `filename` — it is inside the TEE by then, and some backends sniff the
audio container from the extension.

**Base64 encoding of a binary field is standard base64, RFC 4648 §4, padding
required** — *not* the base64url-without-padding of §3. §3 governs binary fields
that appear **on the wire in the clear** (`enc`, `key_id`, `ciphertext`), where
URL-safety and terseness matter; a binary payload field rides *inside* the
ciphertext, and its encoding is fixed here by a different constraint: the same
field name already has an unsealed contract on the router's JSON surface, and one
field name must not have two decoders depending on whether the request was
sealed.

**Size.** Base64 costs +33% and the whole body must be buffered before sealing,
so an implementation MUST bound the JSON-ified request. A future revision MAY
add a **detached** form (the envelope stays JSON; the large ciphertext travels as
a second part, bound by a hash inside the AAD-covered `_e2ee`) for payloads where
that cost matters. It is deliberately not in v1: it is additive, and the sizes
seen in practice do not need it.

#### 5.3.1 Content-Type on a multipart endpoint (fail-closed both ways)

A multipart endpoint now accepts two content types, which makes "is this
sealed?" a question the receiver MUST answer explicitly rather than by falling
through. Both halves are the **receiver's** and both are fail-closed:

- A request whose Content-Type is **JSON** MUST be a valid sealed envelope, or be
  **rejected**. It MUST NOT be forwarded as an unsealed JSON request "just in
  case".
- A request whose Content-Type is **multipart** MUST NOT contain a part named
  `_e2ee`. One that does MUST be **rejected**, never forwarded.

The second rule is the one that is easy to omit and expensive to omit. A sealed
envelope smuggled into a multipart part is not parseable as an envelope, and the
natural implementation of "detect `_e2ee`, else pass through" — parse the body as
JSON, treat a parse failure as *not sealed* — forwards it in the clear. **A body
that cannot be parsed as an envelope is not thereby an unsealed body.** This
holds on every multipart endpoint, including those with no profile yet.

#### 5.3.2 The `speech` profile

`/v1/audio/transcriptions`, JSON-ified. Fields, and where each must travel:

| Field | Kind | Sealed by default | Why |
|---|---|---|---|
| `file_base64` | base64 audio | **yes — payload field** | The audio. Voice is biometric, so this is the profile's whole point; a sealed set that omits it MUST be refused (§12) |
| `filename` | string | yes | Payload (see above) |
| `language` | string | yes | The caller's own language hint; content-adjacent and useless for routing |
| `prompt` | string | yes | A biasing text the caller writes — payload of the same kind as a chat prompt |
| `model` | string | no | The router routes and attributes on it (§5.1) |
| `response_format` | string | **no — pinned to `json`** | Below |
| `stream` | bool | **no — refused when `true`** | §5.3.3 |
| `temperature`, and any field a future upstream adds | — | no (§5.1 default) | Not content |

**A sealed speech request MUST carry an explicit `response_format: "json"`.**
The reason is structural rather than a matter of degree: `text`, `srt` and `vtt`
return a body that is **not a JSON object at all** — plain text, or a subtitle
track. There is no object to attach `_e2ee` to, so the transcript would travel in
the clear; and there is no frame for §7 to describe and no `aad` for §8's `respH`
to hash, so such a response is not merely leaky but **unverifiable**. A sealed
request cannot express those formats, which is why the field is pinned rather
than sanitized.

The pin is a **single value in v1, and that half is a scope choice, not a
requirement.** `verbose_json` is JSON-shaped and could be allowed; what it costs
is three things, none of which v1 needs:

1. The pin becomes a value **set** rather than a value.
2. A second billable-cleartext locator: `verbose_json` responses commonly carry
   no `usage` block at all, only a top-level `duration` (§7.3's required
   cleartext would have to accept either).
3. **Conditional sealing on the response side.** `segments[]` carries the
   transcript per segment and `words[]` per word, and the detected `language` is
   inferred from the audio — all payload. So the response sealed set stops being
   the constant `["text"]` and becomes "`text`, plus each of `segments` / `words`
   / `language` that the frame carries", with the matching receiver-side rule (a
   client MUST reject a frame carrying any of them in cleartext — see §7.2 rule
   6 for the same shape on the Anthropic profile).

Widening the pin later is **additive** (§9): the value set grows, the response
sealed set gains conditionally-sealed fields, and no version is bumped. Note the
product consequence of the narrow v1, which is not an engineering detail:
**pinned to `json`, a sealed transcription cannot return timestamps, so it cannot
produce subtitles.** If that is required, take the wider pin from the start.

Contrast with the image profile's pin (§7.1), which looks identical and is
argued differently. There, the field is required because **the default is the
leak** — OpenAI defaults `response_format` to `url` for the DALL·E family, so
silence publishes the images. Here the endpoint's default (`json`) is already the
safe value, so requiring the field explicitly buys no safety; it is required for
uniformity with §5.1's pinned-cleartext machinery and because an explicit value
makes the refusal of `srt` legible to the caller. A profile author reading only
§7.1 would conclude "pin because silence is dangerous"; on this profile the
reason is "pin because three of the five values are inexpressible".

#### 5.3.3 The `speech` profile is non-streaming: a refused cleartext value

`/v1/audio/transcriptions` has a streaming shape (`stream: true`, delivering
`transcript.text.delta` / `transcript.text.done` events). **The `speech` profile
does not cover it**, so a sealed speech request MUST NOT request streaming: a
sender MUST refuse to seal one, and an enclave MUST reject one it receives rather
than emit frames whose shape this document does not define.

This is a **refused cleartext value**, a construct distinct from a pinned
cleartext field, and the difference is which way absence falls:

|  | Pinned cleartext field | Refused cleartext value |
|---|---|---|
| Absent | **violation** — the server's own default applies, and the profile exists because that default is wrong | **fine** — the endpoint's default is the value the profile wants |
| Present, allowed value | fine | fine |
| Present, other value | violation | violation |
| Sealed away, or `unbound` | violation (§5.1) | violation, same reasons |

`stream` is the second: the endpoint defaults to non-streaming, so silence is
exactly what the profile wants and requiring the field would reject the common
request for no gain. Only the value `true` is refused. It MUST NOT be sealed or
declared `unbound` for the same reasons a pinned field must not be — sealing it
removes it from the cleartext the server reads, and unbinding it lets an
intermediary set it in transit while `Open` and the §8 verification both still
pass.

The refusal is because the shape is **undefined**, not because it is unsafe.
Adding it later means a frame taxonomy in the shape of §7.2 (a discriminator,
per-shape content fields, terminal shapes including `error`, and the
order-sensitive streaming `respH` of §8.1) — additive per §9, and a real piece of
work rather than a flag.

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
images; anthropic profile: **a field per event shape** — §7.2), and leaves the
rest cleartext so the router can bill
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
  value MUST be a non-negative **whole** number. An explicit `0` is a valid count
  and is not an omission; `null` is an omission and is not a zero. Fractional and
  exponent forms (`2.5`, `1e3`) are legal JSON numbers but are NOT valid counts —
  the rule is a whole number so that a producer cannot seal a value the router
  will refuse to bill.

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

### 7.2 Anthropic responses (frame-typed profiles)

The `chat` and `image` profiles repeat **one frame shape**: every frame seals the
same field. An Anthropic response does not. Its events are structurally
different from one another — some carry generated content, some are pure
sequencing — so *what a frame must seal is a property of the frame, not of the
profile*. Such a profile is **frame-typed**: it names a cleartext
**discriminator** field and maps each of its values to a shape.

For `/v1/messages` the discriminator is `type`, which Anthropic already puts in
every event payload:

| `type` | Seals | Cleartext | Ends the stream |
|---|---|---|---|
| `message` (non-streaming) | `content`, **`stop_sequence` when present** | `id`, `type`, `role`, `stop_reason`, `usage`; `model` (unbound †) | n/a — one frame, `final` by definition |
| `message_start` | — | `type`, `message` ‡ | |
| `content_block_start` | `content_block` | `type`, `index` | |
| `content_block_delta` | `delta` | `type`, `index` | |
| `content_block_stop` | — | `type`, `index` | |
| `message_delta` | `delta` (`stop_reason`, `stop_sequence`) | `type`, `usage` (`output_tokens`) | |
| `message_stop` | — | `type` | **yes** |
| `ping` | — | `type` | |
| `error` | `error` | `type` | **yes** |

† `model` is cleartext but **`unbound`**, like every other profile — the router
rewrites the served model back to the alias the caller asked for, and the
resulting value is not authenticated (§5.2, `DefaultUnboundFields`). Do not bind
it: a broker that did would fail the client's `Open` on every response the router
touched. Everything else in the cleartext column is **bound**.

‡ `message` is a **protected cleartext field** — see rule 4. On a streaming
response the billable input count lives inside it, at
`message.usage.input_tokens`.

**Two shapes end the stream.** `message_stop` closes a completed turn and `error`
closes one that failed partway — a turn that fails sends `error` and **no**
`message_stop`. So `final: true` belongs on whichever of the two actually
arrives; an enclave that recognized only `message_stop` would emit an error
stream with no final frame at all, which §7 requires the client to reject as a
truncation. (The reference implementation answers this through
`wire.IsTerminalResponseFrame` rather than leaving each enclave to hardcode it.)

Six rules make that table safe. The first two are the shape contract; the rest
exist because each is a way to satisfy the table and still leak. Rules 4 and 5
are also the two whose SCOPE matters as much as their content: a rule attached to
the shape where a field is expected, or to a field name a nested value does not
share, holds in exactly the case nobody was attacking.

1. **A shape with a content field MUST seal it.** As §7 elsewhere.
2. **A shape with no content field MUST seal nothing** — an empty
   `sealed_fields`. It is still a sealed frame: the ciphertext is over an empty
   object, so the frame still carries `_e2ee`, its cleartext is still bound in
   the AAD, and §8 still covers it. "Anything goes" is not the alternative:
   `message_start`'s `message` holds the input token count the router bills on,
   so a sealer free to seal extra on a sequencing frame could make the response
   unbillable.
3. **No frame may carry ANY shape's content field in cleartext without sealing
   it.** Rules 1–2 key off the frame's own `type`, so a frame that claims
   `message_stop` and puts the answer in a cleartext `delta` satisfies "seals
   nothing" exactly, opens cleanly, and reads to an SDK as a stray field on a
   stop event — while every intermediary has the delta. Keying this rule off the
   field *names* is what makes a mislabeled frame detectable whatever it calls
   itself.
4. **`message` is a PROTECTED cleartext field: it may not be sealed, may not be
   `unbound`, and `message.content` must be empty or absent — on EVERY frame that
   carries it, whatever the frame's shape.** All three follow from one fact: the
   billable input count is inside it, so the router must be able to read a value
   it cannot decrypt and an intermediary cannot rewrite. Sealing the field is
   worse than rewriting the count — the router then finds it on no frame at all
   and bills zero — and a legal *superset* is what makes that reachable from a
   content frame, so "seal nothing extra" (rule 2) does not cover it. The
   emptiness half exists because a cleartext container can smuggle: Anthropic's
   schema fixes `message.content` to `[]`, and an enclave that disagreed would
   ship the answer in the clear in a field an SDK actually renders.

   **The scope is the field, not the shape.** Anchored to `message_start` — the
   only shape where `message` legitimately appears — the emptiness rule held on
   exactly one shape, and a `ping` or `message_stop` frame could carry
   `message: {"content": [...]}` untouched: rule 3 does not name `message`, and
   "seals nothing" was satisfied. A profile that nests a value the router needs
   MUST declare the field once and derive every rule from it, rather than
   attaching each rule to the shape where the field is expected.
5. **The discriminator MUST stay cleartext and MUST NOT be `unbound`.** Every
   rule above keys off it, so a sealed one makes the shape unknowable and an
   unbound one lets an intermediary relabel a content frame as a sequencing frame
   — after which the receiver applies the wrong shape's rules and passes. This is
   the §12 row about a receive-side check gated on a sender-controlled value.
6. **A shape MUST seal `stop_sequence` whenever the frame carries it.** It is the
   custom stop string the CLIENT supplied in `stop_sequences`, echoed back — the
   caller's own input, not model output. The streaming path seals it already (it
   lives inside `message_delta`'s `delta`); the non-streaming shape carries it as
   a top-level field of its own and so has to name it, or the same value would go
   one way in one mode and the other way in the other. It matters exactly when a
   client adds `stop_sequences` to its request's sealed set — which §5.1's
   defaults explicitly invite — because the response would then hand back in the
   clear a value the request deliberately sealed. **`stop_reason` is deliberately
   NOT covered**: it is a model-produced enum (`end_turn`, `max_tokens`, …) with
   no caller input in it, and the router reads it; streaming seals it only
   because it shares the `delta` object with the stop string.

Rule 6 is "sensitive but optional" — the response-side twin of §5.1's
conditionally required payload field — and is checked the same way from both
ends: a field still present in the received frame's cleartext was never sealed.

An **unrecognized** discriminator value is REJECTED, not passed through: an
unknown shape may carry content and nothing about it says otherwise. Adding a
shape is additive (§9) and needs no version bump, but until a shape is added,
frames bearing it cannot be served.

**The SSE `event:` line is not the discriminator and MUST NOT be trusted.** It
sits outside the frame JSON and therefore outside the AAD, so an intermediary can
rewrite it undetected. A receiver MUST read the shape from the bound `type` field
and **rebuild** the `event:` line from it.

Two notes on the token counts. They are cleartext and bound — rule 4 is what
makes the second half of that true for `input_tokens`, whose nesting puts it out
of reach of the general rule — but they arrive on **non-final** frames and one of
them is two levels inside `message`, so unlike the image profile's
`usage.output_images` (§7.1) they are not *required* by this spec to be
**present**. Their being unforgeable and their being present are separate
properties: rule 4 settles the first, and the second is a tracked follow-up. The
failure mode if an enclave omits them is the §7.1 one exactly — a router reads
zero, cannot tell that from a genuine zero, and bills nothing.

**Client open:** `SetupBaseR(resp_enc, eph_priv, info="0g-pc/v1/resp")`, then
`Open` each frame **in order** (fail-closed), merge the decrypted `choices` back
with the cleartext fields. The client MUST receive a frame with `"final": true`
before treating the response as complete — a missing final frame is a truncation
and MUST be rejected. `final` is in the AAD, so a flipped flag is detected.

### 7.3 Speech-to-text responses

A transcription response is one non-streaming frame (§5.3.3) with `text` sealed:

```json
{
  "model": "whisper-large-v3",
  "usage": { "type": "duration", "seconds": 12.5 },
  "_e2ee": { "v": 1, "enc": "…", "sealed_fields": ["text"], "final": true, "ciphertext": "…" }
}
```

One constraint is specific to this profile, and it is the §7.1
`usage.output_images` rule with a sharper failure mode:

- **`usage.seconds` is the billable quantity and MUST be cleartext, bound, and
  present.** The router bills audio duration and cannot recover it from a sealed
  transcript. The enclave writes the duration of the audio it actually processed,
  in the `{"type": "duration", "seconds": N}` shape, where `N` is a
  **non-negative finite** JSON number. Fractional values are valid here (unlike
  §7.1's whole-number image count — audio duration genuinely is fractional);
  infinities, `NaN`-alikes and negatives are not. An explicit `0` is a valid
  quantity; `null` or an absent `usage` is an omission and is not a zero.

  The enclave MUST write it **even when the upstream response omits it**,
  deriving the duration from the audio it decoded, and MUST reject rather than
  seal a response whose duration it cannot establish. This is not the same
  obligation as forwarding the upstream's own count: on this endpoint the
  upstream commonly reports nothing, and a per-second price applied to nothing
  is not an error anywhere.

  Enforced on **both** sides. A sealer MUST refuse to emit a frame that omits it,
  and **a client MUST refuse a frame that omits it** — the half that holds when
  the enclave is not running this library.

  The receiver half matters more here than in §7.1. There, an omitted count makes
  the router bill *nothing* — wrong, but at least monotone in one direction. Here
  the router's existing behavior on a response with no usage block is to
  **estimate from the transcript text**, and under sealing that text is empty, so
  it falls through to a flat constant. An omitted duration therefore does not
  under-bill quietly; it bills a **fabricated** number that is unrelated to the
  audio and looks entirely plausible on a dashboard. Nothing downstream can tell
  that number from a real one, and only the client can refuse the frame that
  produced it.

Nothing else in the frame is sealed under the v1 pin: with
`response_format: "json"` the response body is `{"text": …}` plus `usage`, so the
sealed set is the constant `["text"]`. If the pin is widened to `verbose_json`
(§5.3.2), this section gains a second locator (top-level `duration`) and the
conditionally-sealed `segments` / `words` / `language` — with the receiver-side
rejection that makes conditional sealing enforceable.

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

A profile with a **binary payload field** (§5.3) MUST additionally pin the
encoded field value itself, from fixed raw bytes — the `speech` profile's
`file_base64` from a fixed short audio blob. Its encoding is standard base64
*with* padding while every §3 wire field is base64url *without*, so the two
conventions coexist in one implementation and a KAT over the JCS'd sealed object
alone would not catch a decoder wired to the wrong one: both alphabets accept the
other's output for many inputs, and the mistake surfaces as a corrupt payload
inside the enclave rather than as a failed `Open`. The fixed bytes MUST therefore
include at least one byte triple that encodes differently under the two
alphabets (any input producing `+` / `/`) and a length requiring padding.

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
| a conditionally required payload field present in the request is sealed — Anthropic's top-level `system` (§5.1) | yes | **yes — enclave** (it is the half that sees a third-party client's envelope, and the field's presence in the cleartext half IS the violation) |
| a frame seals its shape's content field, and a shape with none seals nothing (§7.2) | yes | **yes — client** (otherwise the content rides in the clear and Open still succeeds) |
| no frame carries another shape's content field in cleartext (§7.2) | yes | **yes — client** (this is what detects a mislabeled frame; the shape rules alone trust the sender's own label) |
| `message_start.message.content` is empty (§7.2) | yes | **yes — client** (`message` must stay cleartext for the token count, so nothing else would notice content placed there) |
| the frame discriminator is neither sealed nor unbound (§7.2) | yes | **yes — client** (an unbound discriminator makes every other shape check sender-controlled) |
| a protected cleartext field is neither sealed nor unbound, and smuggles no content — Anthropic's `message` (§7.2 rule 4) | yes | **yes — client**. Three failures, one field: a rewritten `input_tokens` verifies (as a rewritten top-level `usage` would), a SEALED `message` leaves the router billing zero, and content inside `message.content` rides in the clear. Only the client can refuse any of them, and only if the rule is anchored to the field rather than to one shape. |
| a shape's conditionally-sealed field is sealed when present — Anthropic's `stop_sequence` (§7.2 rule 6) | yes | **yes — client** (a field still in the received cleartext was never sealed, and no one else can tell) |
| a stream ends with a frame marked `final` — for Anthropic, `message_stop` OR `error` (§7.2) | sealer marks it | **yes — client** (§7 already: a missing final frame is a truncation). An enclave that treats only `message_stop` as terminal emits an error stream the client must then reject. |
| an unrecognized frame shape is refused (§7.2) | yes | **yes — both** (an unknown shape may carry content) |
| pinned cleartext field: correct value, not sealed, not unbound (§5.1/§7.1) | yes | **yes — enclave** |
| refused cleartext value absent — speech: `stream` is not `true`, and is neither sealed nor unbound (§5.3.3) | yes | **yes — enclave**. It is the only side that can decline: the alternative is emitting a stream whose frame shape this document does not define, which no receiver can then validate. Unlike a pinned field, ABSENCE is compliant — the check is on the value, so an implementation that reuses the pinned-field machinery here will reject every conforming request |
| on a multipart endpoint, a JSON-typed body is a valid envelope, and a multipart body carries no `_e2ee` part (§5.3.1) | n/a — the sender chooses one shape and uses it | **yes — enclave, both halves**. The second is the one that gets omitted: an envelope smuggled into a multipart part fails to parse as JSON, and "parse failure ⇒ not sealed" then forwards it in the clear. This is the only row whose violation leaks the payload with every other rule in this document still satisfied |
| response sealed set covers the generated content (§7) | yes | **yes — client** (otherwise the content rides in the clear and Open still succeeds) |
| `usage` not sealed (§7) | yes | client (loud either way: the router cannot bill) |
| `usage` not unbound (§5.2/§7.1) | yes | **yes — client** (otherwise a rewritten count verifies) |
| final frame carries the profile's billable cleartext — image: `usage.output_images` (§7.1) | yes | **yes — client** (a router cannot distinguish an omitted count from a zero, so it bills nothing and reports nothing) |
| final frame carries the profile's billable cleartext — speech: `usage.seconds`, written by the enclave even when the upstream omitted it (§7.3) | yes | **yes — client**, and more load-bearing than the image row. A router with no usage block on this endpoint estimates from the transcript text, which sealing makes empty, so it falls through to a flat constant: the omission does not under-bill quietly, it bills a fabricated number nothing downstream can distinguish from a real one |
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
