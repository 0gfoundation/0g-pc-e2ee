# Request envelope & integrity model — design notes

Scope: the **field-level semantics** of the v1 request envelope and the
**integrity (AAD) model** that binds them. This refines `protocol/SPEC.md` §5–§6
and is a companion to [`router-e2e.md`](./router-e2e.md) (which covers the
*deployment* / trust-boundary and migration story — not repeated here).

> Status: **design notes, pre-launch.** Items marked 🆕 are decisions taken in
> discussion that are **not yet in `SPEC.md` or the code**; everything else
> describes what exists today. `SPEC.md` remains normative once these land.

---

## 0. Background: what the AAD actually protects

Two things are easy to conflate, so state them plainly:

1. **The sealed body's confidentiality & integrity do *not* depend on the AAD.**
   The AEAD auth tag protects the ciphertext unconditionally — even with an empty
   AAD, `messages`/`tools` stay secret and tamper-proof.
2. **Cleartext fields are tamper-evident *only* because they are bound as AAD.**
   A cleartext field that is not in the AAD can be added / changed / removed by
   any intermediary, undetectably.

So "is the AAD necessary?" → only for the cleartext fields whose integrity you
care about. That is the entire lever this document turns.

### Why JCS (canonicalization) is in the path

The AEAD authenticates *exact bytes*, but JSON is not byte-unique (key order,
whitespace, number/string encoding all vary). JCS (RFC 8785) maps a logical JSON
value to one canonical byte string, which is needed because:

- an **untrusted router** may parse and re-serialize the cleartext while routing;
  canonicalization lets a *benign* re-serialization survive while *tampering*
  still fails closed;
- **Go / TS / Rust** implementations must derive identical bytes (see the TS
  browser build in `client/sdk/ts`);
- the **§8 content hash** must match across the parties that compute it.

Reasons 1 and 3 are language-independent, so JCS does not go away just because
only Go ships today.

> **Perf motivation for D1.** Profiling `SealRequest` shows `canonicalJSON`
> dominates at large payloads (~40% CPU, ~65% of allocations at a 1 MiB body;
> ~3.7× / ~16×-alloc headroom if the body's *pre-encryption* canonicalization is
> dropped). The AEAD and the X25519 handshake are comparatively cheap. That cost
> is what D1 targets — without weakening the AAD, which stays over the (small)
> cleartext manifest.

---

## 1. Three categories of request field

| Category | Examples | Router can read? | Router can modify? | Who trusts the value |
|---|---|---|---|---|
| **① Sealed** (encrypted) | `messages`, `tools` | no (only after `Open`) | no — tamper → tag fails | fully trusted |
| **② Cleartext + bound** (default) | `model`, `temperature`, `max_tokens`, `stream` | yes (routing / billing) | no — tamper → AAD fails closed | fully trusted |
| **③ Cleartext + unbound** 🆕 (listed in `unbound_fields`) | `x_0g_trace`, `route_options` | yes | **yes** — freely | **not trusted** — trust must come from elsewhere (the TEE signature), never from the AAD |

`model` stays in **②** (see D2): the router may *read* it to route but not
rewrite it; alias resolution moves to an endpoint inside the trust boundary.

Category ③ is the new construct. Its members are, by definition, unauthenticated
by the transport crypto — so nothing security-relevant may depend on them.

---

## 2. The request envelope, field by field

**Caller's original OpenAI request:**

```json
{
  "model": "glm-5.1",
  "temperature": 0.7,
  "max_tokens": 1000,
  "stream": true,
  "messages": [{"role":"user","content":"the confidential prompt"}],
  "tools": [{"type":"function","function":{"name":"calc"}}]
}
```

**On the wire after `SealRequest` (`messages`/`tools` removed and sealed):**

```json
{
  "model": "glm-5.1",
  "temperature": 0.7,
  "max_tokens": 1000,
  "stream": true,
  "_e2ee": {
    "v": 1,
    "kem_id": "0x0020",
    "key_id": "9Qk2…",
    "provider_id": "0x992e6396157Dc4f22E74F2231235D7DE62696db5",
    "client_eph_pub": "Uj3f…",
    "enc": "b0aZ…",
    "sealed_fields": ["messages","tools"],
    "unbound_fields": ["x_0g_trace"],
    "ciphertext": "k7Xp…"
  }
}
```

### `_e2ee` field dictionary

| Field | Meaning | Notes |
|---|---|---|
| `v` | Envelope version (`1`). Defines the whole byte contract. | Changing its semantics is a **breaking** bump (v2), coordinated across broker+client — even if wire bytes look unchanged. |
| `kem_id` | HPKE KEM id. `0x0020` = DHKEM(X25519, HKDF-SHA256). | Pins the suite on the wire; unknown → reject (anti-downgrade). |
| `key_id` | `base64url(SHA-256(enc_pub)[0:8])`. **Selector** for which recipient key this is sealed to. | Lets the recipient pick the right private key across rotation. Not secret. |
| `provider_id` | The pinned recipient's on-chain signer address (`0x…`). Client asserts "I sealed to *this* provider/gateway." | Recipient checks `provider_id == self`; a router cannot silently reroute to another provider. **Bound.** |
| `client_eph_pub` | Client's **ephemeral** X25519 public key; the enclave seals the **response** to it (§7). | Stored at request time, used at response time. **Must be bound** — else a MITM swaps its own key and reads the response. |
| `enc` | HPKE **encapsulated key** (sender's ephemeral KEM output). Recipient derives the shared secret from `enc` + its private key. | **Bound.** |
| `sealed_fields` | **Allowlist** of which fields were encrypted. After `Open`, decrypted keys must equal this set exactly; must include `messages`. | **Bound** — prevents lying about what was sealed. D6 🆕 flips the *default*: seal all except a declared `visible_fields` set (this list stays as the post-`Open` check). |
| `unbound_fields` 🆕 | **Denylist** of cleartext fields intermediaries may add/modify/remove; these are **excluded from the AAD**. Everything else (except `ciphertext`) is bound by default. | The **list itself is bound** (it lives in `_e2ee`), so a router cannot enlarge it. Must be disjoint from `sealed_fields`. |
| `ciphertext` | AEAD output (sealed body + tag), base64url. | The one field **always** excluded from the AAD (can't bind the ciphertext into its own AAD). |

---

## 3. The AAD formula 🆕

```
AAD = JCS( envelope
           − _e2ee.ciphertext                    # always excluded
           − { top-level fields named in _e2ee.unbound_fields } )
```

- Everything else — category ② fields plus all `_e2ee` metadata except
  `ciphertext` — is bound.
- Subtlety: the **names** in `unbound_fields` are bound; the **values** of the
  fields they name are not. So the router may write `x_0g_trace`'s value but
  cannot add `model` to the list.

Today (`aadFromEnvelope`) the formula is just "envelope − `_e2ee.ciphertext`".
D3 generalizes the exclusion to also drop the declared unbound set.

---

## 4. Decisions

### D0 — the router is blind to prompt & completion by default 🆕
The seal boundary is **client ↔ provider enclave**; the router is a blind
forwarder that reads only the cleartext manifest and never the prompt or the
completion. This is the framing decision the rest depend on. Consequence: any
feature that must read/rewrite prompt or completion content — web-search
injection, file/attachment expansion, response `model`/annotation/`reasoning`
rewriting — does **not** run at the router. It moves either client-side (before
seal / after open) or to a dedicated attested TEE node. The router keeps only
routing, billing off cleartext manifest + response `usage`, and provider auth.

### D1 — the §8 content hash binds produced/decrypted bytes, not a re-derived canonical form 🆕
The plaintext body is JCS-canonicalized today only to feed the §8 signature hash;
the AEAD already protects exact bytes. If §8 hashes the bytes **as produced by
the client and decrypted by the enclave** (both see the identical byte string via
the AEAD) instead of an independently re-canonicalized form, the expensive body
pass disappears. **Get this right now (pre-launch) — defining it wrong and fixing
later is a v2 break.** The AAD over the cleartext manifest is unaffected and stays.

### D2 — `model` stays bound; alias resolution moves to an endpoint 🆕
Letting the router rewrite `model` would let a compromised router silently
downgrade the served model, undetectably — fatal for a verifiable-inference
product. Keep `model` in category ②. Resolve aliases (`glm-5.1` → provider's
canonical model id) **client-side before sealing** or **in the enclave after
`Open`**, never at the router. The response signature attests what actually ran.

### D3 — AAD binds everything except a declared unbound set (denylist, not allowlist) 🆕
Choose **bind-all-except** over **bind-only-these**. Rationale:

- **Secure by default.** An omission fails *closed* (a benign mutation is
  rejected) rather than opening a silent tamper hole. An allowlist's default
  (empty) binds nothing.
- **Small, auditable list.** The set of intermediary-mutable fields is a short,
  reviewable statement of exactly what may change; an allowlist would have to
  enumerate every routing/billing-relevant field and miss one.
- **Future-proof.** A field added later is bound automatically; you relax it only
  by a conscious opt-out.

### D4 — the unbound-set is authenticated; unbound fields are untrusted 🆕
The `unbound_fields` list must live inside the authenticated region (it does, in
`_e2ee`, covered by the AAD) so an attacker cannot enlarge it — otherwise the
attack merely moves from "change the field" to "add the field to the ignore
list." Corollary: any value in an unbound field is **untrusted**. `x_0g_trace`
billing data is fine to carry in the body, but it is only trustworthy if the
party that folds it in is inside the TEE and it rides inside the **signed**
response (or is settled on-chain) — the AAD gives it no protection.

### D5 — the response envelope mirrors D3/D4 🆕
The response `_e2ee` needs the same `unbound_fields` denylist, declaring exactly
what an intermediary may touch on the return path (e.g. an injected
`x_0g_trace`). Same red line: the list is bound; unbound response fields are
untrusted unless signed. Note that under D0 the router does **not** rewrite
response *content* (`model`, annotations, `reasoning` mirroring); any such
transform moves inside the trust boundary — the denylist is for genuinely
intermediary-owned metadata only.

### D6 — seal by default; declare an explicit *visible* allowlist (fail-closed confidentiality) 🆕
The mirror of D3, for confidentiality. Today `sealed_fields` is an allowlist of
what gets **encrypted**, so unknown/new fields default to **cleartext** —
fail-*open*, a silent leak (a future `user` / `metadata` field carrying PII).
Flip it: the sealed set is the **complement of a declared `visible_fields`
allowlist**, computed over the fields actually present, so anything not
explicitly exposed is sealed — including fields this client version has never
heard of. Guard: `messages` may never appear in `visible_fields`.

The router routes on the **generation parameters** (the fleet is heterogeneous —
not every machine supports every param), so `visible_fields` is not small: it
includes `model`, `temperature`, `max_tokens`, `top_p`, `stop`, `stream`,
`response_format`, … The sealed set is therefore the **content** (`messages`,
`tools`) plus any **non-routing / user-identifying** field (`user`, `metadata`,
and — the real point — any field this client version does not yet know about).

So D6's practical effect is **narrow and honest**: it does *not* seal more of the
known routing params (those are legitimately visible); it flips the *default* for
the sensitive/unknown remainder from cleartext to sealed, closing the PII-leak
path (a future `user`/`metadata`) that today's `sealed_fields` allowlist leaves
open. Err toward sealing: forgetting to expose a needed routing param breaks
routing loudly (fail-closed), never leaks. (`sealed_fields` may stay on the wire
as the post-`Open` integrity check; the *default* is defined by `visible_fields`
— encoding detail for SPEC.)

**Read ≠ mutate.** A visible param is still **bound** (category ②): the router
reads it to route but may not rewrite it — else it could downgrade your sampling
or cap `max_tokens` undetectably. A field the router genuinely *rewrites* today
(e.g. forcing `stream_options.include_usage=true`) must therefore be either
listed in `unbound_fields` (low-stakes, untrusted) or — cleaner — set by the
client up front so no rewrite is needed.

**Explicit declaration vs default policy — keep them separate.** "Marking the
partition" never goes away: the seal/cleartext split must be declared
*explicitly and bound* on the wire so the enclave can verify it and no
intermediary can shift a field across the line. What D6 changes is only *which*
list is authoritative. Make `visible_fields` the single bound allowlist: the
sealed set is then "everything present that is not visible (nor `_e2ee`)", so an
unknown field is sealed (fail-closed). `sealed_fields` is derivable from it
(= present − visible − unbound) and need not be sent separately — the enclave
verifies the partition against the bound `visible_fields`. So yes, mark the
boundary explicitly; just enumerate the *visible* set, because that is the
enumeration that fails safe.

Secure-default summary — two mirror-image declarations:

| Dimension | Declares | Default | A new/unknown field is |
|---|---|---|---|
| Confidentiality (D6) | `visible_fields` (who the router sees) | seal all | sealed (safe) |
| Integrity (D3) | `unbound_fields` (who may mutate) | bind all | bound (safe) |

---

## 5. Open / verify flow (how the fields chain together)

1. Select the private key by `key_id`; check `v`, `kem_id`.
2. Recompute the AAD from the **received** envelope (drop `ciphertext` and the
   fields named in `unbound_fields`).
3. `SetupReceiver(enc, priv)` then `Open(ciphertext, aad)` — any tampered **bound**
   field fails closed here.
4. Check decrypted keys == `sealed_fields`, no collision with cleartext names.
5. Check `provider_id == self` (recipient policy; `OpenRequest` leaves this to the
   broker deliberately).
6. Reconstruct request = cleartext ∪ decrypted; resolve the `model` alias here
   (post-`Open`, inside the boundary).

---

## 6. Still open / other considerations

Beyond the field model above, these deserve a decision (some already tracked):

- **The seal boundary (meta-decision) — RESOLVED as D0:** router blind by
  default, seal boundary is client↔provider. The consequence to still execute is
  *relocating* the router's content-touching features (search/file injection,
  response content rewrites) off the routing layer — to the client or a dedicated
  attested TEE node. Tracked as follow-up work, not a protocol-format question.
- **Forward secrecy of requests.** Requests are sealed to the provider's *static*
  enc key (HPKE base mode). Compromise of that key (or the enclave) retroactively
  exposes all captured requests. Mitigation: measurement-tied key rotation with a
  short TTL (already in `router-e2e.md` "Harden") bounds the window; a fuller fix
  is an ephemeral-ephemeral handshake. Worth an explicit rotation cadence.
- **Sealing default is fail-*open* for new fields.** Per SPEC §5.1, unknown/new
  fields default to **cleartext**. That is the opposite safe-default from the
  binding denylist (D3), and its failure mode is a silent **leak** (e.g. a future
  `user` / `metadata` field carrying PII). Recommend a "sensitive-by-default"
  review of known OpenAI fields before launch.
- **Request↔response binding.** Confirm the §8 signature covers a hash of the
  request (not just the response), so a router cannot splice a different or stale
  response. `client_eph_pub` already scopes decryptability per request.
- **Replay / freshness.** Already tracked in `router-e2e.md` "Limitations": a
  per-request nonce in the body (its hash is signed) defeats client-side replay; a
  server timestamp/nonce is the belt-and-suspenders fix. Relevant to billing.
- **Metadata / length leakage.** Cleartext `model`/flags and the **ciphertext
  length** (≈ prompt length) leak to the router/TLS terminator. Padding helps only
  if the router is not the decryptor. Already noted in `router-e2e.md`.

---

## 7. Router-rewrite disposition (D0 follow-up)

The router today rewrites the request and response in many places. Under D0 the
router may not touch prompt/completion content, and under D2–D6 it may not mutate
bound fields. Each rewrite therefore needs a new home. This is the executable
checklist for the D0 follow-up (router repo, not this module).

**Request side (before the provider):**

| Rewrite today | Disposition | Why |
|---|---|---|
| Strip `route_options` (address / sort / allow_fallbacks / require_parameters / trust_mode) | Move to `X-0G-*` headers, or client strips pre-seal | Router inputs, never provider body — keep out of the sealed JSON entirely |
| Strip `plugins` + inject web-search results | Move off router → client or a dedicated attested TEE | Content transform on `messages` — forbidden by D0 |
| Strip `attachments` + inject file text | Move off router → client or a dedicated attested TEE | Content transform on `messages` — forbidden by D0 |
| Strip `verify_tee` | Header / client-side directive | Router directive, not a provider input |
| Rewrite `model` (alias → provider ModelID) | Resolve at an endpoint (D2): client pre-seal, or enclave post-`Open` | `model` stays bound; no router mutation |
| Force `stream_options.include_usage=true` | Client sets it up front (preferred), else list in `unbound_fields` | Avoid a router mutation of a bound field |
| Replace auth header | Header layer — unchanged | Not in body AAD |

**Response side (before the client):**

| Rewrite today | Disposition | Why |
|---|---|---|
| Rewrite `model` back to the requested name | Enclave emits the requested name, or client maps it | Response content is not router-rewritten under D0 |
| Inject `x_0g_trace` (billing) | Enclave folds it in before sealing → rides the signed response; otherwise `unbound_fields` + treated as untrusted | Trust via signature, not AAD (D4) |
| Inject `url_citation` annotations | Enclave (inside the boundary) | Content transform |
| `reasoning` → `reasoning_content` mirror | Enclave or client normalization | Content transform |
| Buffer final `usage` chunk to fold in trace | Revisit with response framing / per-frame sealing | Interacts with streaming frame layout |
| Header rewrites (Content-Type, X-Request-ID, X-Provider, …) | Header layer — unchanged | Not in body AAD |

Pattern: **headers** (routing directives, auth, trace transport) stay at the HTTP
layer, freely mutable; **content** transforms (search, files, annotations,
reasoning) move inside the trust boundary; **bound params** (`model`) are resolved
at an endpoint, never mutated in transit; genuinely intermediary-owned metadata
(`x_0g_trace`) is either signed by the enclave or declared `unbound` and treated
as untrusted.
