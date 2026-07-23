# Request envelope & integrity model — design notes

Scope: the **field-level semantics** of the v1 request envelope and the
**integrity (AAD) model** that binds them. This refines `protocol/SPEC.md` §5–§6
and is a companion to [`router-e2e.md`](./router-e2e.md) (which covers the
*deployment* / trust-boundary and migration story — not repeated here).

> Status: **design notes, pre-launch.** Items marked 🆕 are decisions taken in
> discussion that are **not yet in `SPEC.md` or the code**; everything else
> describes what exists today. `SPEC.md` remains normative once these land.

## Decision log

| # | Decision | Status |
|---|---|---|
| **D0** | Router blind to prompt/completion; seal boundary is client↔provider | ✅ decided (§7 relocation is follow-up work) |
| **D1** | §8 content hash binds produced/decrypted bytes, not a re-derived canonical form | ✅ decided → implement with §8 |
| **D2** | `model` stays bound; alias resolution at an endpoint (client pre-seal / enclave post-open) | ✅ decided |
| **D3** | AAD binds all except a declared `unbound_fields` denylist (fail-closed) | ✅ decided |
| **D4** | `unbound_fields` is authenticated; unbound field values are untrusted (trust via signature) | ✅ decided |
| **D5** | Response envelope mirrors D3/D4 | ✅ decided |
| **D6** | Sealing stays a `sealed_fields` allowlist; fail-open on new fields accepted | ✅ decided |
| — | Request↔response binding (§8 covers the request hash) | ✅ confirmed present |
| — | Forward secrecy: enc key lives only in the TEE, re-derived per enclave lifecycle → de-facto FS; no static long-lived key | ✅ resolved |
| — | Replay / freshness (server-side timestamp/nonce beyond the client nonce) | 🕗 TODO, not urgent |
| — | Metadata / length leakage (cleartext params + ciphertext length ≈ prompt length) | 📌 accepted limitation |

Follow-up execution (decided, not yet built): relocate the router's
content-touching features off the routing layer (§7); implement §8 with D1;
add the Go-reference `_e2ee` collision guard + H1/H2 strict parsing (§8); fold
all of this into `protocol/SPEC.md §5–§6`.

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
| `sealed_fields` | **Allowlist** of which fields were encrypted ({`messages`, `tools`} by default). After `Open`, decrypted keys must equal this set exactly; must include `messages`. | **Bound** — prevents lying about what was sealed. Fail-open on unknown fields is accepted (D6). |
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

### D6 — sealing stays an explicit `sealed_fields` allowlist; fail-open on new fields is accepted
The mirror of D3 for confidentiality (seal-by-default via a `visible_fields`
allowlist) was **considered and declined**. Sealing keeps today's model:
`sealed_fields` explicitly lists what is **encrypted** ({`messages`, `tools`} by
default), and unknown/new fields stay **cleartext** — fail-*open*.

Rationale for accepting fail-open:

- The always-present **content** (`messages`, `tools`) is always sealed — the
  data that matters is never at risk from this default.
- The fields this would otherwise catch (`user`, `metadata`, …) are
  **developer-added and never auto-injected** by the OpenAI SDK (confirmed). A
  leak requires a developer to both add PII *and* not seal it — an explicit
  opt-in, not a silent trap sprung by the framework.
- The allowlist is simpler on the wire and to reason about; the residual risk is
  judged acceptable pre-launch.

**Intentional asymmetry with D3.** Integrity binding is fail-*closed* (a
denylist, D3); confidentiality sealing is fail-*open* (an allowlist, D6). This is
deliberate: tampering is adversarial and must fail closed, whereas leaking a
field the developer chose to add is opt-in and acceptable. If a field later
proves commonly sensitive, add it to the default sealed set.

**Read ≠ mutate.** A cleartext param is still **bound** (category ②): the router
reads it to route but may not rewrite it — else it could downgrade your sampling
or cap `max_tokens` undetectably. A field the router genuinely *rewrites* today
(e.g. forcing `stream_options.include_usage=true`) must therefore be either
listed in `unbound_fields` (low-stakes, untrusted) or — cleaner — set by the
client up front so no rewrite is needed.

**Explicit declaration stays.** Independent of the fail-open default: the
seal/cleartext split is declared *explicitly and bound* via `sealed_fields`
(inside `_e2ee`, covered by the AAD), and the enclave verifies decrypted keys ==
`sealed_fields`. That declaration is what stops an intermediary shifting a field
across the line; it is unaffected by the D6 decision.

Two declarations, deliberately **asymmetric** defaults:

| Dimension | Declares | Default | A new/unknown field is |
|---|---|---|---|
| Confidentiality (D6) | `sealed_fields` (what is encrypted) | cleartext | cleartext (fail-open, **accepted**) |
| Integrity (D3) | `unbound_fields` (who may mutate) | bind all | bound (fail-closed) |

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
- **Forward secrecy of requests — RESOLVED.** Only the *sender* is ephemeral per
  request; the request is sealed to the provider's *recipient* enc key, so
  `shared = DH(client_eph, provider_enc)`, and the per-request client ephemeral
  alone would not give FS (its public half is `enc`, on the wire). But the
  provider **enc key lives only inside the TEE, is never persisted, and is
  re-derived per enclave lifecycle** — so it is not a long-lived static key, and
  recovering a captured request means breaking a live TEE, already outside the
  trust model. That yields de-facto forward secrecy across enclave restarts; no
  ephemeral-ephemeral handshake is needed. (The **response** direction is
  ephemeral-ephemeral and forward-secret independently.)
- **Sealing default is fail-*open* — DECIDED (D6): accepted.** Sealing keeps the
  `sealed_fields` allowlist; unknown/new fields stay cleartext. Accepted because
  the sensitive fields it would catch (`user`, `metadata`) are developer-added,
  never auto-injected, and the content is always sealed. See D6.
- **Request↔response binding — RESOLVED.** Confirmed present: the §8 signature
  covers the request hash (not just the response), so a router cannot splice a
  different or stale response. `client_eph_pub` additionally scopes
  decryptability per request.
- **Replay / freshness — TODO (not urgent).** The client-side per-request nonce
  (its hash is signed) defeats basic replay; a server-side timestamp/nonce in the
  signed text is the belt-and-suspenders addition, deferred. Relevant to billing.
  Also tracked in `router-e2e.md` "Limitations".
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

---

## 8. Implementation hardening — strict parsing (review items)

Two rules that are **safe by construction** in the model above but depend on
strict, *identical* parsing across implementations (Go / TS / Rust). Both are
mandatory; a lenient parser reintroduces the hole. Neither is an attack the
crypto misses — the risk is implementation divergence.

### H1 — `unbound_fields` is a control field; parse it strictly
`unbound_fields` steers the AAD computation itself (it decides what is *excluded*
from the bound bytes), so every implementation must interpret it identically or
the byte-for-byte AAD agreement silently desynchronizes.

- It **MUST** be a JSON array of strings. A non-array (`null`, string, number,
  object) → **fail-closed reject before unsealing**; no implicit coercion.
- **Absent or `[]` → exclude nothing** (bind everything). `null` MUST be treated
  as absent, never as "exclude something."
- Each entry **MUST** name a present top-level cleartext field; the recipient
  **MAY reject** an envelope that lists a field it requires to stay bound (e.g.
  `model`) — the broker's minimum-binding policy (D4).
- *Why this is otherwise safe:* the `unbound_fields` **list value is itself
  bound** (it lives in `_e2ee`, inside the AAD); only the *values of the fields it
  names* are excluded. An attacker cannot enlarge the set — changing the list
  changes the AAD and `Open` fails closed. H1 closes the remaining gap, which is
  not the attacker but a **loose extractor** on one side excluding a field the
  other side bound.

### H2 — reconstruct by strict disjoint union, never override
After `Open`, the request is rebuilt as `cleartext ∪ decrypted`. This merge
**MUST** be a **disjoint union, fatal on overlap** — never a last-writer-wins
assign (`Object.assign` / spread), or a decrypted field could shadow an
AAD-bound cleartext field (e.g. inject a second `model`) or the `_e2ee` object
itself.

- Decrypted keys **MUST equal `sealed_fields`** exactly (already specified).
- Decrypted payload **MUST NOT contain `_e2ee`**, nor **any** key present in the
  outer cleartext → fatal reject.
  - *Concrete gap to close:* the Go reference rejects cleartext collisions, but
    builds the output with `_e2ee` pre-excluded, so a decrypted `_e2ee` key would
    slip past the collision check. Add an explicit `_e2ee` guard, and mandate the
    whole rule for non-reference implementations (dynamic languages especially).
- Constrain the decrypted payload to its expected shape; unexpected top-level
  keys → reject rather than pass upstream.
