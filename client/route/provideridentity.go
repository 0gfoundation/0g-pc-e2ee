package route

import (
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
)

// This file holds what a verification already established about a provider but
// used to throw away: the outcome of the checks THIS process ran before it was
// willing to seal to that provider.
//
// The verification itself is not new — verifyQuoteAt has always DCAP-verified the
// quote and compared the boot chain, and the on-chain signer has always been
// compared against the registry. What is new is that the outcome survives the
// verification, so a verification panel can show the user the broker hop of the
// trust chain instead of a blank.
//
// Two writers, running the same checks at different times and against endpoints they
// source differently:
//
//   - routeCandidates.Provider, for the provider a real request was sealed to, at the
//     endpoint the router's route preview named.
//   - Router.WarmOnce, for every provider the background warmer sweeps, at the
//     endpoint the ON-CHAIN registry names. It runs the same DCAP verification and the
//     same on-chain signer comparison, ahead of any request, so the panel can name a
//     provider's containers before the user has made one. Without it the endpoint
//     could only ever answer about a request that had already happened, which made
//     "show me who I would be sealed to" impossible to answer and left every provider
//     in the catalog invisible until it was picked.
//
// The endpoints agree in any healthy deployment, and where they do the fresher
// verification simply replaces the older one. Where they DISAGREE the served record
// wins — see identityStore.putWarmed for why that ordering is not a preference.
//
// Three properties are load-bearing, and all three come from where the record is
// WRITTEN (after the checks, in both writers) rather than from anything here:
//
//   - A record exists only for a provider this process verified ITSELF, and only
//     once its quote passed DCAP. Nothing in this file can fetch a quote, resolve an
//     endpoint, or reach the chain, so the surface it feeds cannot be turned into a
//     quote proxy or a scanner for arbitrary addresses — an address neither writer
//     has verified is absent however often it is asked for.
//   - It is written on the way past the checks, not on the way to a successful seal.
//     A candidate the on-chain check REJECTS (enforce mode) is recorded with the
//     verdict that rejected it, because the alternative is worse: an earlier pass
//     would stand for the rest of its TTL while the gateway is actively refusing that
//     provider, which is the one way this endpoint could state something the gateway
//     no longer believes. A quote that fails DCAP is the exception and leaves no
//     record at all — see ProviderIdentity.QuoteDCAP.
//   - Every verdict is the one the gateway REACHED, not a restatement of what it
//     would like to be true. VerdictPass on the DCAP check means a genuine,
//     Intel-rooted quote; VerdictNoBaseline on the measurement means the audited
//     allowlist held no entry and nothing was compared. A reader that cannot tell those
//     apart is exactly what the explicit vocabulary below exists to prevent.
//
// What the warmer as a writer DOES change is how much the set of records discloses.
// With the warmer on, the store holds the whole router catalog rather than only the
// providers this gateway has recently been asked to use, so probing address by
// address confirms catalog membership. That discloses nothing new: the catalog is
// GET /v1/providers, which the gateway proxies to the router unauthenticated and
// which the warmer itself reads without a credential. What it must not become is a
// LIST — see providerIdentityHandler — because the set of providers a gateway
// recently SERVED is fleet telemetry, and that is precisely the distinction the
// warmer erases by covering every provider uniformly.
//
// The records are kept HERE rather than inside quoteCache, which holds the same
// verifications, for two reasons that are properties of the data and not of taste.
// That cache is keyed by quote URL, while a panel holds an ADDRESS — and one of the
// checks being reported (the on-chain signer comparison) is per-address, made after
// the quote is cached, so it has nowhere to live there. What the two share is the
// quote-derived half: quoteFacts rides in the cache entry precisely so a request
// served from a warm cache still records a complete answer.
//
// What it is NOT is evidence. These are verdicts the gateway reached and is now
// RELAYING; their weight comes from the reader being able to verify the gateway
// itself (docs/design/cloud-gateway.md §6, `pcverify -gateway`) and, for the
// provider, from being able to re-fetch that provider's quote direct and redo the
// work. That is why ProviderIdentity carries QuoteURL: the honest form of "trust
// me" is "here is where to check".

// Verdict is the outcome of ONE check on ONE provider. The five values are a
// deliberate vocabulary, not a bool with excuses: the distinction between "the
// check ran and said no", "there was nothing to check against", "the check could
// not be completed" and "this deployment does not run that check" is the whole
// difference between a finding about a provider and a gap in our own
// configuration, and a field that cannot express it will be read as the first when
// it means the second.
//
// These strings are the wire vocabulary the browser panel switches on (they are
// marshalled verbatim by the gateway's provider-identity endpoint), so renaming a
// value is an API change, not a refactor.
type Verdict string

const (
	// VerdictPass — the check ran and was positive.
	VerdictPass Verdict = "pass"
	// VerdictNoMatch — the check ran and was NEGATIVE. A real finding about the
	// provider: an out-of-allowlist boot chain, a signer the chain does not
	// acknowledge, a signer that disagrees with the registry.
	VerdictNoMatch Verdict = "no_match"
	// VerdictNoBaseline — the check had nothing to compare against, so it did not
	// run: the audited boot-chain allowlist holds no entry at all. Not a finding about
	// the provider; a panel must render it as "observed only", never as a pass and
	// never as a failure. With brokerimages.json populated this is reached only by a
	// build whose allowlist was emptied.
	VerdictNoBaseline Verdict = "no_baseline"
	// VerdictUnavailable — the check should have run but could not complete (the
	// chain RPC was unreachable or errored). The answer is unknown, which is
	// distinct from negative: retrying may yet produce one.
	VerdictUnavailable Verdict = "unavailable"
	// VerdictNotChecked — this deployment does not perform the check at all (e.g.
	// on-chain signer grounding is not configured). A property of our
	// configuration, disclosed rather than hidden behind a null.
	VerdictNotChecked Verdict = "not_checked"
)

// onchainVerdictOf translates a grounding outcome into the wire vocabulary.
//
// It is a translation and not a second opinion: groundSignerOnChain owns what the
// chain said, and this only decides how much of that distinction a browser panel
// needs. Two collapses, both deliberate:
//
//   - mismatch and not_acknowledged both become VerdictNoMatch. They are counted
//     apart because an operator responds to them differently; to a reader asking "is
//     this the provider the chain vouches for?", both answers are no.
//   - ok_stale becomes VerdictPass, because that is what it means: staleness
//     disqualifies a NEGATIVE, never a positive (see groundSignerOnChain), and a
//     sustained ok_stale rate is a fact about our chain RPC's reachability rather
//     than about this provider — which is why it stays in the metrics, where the
//     operator looking for it will be.
//
// lookup_failed is the one that must NOT collapse: it becomes VerdictUnavailable, so
// a chain RPC having a bad minute never reaches a user as an accusation against the
// provider they were just served by.
func onchainVerdictOf(outcome groundingOutcome) Verdict {
	switch outcome {
	case groundingOK, groundingOKStale:
		return VerdictPass
	case groundingMismatch, groundingNotAcknowledged:
		return VerdictNoMatch
	case groundingLookupFailed:
		return VerdictUnavailable
	default:
		// An outcome added later and not mapped here: report it as unknown rather than
		// as either a pass or a finding. Both of those would be a claim this function
		// has no basis for.
		return VerdictUnavailable
	}
}

// ProviderIdentity is the record of what this gateway verified about one provider:
// the most recent verification it ran against that provider — the last request sealed
// to it, or the last warmer sweep that swept it, the later of the two except where
// they disagree about the provider's endpoint (see identityStore.putWarmed).
//
// It carries no quote bytes and no measurement registers, on purpose. A caller who
// wants to redo the verification should fetch the quote from the provider DIRECT
// (QuoteURL) rather than through the party that is making these claims — the same
// reason the §8 response signature is not proxied through the router. Three hex
// registers, meanwhile, are not actionable for a reader with no baseline to compare
// them against; the reader who needs observed values is the operator filling the
// hop-3 allowlist, and that is pcverify's job.
type ProviderIdentity struct {
	// Address is the provider's on-chain account, as the router spelled it (EIP-55 or
	// lowercase) in whichever list the writer read — the route preview for a served
	// request, the provider catalog for a warmer sweep. It is the same value the
	// gateway returns in the X-Provider response header, which is how a panel knows
	// what to ask for. Lookups canonicalize, so the spelling is a display detail.
	Address string
	// Endpoint is the provider's serving origin (scheme://host[:port]) — the host a
	// panel names as "who answered" (or, for a warmed record, who would), reported so
	// a reader can leave this gateway and go to the source.
	//
	// The two writers source it differently and both are right: a request records the
	// endpoint the route preview named and then verified, a sweep records the one it
	// resolved from the on-chain registry. Either way it is the endpoint whose quote
	// this record describes, which is the only property a reader needs from it.
	//
	// It is a DISPLAY value: do not build paths off it. The router may advertise an
	// endpoint under a base path, which an origin necessarily drops, so
	// Endpoint+"/v1/quote" is not reliably the quote URL. QuoteURL is.
	Endpoint string
	// QuoteURL is the exact URL this gateway fetched and verified the quote from —
	// the provider's /v1/quote with the SPEC §4.2 report_data layout requested, derived
	// from whatever endpoint spelling the preview supplied. Carried separately from
	// Endpoint because "verify it yourself" is only useful if it names the same
	// artifact we checked.
	QuoteURL string
	// QuoteDCAP is the DCAP verification outcome: genuine Intel-rooted TDX quote,
	// acceptable TCB, and a report_data that binds the enc key and signer.
	//
	// It is VerdictPass in every record that exists. That is not a hardcoded "yes":
	// a quote that fails this check makes the candidate unusable, so the record is
	// never written and the endpoint 404s. The field is present because a panel
	// showing a three-hop trust chain needs to state the check per hop, and because a
	// future softer mode (report a failure rather than skip the candidate) would fill
	// it differently without changing the shape.
	QuoteDCAP Verdict
	// OnChainSigner is whether the quote-bound signer equals the provider's
	// acknowledged teeSignerAddress in the InferenceServing registry (SPEC §4.4 step
	// 3 / trust-chain hop 5) — the check that separates the EXPECTED provider from a
	// look-alike enclave running the same audited image. VerdictNotChecked when the
	// deployment did not configure on-chain grounding.
	OnChainSigner Verdict
	// Measurement is the boot-chain check against the audited allowlist (hop 3):
	// VerdictPass in the allowlist, VerdictNoMatch not in it, VerdictNoBaseline when
	// the allowlist holds no entry (client/evidence/brokerimages.json).
	//
	// Which of those a reader can actually see depends on the mode, and the difference
	// matters to anyone using this endpoint to survey a fleet: under -attest-enforce an
	// out-of-allowlist boot chain makes the candidate unusable, so — exactly as for
	// QuoteDCAP above — no record is written and the endpoint 404s rather than reporting
	// VerdictNoMatch. VerdictNoMatch is therefore reachable only in warn mode, which is
	// what makes warn mode the state in which "is every provider on a listed image?" can
	// be answered from these records at all.
	Measurement Verdict
	// OSImage names the allowlisted OS image the boot chain matched, or "" when
	// nothing was matched.
	//
	// It is "" on a matched provider too, and the reason is worth stating rather than
	// leaving to be discovered: attest.BootChainPolicy holds boot chains without
	// labels, so a match knows the registers agreed but not which entry's name to
	// report. (evidence.OSImage carries the name; wiring it through would mean the
	// verifier returning which entry matched.) Unlike the gateway's
	// own os_image — where null conflated "matched nothing" with "checked nothing" —
	// an empty value here is never ambiguous: Measurement says which case it is.
	OSImage string
	// ComposeHash is the dstack compose hash from the verified quote's mr_config_id,
	// hex-encoded: SHA-256 over the provider CVM's app-compose.json, i.e. WHICH
	// application configuration that enclave booted. Empty when the quote's
	// mr_config_id uses a layout that does not expose it (V2/V3 commit to it inside a
	// digest) — see attest.ComposeHashFromMRConfigID.
	//
	// It is authenticated: mr_config_id sits inside the signed TD report, so the same
	// signature check behind QuoteDCAP covers it.
	ComposeHash string
	// Containers is what ComposeHash commits to, unpacked: the services of the
	// provider CVM's compose text, in file order. Nil when the quote reply carried no
	// app-compose, when it failed the hash gate, or when the text did not parse — all
	// three are "nothing to show", never a claim that the enclave runs no containers.
	//
	// Reaching this field means the bytes hashed to ComposeHash, so the list is as
	// authenticated as the hash is. What it is NOT is a check: the images here were
	// never compared against anything (that is hop 3's unfilled allowlist), so a
	// reader may render them but must not read the list's existence as approval. The
	// one entry that carries a finding on its own is an empty Digest — an image
	// pinned only by tag, which leaves ComposeHash committing to a name whose
	// contents can be republished underneath it.
	Containers []compose.Service
}

// ProviderIdentitySource is the read side of the record store — the seam the
// gateway's provider-identity endpoint reads through, so the HTTP layer gets a
// lookup and nothing else (no way to trigger a verification, evict an entry, or
// reach the router's transport).
type ProviderIdentitySource interface {
	// ProviderIdentity returns the record for a provider address, or false when there
	// is none: an address this process never verified, or one whose record has
	// expired. Address matching is case-insensitive (a caller may hold the EIP-55 or
	// the lowercase spelling of the same account).
	ProviderIdentity(address string) (ProviderIdentity, bool)
}

// providerIdentityTTL bounds how long a record is reported.
//
// It is bounded for the same reason the quote cache is: a verification attests a
// point in time, and TCB status, collateral validity and a provider's on-chain
// signer all change out from under it. It is deliberately NOT tied to
// WithQuoteTTL — a deployment that disables the quote cache to re-verify on every
// request has MORE current verdicts, not fewer, and should not thereby lose the
// panel's data source.
//
// Sized to match the quote cache's default so a reported verdict is never much
// older than the verification a request would itself have relied on. That also
// puts it above the warmer's default interval (proxycli.defaultWarmInterval, 4m),
// which is what makes a warmed record CONTINUOUSLY available rather than
// intermittently: each sweep replaces the entry before the previous one expires, so
// a panel loading at an arbitrary moment finds an answer. A deployment that widens
// -warm-interval past this TTL gets gaps between sweeps, and the endpoint honestly
// 404s in them rather than reporting a verification that has lapsed.
const providerIdentityTTL = 5 * time.Minute

// maxProviderIdentities caps how many records are held.
//
// The address in a record comes from the router, which is untrusted: a compromised
// one could name a new address per candidate (all pointing at one
// genuinely-verifiable endpoint, since a record requires a passing quote check) and
// grow this map for as long as it keeps answering. The cap turns that into a fixed
// cost. It is far above any real fleet — the router's catalog is tens of providers —
// so a legitimate deployment never reaches it.
//
// The warmer, despite reading the same untrusted catalog, cannot be used this way at
// all: it resolves every address's endpoint from the ON-CHAIN registry before
// verifying anything, so an invented address fails that lookup and is skipped. Only
// providers the chain knows about can ever reach the store through a sweep.
const maxProviderIdentities = 1024

// identityStore holds the records, keyed by provider address through
// chain.ProviderKey — the one canonicalization every per-provider keyed structure in
// this codebase goes through, so "the same provider, differently capitalized" cannot
// become a second entry the panel never finds. Safe for concurrent use (mutex-guarded
// map, like quoteCache).
type identityStore struct {
	ttl time.Duration
	max int
	mu  sync.Mutex
	m   map[string]identityEntry
}

type identityEntry struct {
	id  ProviderIdentity
	exp time.Time
	// served marks a record the REQUEST path wrote — a verification of the endpoint a
	// user's prompt was actually sealed to, as opposed to a sweep's verification of the
	// endpoint the chain names. It exists only to order the two writers when they
	// disagree (see putWarmed) and is deliberately not reported: which internal path
	// last verified a provider is not a claim about that provider, and a wire field for
	// it would invite a panel to rank one verification above the other when both are
	// the same checks against the same roots.
	served bool
}

// shieldedFrom reports whether this entry must survive a sweep that verified (or
// tried to verify) quoteURL — because it is a served record describing a DIFFERENT
// endpoint, so the sweep's outcome, good or bad, says nothing about it.
//
// One predicate for both directions on purpose: a sweep may neither overwrite such a
// record with its own verdict (putWarmed) nor drop it because its own verification
// failed (delWarmed). Those are the same claim — "what happened at the endpoint the
// chain names does not describe the endpoint a user's prompt went to" — and splitting
// them invites the two halves to drift.
//
// An expired entry is shielded from nothing: no reader can reach it, so keeping it
// would only block the sweep from filling the slot.
func (e identityEntry) shieldedFrom(quoteURL string, now time.Time) bool {
	return e.served && now.Before(e.exp) && e.id.QuoteURL != quoteURL
}

func newIdentityStore(ttl time.Duration, max int) *identityStore {
	if max <= 0 {
		// A non-positive cap would make the eviction below a no-op that still admits
		// every write — unbounded growth wearing a cap's clothes. Fall back to the real
		// one rather than let a caller's zero value mean "no limit".
		max = maxProviderIdentities
	}
	return &identityStore{ttl: ttl, max: max, m: make(map[string]identityEntry)}
}

// put records (or replaces) what a SERVED REQUEST verified. An empty address is
// dropped: direct-broker mode pins no on-chain address, and a record no one can look
// up would only consume the cap.
//
// It always wins. A record describing the endpoint a user's prompt actually went to
// is the one a panel is asking about, so nothing defers to a sweep here.
func (s *identityStore) put(id ProviderIdentity) { s.record(id, true) }

// putWarmed records what a WARMER SWEEP verified, unless that would overwrite a
// served record for a DIFFERENT endpoint.
//
// The exception is the whole reason the two writers are distinguished. They resolve a
// provider's endpoint from different places — the request path from the router's
// route preview, a sweep from the on-chain registry — so for one address they can
// verify two different enclaves and reach two different verdicts. Where that happens,
// last-write-wins would let a sweep's `pass` at the on-chain endpoint replace the
// `no_match` a request reached at the router's: the panel would report agreement for the
// very provider whose signer this gateway could not ground. Wrong under either verdict
// mode, and differently wrong in each — under warn the request proceeded anyway, so the
// record would vouch for an enclave the prompt was actually sealed to ungrounded; under
// enforce (the shipped configuration) the candidate was refused, so it would vouch for
// one the gateway declined to seal to at all. That is precisely the
// "states something the gateway no longer believes"
// failure routeCandidates.Provider takes care to avoid by recording rejected
// candidates in the first place, and it must not come back in through the warmer.
//
// Same endpoint — the case in every healthy deployment, where the router advertises
// what the chain says — is not a conflict at all: both writers verified the same
// artifact, so the fresher verification is simply better and replaces the older one,
// which is what keeps a warmed record continuously refreshed.
func (s *identityStore) putWarmed(id ProviderIdentity) { s.record(id, false) }

func (s *identityStore) record(id ProviderIdentity, served bool) {
	key := chain.ProviderKey(id.Address)
	// A nil store is a Router assembled field-by-field (tests do this for the
	// on-chain and warmer paths); recording nowhere is the right behavior, not a
	// panic on a display feature.
	if s == nil || key == "" || s.ttl <= 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, replacing := s.m[key]
	if !served && replacing && cur.shieldedFrom(id.QuoteURL, now) {
		return
	}
	if !replacing && len(s.m) >= s.max {
		s.makeRoomLocked(now)
	}
	s.m[key] = identityEntry{id: id, exp: now.Add(s.ttl), served: served}
}

// delWarmed drops the record for a provider whose quote a sweep just FAILED to
// verify, at the endpoint quoteURL.
//
// It is the identity store's half of the eviction refreshQuote already does on the
// quote cache, and it exists for the same reason: a verification attests a point in
// time, and once a provider has gone bad — TCB downgrade, unreachable, revoked — the
// last good answer must stop being served rather than ride out its TTL. Leaving it
// would publish `quote_dcap: pass` for an enclave this gateway has just established
// it cannot verify at all, which is worse than 404 by exactly the margin a reader
// trusts the verdict.
//
// The failure has to be re-established each sweep for the record to stay gone, which
// is the correct shape: a sweep that succeeds again re-records, so a provider
// recovering from a blip is described again on the next sweep rather than waiting out
// a penalty.
//
// A served record for a different endpoint is shielded, symmetrically with putWarmed:
// a sweep failing at the endpoint the chain names has established nothing about the
// endpoint a user's prompt actually went to.
func (s *identityStore) delWarmed(address, quoteURL string) {
	key := chain.ProviderKey(address)
	if s == nil || key == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.m[key]; ok && !cur.shieldedFrom(quoteURL, now) {
		delete(s.m, key)
	}
}

// makeRoomLocked frees one slot: expired entries first, and failing that the entry
// closest to expiry. Evicting the oldest rather than refusing the write keeps the
// store showing the providers most recently used — the ones a panel is asking
// about — under a router that is inventing addresses.
func (s *identityStore) makeRoomLocked(now time.Time) {
	for k, e := range s.m {
		if now.After(e.exp) {
			delete(s.m, k)
		}
	}
	if len(s.m) < s.max {
		return
	}
	oldestKey, oldestExp := "", time.Time{}
	for k, e := range s.m {
		if oldestKey == "" || e.exp.Before(oldestExp) {
			oldestKey, oldestExp = k, e.exp
		}
	}
	delete(s.m, oldestKey)
}

func (s *identityStore) get(address string) (ProviderIdentity, bool) {
	key := chain.ProviderKey(address)
	if s == nil || key == "" {
		return ProviderIdentity{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok {
		return ProviderIdentity{}, false
	}
	if time.Now().After(e.exp) {
		// Drop it here rather than only on the next write: a stale verdict must not be
		// reachable, and reads are the only traffic an idle gateway has.
		delete(s.m, key)
		return ProviderIdentity{}, false
	}
	return e.id, true
}

// ProviderIdentity implements ProviderIdentitySource against this Router's records.
// It only ever reads: an address this Router has not verified returns false, and
// nothing here starts a verification to change that.
func (r *Router) ProviderIdentity(address string) (ProviderIdentity, bool) {
	return r.identities.get(address)
}

// providerIdentityOf assembles the record from a verified provider: its on-chain
// address, the endpoint the quote was verified at, the facts that verification
// established, and the on-chain signer verdict.
//
// It takes the address and endpoint as plain strings rather than the previewProvider
// the request path holds, because the warmer reaches it with neither — it enumerates
// an address from the catalog and resolves the endpoint from chain, and there is no
// route preview anywhere in a sweep. Naming the two fields it actually reads keeps
// the second writer from having to fabricate a preview candidate to satisfy a type.
//
// QuoteDCAP is VerdictPass unconditionally, and only here: this function is reached
// only from a path where r.verifier.Verify returned without error, which is the
// definition of that verdict. A caller that reaches it any other way would be
// asserting something no check made — see ProviderIdentity.QuoteDCAP.
func providerIdentityOf(address, endpoint string, res quoteResult, onchain Verdict) ProviderIdentity {
	id := ProviderIdentity{
		Address:       address,
		QuoteDCAP:     VerdictPass,
		OnChainSigner: onchain,
		Measurement:   res.facts.measurement,
		ComposeHash:   res.facts.composeHash,
		Containers:    res.facts.containers,
	}
	// A verdict must never reach the wire empty. Every path that builds a quoteResult
	// records what the boot-chain check concluded, so an unset value would mean a
	// future one did not — and the honest report of a verdict nobody computed is
	// "unknown", not the pass or the finding a reader would otherwise infer from a
	// blank.
	if id.Measurement == "" {
		id.Measurement = VerdictUnavailable
	}
	// Report the provider's ORIGIN rather than the endpoint spelling the router
	// happened to send (a bare origin, a /v1 base, or a full chat URL are all the same
	// provider): a panel showing "this is who answered" wants the host, and a reader
	// going to fetch the quote wants a URL they can reason about. Both derivations are
	// best-effort — a malformed endpoint could not have been verified in the first
	// place, so in practice they always succeed; an empty field beats a half-parsed URL.
	if origin, err := deriveOrigin(endpoint); err == nil {
		id.Endpoint = origin
	}
	if quoteURL, err := deriveQuoteURL(endpoint); err == nil {
		id.QuoteURL = quoteURL
	}
	return id
}

// recordProviderIdentity stores what the checks in routeCandidates.Provider just
// established for a served request. It is called once the quote has been verified,
// the keys bound and the on-chain check made — so a record means "this gateway ran
// its checks against this provider", never "the router mentioned it".
func (r *Router) recordProviderIdentity(id ProviderIdentity) {
	r.identities.put(id)
}

// recordWarmedProviderIdentity is the same for a warmer sweep, which defers to a
// served record when the two verified different endpoints — see putWarmed.
func (r *Router) recordWarmedProviderIdentity(id ProviderIdentity) {
	r.identities.putWarmed(id)
}

// forgetWarmedProviderIdentity drops what a sweep can no longer stand behind: the
// provider's quote failed to verify at quoteURL, so any record of an earlier success
// must go rather than outlive the verification it reports — see delWarmed.
func (r *Router) forgetWarmedProviderIdentity(address, quoteURL string) {
	r.identities.delWarmed(address, quoteURL)
}
