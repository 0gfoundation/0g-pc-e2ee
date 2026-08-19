package route

import (
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/chain"
)

// This file holds what a request path already established about a provider but
// used to throw away: the outcome of the checks THIS process ran before it agreed
// to seal to that provider.
//
// The verification itself is not new — verifyQuoteAt has always DCAP-verified the
// quote and compared the boot chain, and groundSignerOnChain has always compared
// the quote-bound signer against the on-chain registry. What is new is that the
// outcome survives the request, so a verification panel can show the user the
// broker hop of the trust chain instead of a blank.
//
// Two properties are load-bearing, and both come from where the record is WRITTEN
// (routeCandidates.Provider, after the checks) rather than from anything here:
//
//   - A record exists only for a provider this gateway actually verified while
//     serving a request. Nothing in this file can fetch a quote, resolve an
//     endpoint, or reach the chain, so the surface it feeds cannot be turned into a
//     quote proxy or a scanner for arbitrary addresses.
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
//     allowlist is empty and nothing was compared. A reader that cannot tell those
//     apart is exactly what the explicit vocabulary below exists to prevent.
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
	// run: the audited boot-chain allowlist is empty (trust-chain hop 3, still
	// unfilled). Not a finding about the provider; a panel must render it as
	// "observed only", never as a pass and never as a failure.
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

// ProviderIdentity is the record of what this gateway verified about one provider,
// as of the last request that used it.
//
// It carries no quote bytes and no measurement registers, on purpose. A caller who
// wants to redo the verification should fetch the quote from the provider DIRECT
// (QuoteURL) rather than through the party that is making these claims — the same
// reason the §8 response signature is not proxied through the router. Three hex
// registers, meanwhile, are not actionable for a reader with no baseline to compare
// them against; the reader who needs observed values is the operator filling the
// hop-3 allowlist, and that is pcverify's job.
type ProviderIdentity struct {
	// Address is the provider's on-chain account, as the router spelled it in the
	// route preview (EIP-55 or lowercase). It is the same value the gateway returns
	// in the X-Provider response header, which is how a panel knows what to ask for.
	Address string
	// Endpoint is the provider's serving origin (scheme://host[:port]) — the host a
	// panel names as "who answered", reported so a reader can leave this gateway and go
	// to the source.
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
	// the allowlist is empty — which is every deployment today, since that allowlist
	// is the half of hop 3 still unfilled (docs/design/trust-chain.md).
	Measurement Verdict
	// OSImage names the allowlisted OS image the boot chain matched, or "" when
	// nothing was matched.
	//
	// It is "" in every record today, and the reason is worth stating rather than
	// leaving to be discovered: hop 3's allowlist is empty (so Measurement is
	// VerdictNoBaseline and there is nothing to name), and even once filled,
	// attest.BootChainPolicy holds boot chains without labels. Unlike the gateway's
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
// older than the verification a request would itself have relied on.
const providerIdentityTTL = 5 * time.Minute

// maxProviderIdentities caps how many records are held.
//
// The address in a record comes from the route preview, and the router is
// untrusted: a compromised one could name a new address per candidate (all pointing
// at one genuinely-verifiable endpoint, since a record requires a passing quote
// check) and grow this map for as long as it keeps answering. The cap turns that
// into a fixed cost. It is far above any real fleet — the router's catalog is tens
// of providers — so a legitimate deployment never reaches it.
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

// put records (or replaces) one provider's identity. An empty address is dropped:
// direct-broker mode pins no on-chain address, and a record no one can look up
// would only consume the cap.
func (s *identityStore) put(id ProviderIdentity) {
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
	if _, replacing := s.m[key]; !replacing && len(s.m) >= s.max {
		s.makeRoomLocked(now)
	}
	s.m[key] = identityEntry{id: id, exp: now.Add(s.ttl)}
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

// providerIdentityOf assembles the record from a materialized candidate: the
// address and endpoint the preview named, the facts the quote verification
// established, and the on-chain verdict.
//
// QuoteDCAP is VerdictPass unconditionally, and only here: this function is reached
// only from the path where r.verifier.Verify returned without error, which is the
// definition of that verdict. A caller that reaches it any other way would be
// asserting something no check made — see ProviderIdentity.QuoteDCAP.
func providerIdentityOf(prov previewProvider, res quoteResult, onchain Verdict) ProviderIdentity {
	id := ProviderIdentity{
		Address:       prov.Address,
		QuoteDCAP:     VerdictPass,
		OnChainSigner: onchain,
		Measurement:   res.facts.measurement,
		ComposeHash:   res.facts.composeHash,
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
	if origin, err := deriveOrigin(prov.Endpoint); err == nil {
		id.Endpoint = origin
	}
	if quoteURL, err := deriveQuoteURL(prov.Endpoint); err == nil {
		id.QuoteURL = quoteURL
	}
	return id
}

// recordProviderIdentity stores what the checks in routeCandidates.Provider just
// established. It is called once the quote has been verified, the keys bound and the
// on-chain check made — so a record means "this gateway ran its checks against this
// provider for a real request", never "the router mentioned it".
func (r *Router) recordProviderIdentity(id ProviderIdentity) {
	r.identities.put(id)
}
