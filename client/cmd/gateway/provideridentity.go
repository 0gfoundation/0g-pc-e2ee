package main

import (
	"encoding/json"
	"net/http"

	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
)

// providerIdentityPath is the public route this serves. The {address} wildcard is
// the provider's on-chain account — the same value the gateway returns in the
// X-Provider response header, so a panel asks about the provider it was actually
// sealed to and pinned to rather than one the router named. With the warmer running
// it also answers for a provider no request has used yet (see client/route's
// identity store), which is what lets a panel show the fleet before the first
// prompt; the header remains how it names the one that served a given response.
const providerIdentityPath = "/v1/providers/{address}/identity"

// THIS ENDPOINT REPORTS VERDICTS, AND THAT IS DELIBERATE — it is the one place the
// gateway is allowed to, which is worth stating next to /v1/gateway/identity, where
// the opposite rule holds.
//
// /v1/gateway/identity is the gateway describing ITSELF: nothing verified anything,
// so it carries no verdict of any shape and never should. Here the gateway reports
// checks it genuinely PERFORMED on a THIRD PARTY — a DCAP verification of the
// provider's quote against Intel's roots, and a comparison of the quote-bound signer
// against the on-chain registry — the checks that decide whether it is willing to
// seal a user's prompt to that enclave at all. Withholding those would not make the
// endpoint humbler; it would hide the only verification in the picture.
//
// What the verdicts are NOT is the reader's own verification. They are RELAYED:
// their weight rests entirely on the reader being able to check this gateway itself
// (`pcverify -gateway <domain>`, trust chain A), which is why every response carries
// the note below and why a UI must render these as "the gateway verified this for
// you", never as "verified". A compromised gateway would serve whatever it liked
// here, exactly as with the self-description.
//
// Three things it deliberately does not do:
//
//   - It never fetches anything. The record is a byproduct of a verification that
//     already happened — a served request, or a warmer sweep (client/route's identity
//     store) — so an address this gateway has not verified itself is a 404 rather than
//     a lookup. That is what keeps the route from becoming a quote proxy — or a
//     scanner — for arbitrary addresses, whichever writer filled the store.
//   - It does not return the raw quote. A reader who wants to redo the work should
//     fetch it from the provider DIRECT (the note names the URL), not through the
//     party whose claims are under examination — the same reason the §8 signature is
//     not proxied through the router. It is smaller and the trust path is shorter.
//   - It does not return the boot-chain registers. Three hex strings are not
//     actionable for a reader with no baseline to compare them against; the reader
//     who needs observed values is the operator filling the hop-3 allowlist, and
//     that is pcverify's job.

// providerVerifyNote rides in every response so a verdict cannot travel without the
// caveat, mirroring /v1/gateway/identity's note. It names the two independent
// recourses in order: recheck the provider at the source, and check the gateway that
// is telling you about it.
func providerVerifyNote(quoteURL string) string {
	note := "verdicts reached by this gateway on your behalf, not by you; verify this gateway itself with: pcverify -gateway <domain>"
	if quoteURL == "" {
		return note
	}
	return "recheck this provider yourself: GET " + quoteURL + " direct from the provider and DCAP-verify it. " + note
}

// providerIdentityDoc is the response body.
//
// Absent values are null rather than "" — as on /v1/gateway/identity, "" and null
// are different claims — but nothing here depends on reading a null correctly: the
// verdicts say which case produced it. That is the whole point of the vocabulary in
// route.Verdict, and the fix for the ambiguity the gateway's own os_image shipped
// with.
type providerIdentityDoc struct {
	// Address is the provider's on-chain account as RECORDED (the spelling the route
	// preview used), not as spelled in the request path: matching is case-insensitive,
	// and echoing the caller's own bytes back would make this field a mirror rather
	// than a statement.
	Address string `json:"address"`
	// Endpoint is the provider's serving origin — the host its quote, enc key and §8
	// signatures come from. It is here so a reader can leave this gateway and go to
	// the source; the exact URL to fetch is in `verify`, because an origin cannot carry
	// a base path (see route.ProviderIdentity.Endpoint).
	Endpoint string `json:"endpoint"`
	// Verdicts are the outcomes of the checks this gateway made before sealing.
	Verdicts providerVerdicts `json:"verdicts"`
	// OSImage names the allowlisted OS image the provider's boot chain matched, or
	// null. Null even on a match, because attest.BootChainPolicy holds boot chains
	// without labels — verdicts.measurement is what distinguishes matched from not
	// compared, so null here is never ambiguous; see route.ProviderIdentity.
	OSImage *string `json:"os_image"`
	// ComposeHash is the dstack compose hash out of the verified quote's mr_config_id
	// — WHICH application configuration that enclave booted. Null when the register's
	// layout does not carry it in the clear (mr_config_id V2/V3).
	ComposeHash *string `json:"compose_hash"`
	// Containers is what ComposeHash commits to, unpacked: the services the provider
	// CVM runs, in the order its compose file lists them. Null — never [] — when
	// there is none to report: the quote reply carried no app-compose, it did not
	// hash to ComposeHash, or the text did not parse. An empty array would say "this
	// enclave runs no containers", which is never true.
	//
	// Reaching the wire means the bytes hashed to ComposeHash, so this is as
	// authenticated as the hash — the `source` label on each entry included, since it
	// is derived from those same bytes and from nothing else. It is NOT a check:
	// nothing compared these images against an expected set, so a panel may render
	// them but must not present the list's existence, or the label, as approval.
	Containers []providerContainerRef `json:"containers"`
	// Verify is providerVerifyNote. See the file comment.
	Verify string `json:"verify"`
}

// providerContainerRef is one container of a provider's deployment.
//
// It carries the same `source` label as the gateway's own containerRef, and the
// question that label answers had to be narrowed before it could: not "can I trace
// this image to a GitHub release of this repository" — no per-provider manifest is
// published (docs/design/cloud-gateway.md §6.4), so for a provider there is no release
// to trace to — but "who PUBLISHED this image", which an authenticated compose text
// answers for a provider exactly as well as it does for us. See classifySource: it is
// one classifier for both endpoints, reading the reference's registry and namespace
// rather than this repository's release namespace, which is what stops it stamping
// "third-party" on 0G's own broker image for shipping from a different repository.
//
// What the label is NOT is a check. Nothing compared these images against an expected
// set, and "0G published it" says nothing about WHICH build of it this is — an image
// of ours with a year-old CVE carries the same label as the current one. A panel may
// use it to sort the list into "ask 0G" and "ask upstream"; it must not render it as
// approval, any more than the list's existence is approval.
type providerContainerRef struct {
	// Name is the compose service name.
	Name string `json:"name"`
	// Image is the repository, without tag or digest.
	Image string `json:"image"`
	// Digest is the "sha256:…" the compose text pins, or "" when the reference
	// carries none — which is the one finding a reader can draw from this list
	// unaided, so it is rendered rather than hidden: an unpinned image leaves
	// compose_hash committing to a NAME whose contents can be republished under it.
	Digest string `json:"digest"`
	// Source is "0g-release" for an image 0G published and "third-party" for
	// everything else, in the same vocabulary as /v1/gateway/identity so a panel
	// switches on one set of values across both hops. Unlike there, no matched_release
	// stands behind it: for a provider this is a statement about the image's
	// publisher and nothing more.
	Source string `json:"source"`
}

// providerContainersOf renders the record's service list for the wire, preserving
// file order and mapping "none" to nil so it marshals as null.
func providerContainersOf(services []compose.Service) []providerContainerRef {
	if len(services) == 0 {
		return nil
	}
	out := make([]providerContainerRef, 0, len(services))
	for _, s := range services {
		out = append(out, providerContainerRef{
			Name:   s.Name,
			Image:  s.Image,
			Digest: s.Digest,
			Source: classifySource(s.Image),
		})
	}
	return out
}

// providerVerdicts is the per-check outcome block. Every value is one of the
// route.Verdict strings, so a panel switches on a closed vocabulary instead of
// interpreting nulls.
type providerVerdicts struct {
	// QuoteDCAP: the quote is a genuine, Intel-rooted TDX quote with an acceptable TCB
	// whose report_data binds the enc key and signer. Always "pass" in a served
	// response — a quote that fails this leaves no record behind, so the request 404s
	// rather than reporting a failure (see route.ProviderIdentity.QuoteDCAP).
	QuoteDCAP route.Verdict `json:"quote_dcap"`
	// OnChainSigner: the quote-bound signer equals the provider's acknowledged
	// teeSignerAddress on chain (SPEC §4.4 step 3 / trust-chain hop 5) — what
	// separates the expected provider from a look-alike enclave running the same
	// image. "not_checked" when the deployment did not enable on-chain grounding.
	OnChainSigner route.Verdict `json:"onchain_signer"`
	// Measurement: the boot chain against the audited allowlist (hop 3). "pass" in it,
	// "no_match" not in it, "no_baseline" when the build carried no entry at all — a
	// panel must render that last one as "observed only", never as a pass and never as
	// a failure, since it says nothing about the provider.
	Measurement route.Verdict `json:"measurement"`
}

// providerIdentityHandler serves one provider's record from src.
//
// An address src does not know is a 404, and so is a malformed one: both mean "this
// gateway has no verdict for that", which is the honest answer and the only one that
// does not invite the caller to keep asking about addresses in the hope of a
// different result. There is deliberately no way to ask for a LIST — which providers
// a gateway has recently used is not something a panel needs, and publishing it
// would turn an answer about the caller's own request into fleet telemetry.
func providerIdentityHandler(src route.ProviderIdentitySource) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := src.ProviderIdentity(r.PathValue("address"))
		if !ok {
			openaiproxy.WriteError(w, http.StatusNotFound, "gateway",
				"this gateway has verified no provider at that address (it reports only providers it has checked itself — while serving a request, or in a background sweep — and only for a few minutes afterwards)")
			return
		}
		body, err := json.MarshalIndent(providerIdentityDoc{
			Address:  id.Address,
			Endpoint: id.Endpoint,
			Verdicts: providerVerdicts{
				QuoteDCAP:     id.QuoteDCAP,
				OnChainSigner: id.OnChainSigner,
				Measurement:   id.Measurement,
			},
			OSImage:     optional(id.OSImage),
			ComposeHash: optional(id.ComposeHash),
			Containers:  providerContainersOf(id.Containers),
			Verify:      providerVerifyNote(id.QuoteURL),
		}, "", "  ")
		if err != nil {
			// Nothing in the document can fail to marshal; a 500 here would be a bug in
			// this file, not a condition a caller can act on.
			openaiproxy.WriteError(w, http.StatusInternalServerError, "gateway", "cannot render provider identity")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// This response varies by Origin (the CORS middleware reflects an allowed one)
		// and, unlike /v1/gateway/identity, it is NOT cacheable: the record is replaced
		// as the gateway re-verifies, and it expires. A shared cache holding a verdict
		// past its record would be showing a verification that is no longer in force —
		// the one thing this endpoint must not do. Vary is added anyway so a cache that
		// ignores no-cache still keys on the origin (see identityHandler).
		w.Header().Add("Vary", "Origin")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	})
}

// optional turns an absent string into a JSON null. Empty means "we have no value",
// and "" would be a claim that the value IS empty.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
