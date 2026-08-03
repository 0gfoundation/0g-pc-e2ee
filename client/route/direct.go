package route

import (
	"context"
	"fmt"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// directResolver seals every request to ONE fixed provider, skipping the
// router's route-preview hop entirely. It is the dev/test posture for an
// environment that has a broker but no centralized router: the sealed request is
// POSTed straight to the broker's own /v1/proxy/chat/completions (the endpoint
// the router would otherwise forward to — the broker serves its proxied inference
// surface under ServicePrefix "/v1/proxy", same as /v1/proxy/signature), and the
// provider's enc key + signer are fetched from its broker's /v1/e2ee/pubkey (the
// same fetch the routed path uses, reused here) — or from a DCAP-verified
// /v1/quote when the underlying Router has quote verification configured.
//
// Two things the routed path does are intentionally absent, because there is no
// router in the path: no X-0G-Provider-Address routing pin (Provider.Address is
// left empty — the request goes to the broker directly, nothing to steer) and no
// canonical-model rewrite (Provider.Model is left empty — the caller's own
// "model" passes through, since a single fixed provider is not a heterogeneous
// preview list). On-chain signer grounding is also not applied here: it needs the
// provider's on-chain account, which the router preview would supply but a direct
// endpoint does not.
type directResolver struct {
	router      *Router
	providerURL string
	// chatURL is the broker's own chat-completions endpoint under its "/v1/proxy"
	// service prefix (…/v1/proxy/chat/completions — the path the router would
	// forward a sealed request to, NOT the router's own /v1/chat/completions),
	// derived from providerURL once at construction so a malformed URL fails loud up
	// front. The sealed request POSTs here directly (no router completions hop).
	chatURL string
}

// NewDirect returns a core.Resolver that seals directly to providerURL's broker,
// with no route-preview hop — for an environment that has a broker but no
// centralized router (dev). The opts configure the underlying key fetch (sensitive
// fields to withhold, pubkey TTL, HTTP client, and — if set — quote verification),
// reusing the same machinery the routed path uses; router-only options (the
// completions/preview URLs) are simply unused.
//
// providerURL may be a bare origin (https://host[:port]), the /v1 base, or the
// full chat-completions URL; all resolve to the same /v1 base, off which the
// pubkey (/v1/e2ee/pubkey), quote (/v1/quote), signature (/v1/proxy/signature),
// and chat (/v1/proxy/chat/completions) paths hang (see deriveV1Base). A malformed
// or empty URL is a construction error, not a per-request one.
func NewDirect(providerURL string, opts ...Option) (core.Resolver, error) {
	if strings.TrimSpace(providerURL) == "" {
		return nil, fmt.Errorf("direct provider URL is required")
	}
	base, err := deriveV1Base(providerURL)
	if err != nil {
		return nil, fmt.Errorf("direct provider URL: %w", err)
	}
	// routerURL is unused in direct mode (no preview / completions hop); pass
	// providerURL only so New's construction (HTTP client, pubkey/quote caches) is
	// satisfied — its previewURL/completionsURL fields are never read here.
	return &directResolver{
		router:      New(providerURL, opts...),
		providerURL: providerURL,
		// The broker serves chat completions under its "/v1/proxy" prefix
		// (mirroring /v1/proxy/signature), NOT at the router's top-level
		// /v1/chat/completions — POST the sealed request there directly.
		chatURL: base + "/proxy/chat/completions",
	}, nil
}

// Resolve implements core.Resolver: a single fixed candidate, the configured
// provider. Materialization (its key fetch) is deferred to Candidates.Provider,
// mirroring the routed path.
func (d *directResolver) Resolve(context.Context, wire.Request) (core.Candidates, error) {
	return directCandidates{d}, nil
}

// directCandidates is the one-element candidate list backing a directResolver:
// no fallback (a single provider), lazy key fetch on Provider(0).
type directCandidates struct{ d *directResolver }

func (c directCandidates) Len() int { return 1 }

// Provider materializes the fixed provider, fetching its enc key + signer from
// the broker (pubkey endpoint, or a DCAP-verified quote when configured). URL is
// the broker's OWN /v1/proxy/chat/completions (direct, no router), Endpoint
// carries the same base so the §8 response signature can be fetched direct from
// it, and Address / Model are left empty (no routing pin, caller's model passes
// through).
func (c directCandidates) Provider(ctx context.Context, _ int) (core.Provider, error) {
	d := c.d
	var (
		encPub crypto.PublicKey
		signer string
		err    error
	)
	if d.router.verifier != nil {
		encPub, signer, err = d.router.verifiedKeys(ctx, d.providerURL)
	} else {
		var pubkeyURL string
		pubkeyURL, err = derivePubkeyURL(d.providerURL)
		if err == nil {
			encPub, signer, err = d.router.pubkey(ctx, pubkeyURL)
		} else {
			err = upstream(0, fmt.Errorf("provider endpoint: %w", err))
		}
	}
	if err != nil {
		return core.Provider{}, err
	}
	return core.Provider{
		URL:        d.chatURL,
		EncPubKey:  encPub,
		SignerAddr: signer,
		Endpoint:   d.providerURL,
	}, nil
}
