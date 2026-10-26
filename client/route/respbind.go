package route

// respbind.go decides, per provider, whether a request is sealed with the response
// binding (SPEC §7.6): a `_bind` the enclave keys the response's HPKE context with,
// so a stream the router substitutes is refused at its first frame instead of after
// the whole stream by the §8 signature.
//
// WHO SAYS A PROVIDER SUPPORTS IT. A broker that predates §7.6 forwards `_bind`
// upstream and seals in base mode, and a bound client then refuses every response
// from it. So the binding is attached only to a provider that advertises
// `"e2ee_features": ["resp-bind"]` in its /v1/quote reply.
//
// WHERE THAT IS READ, which is the whole security argument. The decision is a
// downgrade target: a router that can make this gateway believe a provider does
// NOT support the binding can substitute that provider's streams again. The quote
// on the request path is fetched from the router-supplied endpoint — fine for the
// keys, which the quote authenticates, but not for this field: the router can
// point the endpoint at a proxy that strips it, and even a signed reply is
// replayable, since an older build's reply is signed by the same derived key. So
// the answer is taken only from the warmer, which fetches each provider's quote at
// its ON-CHAIN serving URL (warmer.go), a path the router neither chooses nor sits
// on. Nothing the request path reads feeds it.
//
// WHAT CHANGES IT. Only an observation from that path, in either direction: a reply
// that advertises the feature turns it on, a verified reply that does not turns it
// off (a broker rolled back). A failed fetch changes nothing, and nothing ages out,
// so a router that hides a provider from the catalog the warmer enumerates cannot
// make its entry lapse. The cost of erring on the side of binding is availability,
// not exposure: a provider that stops sealing bound responses fails at its first
// frame, before anything is delivered, and the walk falls back to the next
// candidate.

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
)

// featureRespBind is the /v1/quote `e2ee_features` entry a broker implementing
// SPEC §7.6 advertises.
const featureRespBind = "resp-bind"

// WithResponseBinding makes the Router seal requests with the response binding
// (SPEC §7.6) to every provider whose quote, fetched by the warmer at the
// provider's on-chain URL, advertises it. It does nothing without the warmer
// (RunWarmer with an endpoint resolver), which is the only source it trusts: until
// a sweep has seen a provider advertise the feature, requests to it are sealed as
// before.
func WithResponseBinding() Option {
	return func(r *Router) { r.respBind = newRespBindStore(maxProviderIdentities) }
}

// quoteAdvertisesRespBind reports whether a /v1/quote reply lists the response
// binding among its `e2ee_features`. A reply without the field, or with one this
// version cannot read, does not.
func quoteAdvertisesRespBind(reply []byte) bool {
	var r struct {
		Features []string `json:"e2ee_features"`
	}
	if err := json.Unmarshal(reply, &r); err != nil {
		return false
	}
	return slices.Contains(r.Features, featureRespBind)
}

// respBindStore holds, per provider address, whether the warmer last saw that
// provider advertise the response binding. Safe for concurrent use.
type respBindStore struct {
	mu  sync.Mutex
	max int
	on  map[string]struct{}
}

func newRespBindStore(max int) *respBindStore {
	return &respBindStore{max: max, on: map[string]struct{}{}}
}

// observe records what a verified quote fetched at addr's on-chain URL said.
// Addresses compare case-insensitively: the catalog may use EIP-55 or lowercase.
func (s *respBindStore) observe(addr string, advertised bool) {
	key := strings.ToLower(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !advertised {
		delete(s.on, key)
		return
	}
	if _, ok := s.on[key]; !ok && len(s.on) >= s.max {
		// Bounded by the warmer's enumeration, which only reaches addresses with an
		// on-chain service; the cap is for a catalog that lists absurdly many. Not
		// binding is the behavior before this existed.
		return
	}
	s.on[key] = struct{}{}
}

// supports reports whether requests to addr are sealed with the binding.
func (s *respBindStore) supports(addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.on[strings.ToLower(addr)]
	return ok
}

// bindsResponse is what routeCandidates.Provider sets core.Provider.BindResponse
// from. Only on the quote-verified path: without a verified quote there is no
// enclave key whose holder the binding would authenticate.
func (r *Router) bindsResponse(addr string) bool {
	return r.respBind != nil && r.verifier != nil && r.respBind.supports(addr)
}
