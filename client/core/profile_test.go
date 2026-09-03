package core

import (
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A client is bound to one surface, whose row selects both the wire profile it
// seals/opens under and — unless the operator overrode it — the sealed set for
// that profile. Before this, core was chat-only by construction: it called the
// chat shorthands and defaulted to chat's fields, so an image request could not
// be built at all and an image response would have been opened under chat's
// rules.
//
// Driven off endpoint.All rather than a list repeated here, so a row added to
// the table is covered by this test the day it lands instead of the day someone
// remembers to extend the fixture.
func TestWithEndpointSelectsProfileAndDefaults(t *testing.T) {
	cases := []struct {
		name       string
		ep         endpoint.Endpoint
		useDefault bool
	}{{"default is chat", endpoint.Chat, true}}
	for _, ep := range endpoint.All {
		cases = append(cases, struct {
			name       string
			ep         endpoint.Endpoint
			useDefault bool
		}{ep.Path, ep, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantProfile := tc.ep.Profile
			wantFields := wire.DefaultSealedFieldsFor(tc.ep.Profile)
			var opts []Option
			if !tc.useDefault {
				opts = append(opts, WithEndpoint(tc.ep))
			}
			c := NewWithResolver(staticResolver{Provider{URL: DefaultProviderURL}}, opts...)
			if c.ep.Profile != wantProfile {
				t.Errorf("profile = %q, want %q", c.ep.Profile, wantProfile)
			}
			if !equalStrings(c.sealFields, wantFields) {
				t.Errorf("sealFields = %v, want %v", c.sealFields, wantFields)
			}
			// The whole row reaches the resolver, so assert the row and not just the
			// service type: /v1/chat/completions and /v1/messages share "chatbot", so
			// a service-type-only check passes for a client bound to the wrong one.
			// Field-wise because Endpoint carries a func (PreSeal) and so is not
			// comparable with ==; these are the fields that identify a row.
			if got := c.ep; got.ServiceType != tc.ep.ServiceType || got.APIFormat != tc.ep.APIFormat ||
				got.Profile != tc.ep.Profile || got.Path != tc.ep.Path ||
				got.UpstreamPath != tc.ep.UpstreamPath || got.Streams != tc.ep.Streams {
				t.Errorf("ep = %+v, want %+v — the row is what the resolver is handed", got, tc.ep)
			}
		})
	}
}

// A surface the table does not carry must fail closed rather than fall back to
// chat. SPEC §1 covers two profiles; guessing chat for anything else would apply
// the wrong rules to a request shape nobody analysed — and would do it silently,
// for a service type that may not exist yet.
//
// With the string door gone this is a property of the ZERO Endpoint, which is
// what a table lookup will yield on a miss (and what a caller gets from an
// uninitialised value either way). Its empty profile is what wire rejects, and
// asserting that here is what keeps the old unknown-service-type guarantee
// standing now that no unknown STRING can reach this package.
//
// One case, not one per unrecognised name: every such name collapses to this
// same value before a client is built, so a loop over them would run the
// identical assertion five times and imply a coverage it does not have.
func TestUnknownSurfaceFailsClosedRatherThanDefaultingToChat(t *testing.T) {
	c := NewWithResolver(staticResolver{Provider{URL: DefaultProviderURL}}, WithEndpoint(endpoint.Endpoint{}))
	if c.ep.Profile == wire.ProfileChat {
		t.Fatalf("the zero Endpoint must not resolve to the chat profile")
	}
	if len(c.sealFields) != 0 {
		t.Errorf("sealFields = %v, want empty so sealing fails closed", c.sealFields)
	}
	// wire must refuse it, which is what makes the empty profile safe rather than
	// merely undefined.
	if err := wire.ValidateSealedFieldsFor(c.ep.Profile, []string{"messages"}); err == nil {
		t.Error("wire must reject an unknown profile")
	}
}

// Option order must not matter: the sealed-set default is resolved after every
// option has run, so WithSealFields wins whichever side of WithEndpoint it
// was passed on. Resolving it as a struct default instead would make the result
// depend on argument order — the bug route.Router's sensitiveFieldsSet exists to
// prevent. Folding the two options into one did NOT remove the need for it:
// the derived default still has to lose to an explicit override passed on either
// side, which is what the post-loop resolution buys.
func TestExplicitSealFieldsWinRegardlessOfOptionOrder(t *testing.T) {
	custom := []string{"prompt", "metadata"}
	for _, name := range []string{"service type first", "seal fields first"} {
		t.Run(name, func(t *testing.T) {
			opts := []Option{WithEndpoint(endpoint.Image), WithSealFields(custom)}
			if name == "seal fields first" {
				opts = []Option{WithSealFields(custom), WithEndpoint(endpoint.Image)}
			}
			c := NewWithResolver(staticResolver{Provider{URL: DefaultProviderURL}}, opts...)
			if !equalStrings(c.sealFields, custom) {
				t.Errorf("sealFields = %v, want the explicit %v", c.sealFields, custom)
			}
			if c.ep.Profile != wire.ProfileImage {
				t.Errorf("profile = %q, want image", c.ep.Profile)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
