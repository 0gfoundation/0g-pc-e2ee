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
		}{ep.ServiceType, ep, false})
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
			if c.profile != wantProfile {
				t.Errorf("profile = %q, want %q", c.profile, wantProfile)
			}
			if !equalStrings(c.sealFields, wantFields) {
				t.Errorf("sealFields = %v, want %v", c.sealFields, wantFields)
			}
			if c.serviceType != tc.ep.ServiceType {
				t.Errorf("serviceType = %q, want %q — it is what the resolver is asked for",
					c.serviceType, tc.ep.ServiceType)
			}
		})
	}
}

// A surface the table does not carry must fail closed rather than fall back to
// chat. SPEC §1 covers two profiles; guessing chat for anything else would apply
// the wrong rules to a request shape nobody analysed — and would do it silently,
// for a service type that may not exist yet. The empty profile makes wire reject
// every seal and open.
//
// The route to this state is endpoint.ByServiceType returning its zero Endpoint
// on a miss: a caller that ignores the ok and passes it here must land on the
// closed door rather than on chat's rules. That is why this drives the zero value
// through ByServiceType instead of constructing one directly — the miss path is
// the thing being tested.
func TestUnknownServiceTypeFailsClosedRatherThanDefaultingToChat(t *testing.T) {
	for _, st := range []string{"speech-to-text", "image-editing", "video-generation", "not-a-service", "anthropic-chat"} {
		t.Run(st, func(t *testing.T) {
			ep, ok := endpoint.ByServiceType(st)
			if ok {
				t.Fatalf("endpoint.ByServiceType(%q) reported a hit; this test is about the miss path", st)
			}
			c := NewWithResolver(staticResolver{Provider{URL: DefaultProviderURL}}, WithEndpoint(ep))
			if c.profile == wire.ProfileChat {
				t.Fatalf("service type %q must not resolve to the chat profile", st)
			}
			if len(c.sealFields) != 0 {
				t.Errorf("sealFields = %v, want empty so sealing fails closed", c.sealFields)
			}
			// wire must refuse it, which is what makes the empty profile safe
			// rather than merely undefined.
			if err := wire.ValidateSealedFieldsFor(c.profile, []string{"messages"}); err == nil {
				t.Error("wire must reject an unknown profile")
			}
		})
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
			if c.profile != wire.ProfileImage {
				t.Errorf("profile = %q, want image", c.profile)
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
