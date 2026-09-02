package core

import (
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A client is bound to one service type, which selects both the wire profile it
// seals/opens under and — unless the operator overrode it — the sealed set for
// that profile. Before this, core was chat-only by construction: it called the
// chat shorthands and defaulted to chat's fields, so an image request could not
// be built at all and an image response would have been opened under chat's
// rules.
func TestWithServiceTypeSelectsProfileAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		name        string
		serviceType string
		wantProfile wire.Profile
		wantFields  []string
	}{
		{"default is chat", "", wire.ProfileChat, wire.DefaultSealedFieldsFor(wire.ProfileChat)},
		{"chatbot", ServiceTypeChatbot, wire.ProfileChat, wire.DefaultSealedFieldsFor(wire.ProfileChat)},
		{"text-to-image", ServiceTypeTextToImage, wire.ProfileImage, wire.DefaultSealedFieldsFor(wire.ProfileImage)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.serviceType != "" {
				opts = append(opts, WithServiceType(tc.serviceType))
			}
			c := NewWithResolver(staticResolver{Provider{URL: DefaultProviderURL}}, opts...)
			if c.profile != tc.wantProfile {
				t.Errorf("profile = %q, want %q", c.profile, tc.wantProfile)
			}
			if !equalStrings(c.sealFields, tc.wantFields) {
				t.Errorf("sealFields = %v, want %v", c.sealFields, tc.wantFields)
			}
		})
	}
}

// An unrecognised service type must fail closed rather than fall back to chat.
// SPEC §1 covers two profiles; guessing chat for anything else would apply the
// wrong rules to a request shape nobody analysed — and would do it silently, for
// a service type that may not exist yet. The empty profile makes wire reject
// every seal and open.
func TestUnknownServiceTypeFailsClosedRatherThanDefaultingToChat(t *testing.T) {
	for _, st := range []string{"speech-to-text", "image-editing", "video-generation", "not-a-service"} {
		t.Run(st, func(t *testing.T) {
			c := NewWithResolver(staticResolver{Provider{URL: DefaultProviderURL}}, WithServiceType(st))
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
// option has run, so WithSealFields wins whichever side of WithServiceType it
// was passed on. Resolving it as a struct default instead would make the result
// depend on argument order — the bug route.Router's sensitiveFieldsSet exists to
// prevent.
func TestExplicitSealFieldsWinRegardlessOfOptionOrder(t *testing.T) {
	custom := []string{"prompt", "metadata"}
	for _, name := range []string{"service type first", "seal fields first"} {
		t.Run(name, func(t *testing.T) {
			opts := []Option{WithServiceType(ServiceTypeTextToImage), WithSealFields(custom)}
			if name == "seal fields first" {
				opts = []Option{WithSealFields(custom), WithServiceType(ServiceTypeTextToImage)}
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
