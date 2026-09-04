package wire

import (
	"slices"
	"testing"
)

// Profiles must report EVERY profile the table defines, because its whole job is
// to answer "what could a request shape I do not recognise be?" for a caller
// building a fail-safe union.
//
// Comparing against the table itself rather than a list written here is the
// point: a fourth profile joins the union by being added to `profiles`, and a
// Profiles that returned a hand-maintained list would pass a fixture naming the
// three that exist today while silently narrowing the union the day a fourth
// lands. The caller this protects — route's withheld-field set, whose preview
// body is the COMPLEMENT of the union — turns a narrowed set into an upload, not
// an error.
func TestProfilesCoversEveryDefinedProfile(t *testing.T) {
	got := Profiles()
	if len(got) != len(profiles) {
		t.Fatalf("Profiles() returned %d profiles, but the table defines %d: %v", len(got), len(profiles), got)
	}
	for p := range profiles {
		if !slices.Contains(got, p) {
			t.Errorf("profile %q is defined but not reported by Profiles()", p)
		}
	}
	// Sorted, so a caller that renders or hashes the result gets a stable answer
	// rather than Go's randomised map order.
	if !slices.IsSorted(got) {
		t.Errorf("Profiles() = %v, want it sorted", got)
	}
	// Every reported profile must actually resolve — a name with no spec behind it
	// would contribute nothing to the union while looking like it did.
	for _, p := range got {
		if _, err := p.spec(); err != nil {
			t.Errorf("Profiles() reported %q, which has no spec: %v", p, err)
		}
	}
}

// The union a fail-safe caller builds over Profiles() must cover the fields that
// belong to a profile a given deployment does NOT serve. `system` is the case
// that matters: it is ProfileAnthropic's alone, so a union taken over the
// surfaces a chat-and-image gateway mounts would omit it.
func TestProfilesUnionCoversFieldsNoChatOrImageProfileHas(t *testing.T) {
	// The premise, checked BEFORE anything is asserted: `system` is in the union
	// only via a profile chat and image do not cover. If either ever seals it the
	// assertions below would pass for the wrong reason, so skip rather than assert.
	if slices.Contains(DefaultSealedFieldsFor(ProfileChat), "system") ||
		slices.Contains(DefaultSealedFieldsFor(ProfileImage), "system") {
		t.Skip("chat or image now seals `system`; this test's premise no longer holds")
	}
	var union []string
	for _, p := range Profiles() {
		for _, f := range DefaultSealedFieldsFor(p) {
			if !slices.Contains(union, f) {
				union = append(union, f)
			}
		}
	}
	for _, f := range []string{"messages", "tools", "prompt", "system"} {
		if !slices.Contains(union, f) {
			t.Errorf("the union over Profiles() is missing %q: %v", f, union)
		}
	}
}

// Every profile's own SHIPPED DEFAULTS must satisfy that profile's own rules.
//
// This is the coverage the per-request checks structurally cannot give. Those
// run only for profiles a given binary actually serves, and only for requests
// it actually receives, so a table edit that makes a default set inconsistent
// with its own profile is invisible until the first request on that surface —
// which is after the upstream call, hence after the bill. Here it is one
// assertion per row, for every row, at compile-and-test time.
//
// It is a test rather than a runtime check for the reason SealRequestFor's two
// validators are split: these inputs are CONSTANTS of this package, so their
// verdict never changes between runs. What the runtime checks answer instead is
// what a CALLER supplied — a set from core.WithSealFields, a request from a
// user — which this can say nothing about.
func TestEveryProfileDefaultSatisfiesItsOwnRules(t *testing.T) {
	for _, p := range Profiles() {
		t.Run(string(p), func(t *testing.T) {
			spec, err := p.spec()
			if err != nil {
				t.Fatalf("spec(): %v", err)
			}
			sealed := DefaultSealedFieldsFor(p)
			// The default set must pass the same name-only validation a caller's
			// set does: it contains the payload field, has no duplicates, and
			// seals away neither pin family's field.
			if err := ValidateSealedFieldsFor(p, sealed); err != nil {
				t.Errorf("the shipped default sealed set %v is invalid for its own profile: %v", sealed, err)
			}
			// Every payload field must be in the default set, optional ones
			// included. Otherwise the default itself leaks: a request carrying
			// Anthropic's `system`, or a transcription carrying `filename`, would
			// be refused by validatePayloadSealedFor — or worse, accepted by a
			// caller who skips it, handing the field to the router in the clear.
			//
			// defaultRequestSealed derives the set from `payload`, so this now
			// holds by construction; it stays asserted because the derivation is
			// what makes it hold, and that is a thing a future edit can undo.
			for _, f := range spec.payload {
				if !slices.Contains(sealed, f.name) {
					t.Errorf("%q is payload but missing from the default sealed set %v", f.name, sealed)
				}
			}
			// The shipped unbound default must be usable with the shipped sealed
			// default, for EVERY profile — not just whichever one a binary serves.
			// A mismatch here is the "passed startup clean, then failed 100% of
			// requests" failure that ValidateUnboundFieldsFor exists to prevent.
			if err := ValidateUnboundFieldsFor(p, DefaultUnboundFields(), sealed); err != nil {
				t.Errorf("the shipped default unbound set %v is unusable with the default sealed set %v: %v",
					DefaultUnboundFields(), sealed, err)
			}

			// Response side. A frame-typed profile has no profile-wide default
			// (the sealed set is a property of the frame), and so does one whose
			// set is not constant — both correctly report an empty set, which is
			// the "fail on the first request rather than on the first UNUSUAL
			// request" choice DefaultResponseSealedFieldsFor documents.
			respDefault := DefaultResponseSealedFieldsFor(p)
			if ResponseFramesAreTyped(p) || spec.hasOptionalResponsePayload() {
				if len(respDefault) != 0 {
					t.Errorf("profile has no constant response default, but got %v", respDefault)
				}
			} else {
				for _, f := range spec.responsePayload {
					if !slices.Contains(respDefault, f.name) {
						t.Errorf("the default response sealed set %v omits %q, which every frame must seal",
							respDefault, f.name)
					}
				}
			}
			// An OPTIONAL response payload field must never reach the always-sealed
			// default: SealFrame refuses a sealed field the frame does not have, so
			// a default naming `segments` would reject every plain `json` response.
			// Deriving the default from one list is what enforces that — while the
			// two were separate lists, a name could sit in both.
			for _, f := range spec.responsePayload {
				if f.optional && slices.Contains(spec.alwaysSealedResponseFields(), f.name) {
					t.Errorf("%q is optional but reached the always-sealed response set", f.name)
				}
			}
			// The request-side twin, on the PINS. A field pinned twice would draw
			// two verdicts from one request — pinFor answers with the first entry
			// while validatePinnedValues checks every one — so a mandatory and an
			// optional entry for the same field would disagree about whether
			// absence is compliant, and which error a caller saw would depend on
			// declaration order. One entry per field is what makes that
			// unrepresentable rather than merely unlikely.
			seenPin := map[string]bool{}
			for _, p := range spec.pinned {
				if seenPin[p.field] {
					t.Errorf("%q is pinned twice: two entries for one field can disagree about "+
						"whether absence is compliant", p.field)
				}
				seenPin[p.field] = true
			}
		})
	}
}
