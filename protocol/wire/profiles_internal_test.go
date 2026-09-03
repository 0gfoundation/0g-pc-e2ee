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
