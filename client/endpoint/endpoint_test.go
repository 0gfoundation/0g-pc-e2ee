package endpoint

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Image.PreSeal. The image profile pins `response_format` to "b64_json" and requires it to be
// PRESENT — an omitted field is not defaulted at the protocol layer, because
// OpenAI's own default for the DALL·E family is `url`, so silence there is a
// request to publish the images in the clear (SPEC §7.1).
//
// Filling it in is this gateway's job precisely because it knows something the
// protocol cannot: its caller reached a sealed endpoint on purpose. An explicit
// conflicting value is still refused rather than rewritten — the caller asked
// for a format this mode cannot honour and has to learn that.
func TestWithB64ResponseFormat(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{
			name: "absent is filled in",
			in:   `{"model":"z-image","prompt":"a cat"}`,
			want: `"b64_json"`,
		},
		{
			name: "explicit b64_json is left alone",
			in:   `{"model":"z-image","prompt":"a cat","response_format":"b64_json"}`,
			want: `"b64_json"`,
		},
		{
			name:    "explicit url is refused, not rewritten",
			in:      `{"model":"z-image","prompt":"a cat","response_format":"url"}`,
			wantErr: "not supported for a sealed image request",
		},
		{
			name:    "non-string is refused",
			in:      `{"model":"z-image","response_format":1}`,
			wantErr: "must be the JSON string",
		},
		{
			// `null` is the absence of a value, not a value. Decoding it into a
			// string is a no-op that returns no error, so without an explicit
			// check it fell through to the value comparison and was rejected as
			// `response_format=""` — a confusing message for a field the caller
			// never set. Same reading wire.IsE2EESealed gives `_e2ee: null`.
			name: "null is treated as absent and filled in",
			in:   `{"model":"z-image","response_format":null}`,
			want: `"b64_json"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req wire.Request
			if err := json.Unmarshal([]byte(tc.in), &req); err != nil {
				t.Fatalf("bad fixture: %v", err)
			}
			_, hadBefore := req[fieldResponseFormat]
			out, err := imagePreSeal(req)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error, got %s", out[fieldResponseFormat])
				}
				if got := err.Error(); !strings.Contains(got, tc.wantErr) {
					t.Fatalf("error = %q, want it to mention %q", got, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := string(out[fieldResponseFormat]); got != tc.want {
				t.Errorf("response_format = %s, want %s", got, tc.want)
			}
			// The caller's map must never be mutated: the same request is
			// re-sealed to each fallback candidate, so an in-place write would
			// leak one attempt's normalisation into the next.
			//
			// The previous form of this check could not fail — its outer guard
			// required the field to be ABSENT and its inner one required it to be
			// PRESENT — so it passed against a version of imagePreSeal that wrote
			// through. Compare presence across the call instead.
			if _, hasAfter := req[fieldResponseFormat]; hasAfter != hadBefore {
				t.Errorf("the caller's request was mutated: %s presence went %v -> %v",
					fieldResponseFormat, hadBefore, hasAfter)
			}
		})
	}
}

// Defaulting must not disturb the rest of the body — the cleartext fields are
// what the router routes and bills on.
func TestWithB64ResponseFormatPreservesOtherFields(t *testing.T) {
	var req wire.Request
	if err := json.Unmarshal([]byte(`{"model":"z-image","prompt":"a cat","n":2,"size":"1024x1024"}`), &req); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	out, err := imagePreSeal(req)
	if err != nil {
		t.Fatalf("imagePreSeal: %v", err)
	}
	for _, k := range []string{"model", "prompt", "n", "size"} {
		if string(out[k]) != string(req[k]) {
			t.Errorf("%q = %s, want it untouched (%s)", k, out[k], req[k])
		}
	}
	if _, added := req[fieldResponseFormat]; added {
		t.Error("the caller's request must not be mutated")
	}
}

// All is the registry every other layer reads, so a malformed row does not fail
// here — it fails somewhere else, at runtime: a refused request, or a surface
// silently confused with another that shares one of its fields. This is where
// those are caught instead.
//
// It is also the only place the empty-UpstreamPath guard in route.upstreamURL is
// exercised at all: with the real table that branch is unreachable, so without
// this nothing checks the property it defends.
func TestAllRowsAreWellFormed(t *testing.T) {
	if len(All) == 0 {
		t.Fatal("All is empty; the gateway would mount nothing")
	}
	byPath := map[string]int{}
	bySurface := map[string]int{}
	for i, ep := range All {
		name := ep.Path
		if name == "" {
			name = "row " + strconv.Itoa(i)
		}
		if ep.ServiceType == "" {
			t.Errorf("%s: no ServiceType — the resolver could not ask the router for it", name)
		}
		if ep.Profile == "" {
			t.Errorf("%s: no Profile — every seal and open would fail closed", name)
		} else if fields := wire.DefaultSealedFieldsFor(ep.Profile); len(fields) == 0 {
			t.Errorf("%s: Profile %q is unknown to wire — it would seal nothing", name, ep.Profile)
		}
		if ep.Path == "" {
			t.Errorf("%s: no Path — nothing to mount", name)
		}
		if ep.UpstreamPath == "" {
			t.Errorf("%s: no UpstreamPath — route would POST the sealed request to the bare router origin", name)
		}
		// Path is the row's IDENTITY, and the only field that has to be unique.
		// Every layer keys off it: proxycli's client map, the gateway's mount loop
		// (a duplicate would mount the same pattern twice and panic), metrics'
		// route label, and direct mode's "chat only" check.
		if j, dup := byPath[ep.Path]; dup {
			t.Errorf("rows %d and %d share Path %q; it is the key every layer uses, so one would shadow the other", j, i, ep.Path)
		}
		byPath[ep.Path] = i
		// ServiceType alone is deliberately NOT unique — Chat and Anthropic are
		// both "chatbot", one provider pool answering two request shapes. What must
		// stay unique is the PAIR the router resolves a pool from: two rows with the
		// same (service type, api_format) would preview identically and be
		// indistinguishable upstream, which is a table bug even though each row
		// serves its own path.
		surface := ep.ServiceType + "\x00" + ep.APIFormat
		if j, dup := bySurface[surface]; dup {
			t.Errorf("rows %d and %d share (ServiceType %q, APIFormat %q); they would preview the same pool",
				j, i, ep.ServiceType, ep.APIFormat)
		}
		bySurface[surface] = i
	}
}

// The zero Endpoint must fail closed for SEALING: its empty profile is unknown to
// wire, so every seal and open rejects it rather than falling back to chat's
// rules on a request shape nobody analysed.
//
// It is stated here because the zero value is reachable — a struct literal that
// forgot a field, or a caller that built one by hand — and because the OTHER half
// of the promise does not hold: wire.DefaultSealedFieldsFor of the empty profile
// is the EMPTY set, so a caller asking the zero row "what must I withhold from
// the untrusted router" is told "nothing". route.sensitiveFieldsFor keys its
// fallback on that empty answer for exactly this reason.
func TestZeroEndpointFailsClosedForSealing(t *testing.T) {
	var zero Endpoint
	if fields := wire.DefaultSealedFieldsFor(zero.Profile); len(fields) != 0 {
		t.Errorf("the zero profile has default sealed fields %v; the fail-closed argument assumes it has none", fields)
	}
	if err := wire.ValidateSealedFieldsFor(zero.Profile, []string{"messages"}); err == nil {
		t.Error("wire accepted a sealed set for the zero profile; a malformed row would seal under no rules at all")
	}
}
