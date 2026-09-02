package endpoint

import (
	"encoding/json"
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
