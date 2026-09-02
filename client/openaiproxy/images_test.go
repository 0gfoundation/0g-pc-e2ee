package openaiproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The image profile pins `response_format` to "b64_json" and requires it to be
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
			out, err := withB64ResponseFormat(req)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error, got %s", out[fieldResponseFormat])
				}
				if got := err.Error(); !contains(got, tc.wantErr) {
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
			// re-sealed to each fallback candidate.
			if _, mutated := req[fieldResponseFormat]; !mutated && len(req) != 0 {
				if _, had := req[fieldResponseFormat]; had {
					t.Error("the caller's request was mutated")
				}
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
	out, err := withB64ResponseFormat(req)
	if err != nil {
		t.Fatalf("withB64ResponseFormat: %v", err)
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

// Image generation has no stream: it returns one JSON object. The chat handler
// branches on `stream` (streamRequested → serveStream); the image handler has no
// such branch, so before this check a `"stream": true` was neither honoured nor
// refused — it was forwarded to the provider as an ordinary cleartext field, and
// the client core then grafted a chat-profile `stream_options` alongside it (see
// core.TestE2E_Image_NoStreamOptionsGrafted).
//
// Refusing it is the honest answer: the caller asked for a mode this endpoint
// cannot serve and has to learn that, the same reasoning withB64ResponseFormat
// applies to `response_format: "url"`. An explicit `"stream": false` is fine —
// some SDKs always send it — and so is its absence.
func TestImagesRejectStreaming(t *testing.T) {
	// Only the public half is needed: nothing here ever opens an envelope — the
	// upstream records that it was reached and refuses.
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}

	// Atomic: the handler runs on the server's goroutine while the assertions
	// read it from the test's.
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		http.Error(w, "the request must never have reached a provider", http.StatusTeapot)
	}))
	defer upstream.Close()

	mux := http.NewServeMux()
	RegisterImages(mux, core.New(core.Provider{
		URL:        upstream.URL,
		EncPubKey:  encPub,
		SignerAddr: "0x000000000000000000000000000000000000dEaD",
	}, core.WithServiceType(core.ServiceTypeTextToImage)))
	proxy := httptest.NewServer(mux)
	defer proxy.Close()

	for _, tc := range []struct {
		name       string
		body       string
		wantStatus int
		wantHits   int
	}{
		{
			name:       "stream true is refused before anything is sealed",
			body:       `{"model":"z-image","prompt":"a cat","stream":true}`,
			wantStatus: http.StatusBadRequest,
			wantHits:   0,
		},
		{
			// Rejected for the same reason the chat path rejects it, so a caller
			// gets one answer for a malformed `stream` whichever endpoint they hit.
			name:       "non-boolean stream is refused",
			body:       `{"model":"z-image","prompt":"a cat","stream":"yes"}`,
			wantStatus: http.StatusBadRequest,
			wantHits:   0,
		},
		{
			// Not an error: an explicit false says the caller wants exactly what
			// this endpoint does. It must reach the provider rather than being
			// refused for naming the field at all — the upstream's own 418 comes
			// back verbatim, which is how we know it got there.
			name:       "stream false is allowed through",
			body:       `{"model":"z-image","prompt":"a cat","stream":false}`,
			wantStatus: http.StatusTeapot,
			wantHits:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstreamHits.Store(0)
			resp, err := http.Post(proxy.URL+"/v1/images/generations", "application/json",
				strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", resp.StatusCode, tc.wantStatus, body)
			}
			if got := upstreamHits.Load(); got != int64(tc.wantHits) {
				t.Errorf("upstream was hit %d times, want %d: a refusal must happen "+
					"before the request is sealed and sent", got, tc.wantHits)
			}
			if tc.wantStatus == http.StatusBadRequest && !contains(string(body), "stream") {
				t.Errorf("the error must name the field it is about, got %s", body)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
