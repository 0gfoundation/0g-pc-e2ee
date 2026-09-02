package openaiproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// endpoint.Image.Streams is false, and the shared handler must act on it: image
// generation returns one JSON object, so a `"stream": true` is a caller error
// rather than a mode to select. Before Streams existed this was expressed as
// "the image handler happens to have no streaming branch", so the field was
// neither honoured nor refused — it went to the provider as an ordinary
// cleartext field, and the core grafted a chat-profile `stream_options` next to
// it (see core.TestE2E_Image_NoStreamOptionsGrafted).
//
// Refusing it is the honest answer: the caller asked for a mode this surface
// cannot serve and has to learn that, the same reasoning Image.PreSeal applies
// to `response_format: "url"`. An explicit `"stream": false` is fine — some SDKs
// always send it — and so is its absence.
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
	Register(mux, endpoint.Image, core.New(core.Provider{
		URL:        upstream.URL,
		EncPubKey:  encPub,
		SignerAddr: "0x000000000000000000000000000000000000dEaD",
	}, core.WithEndpoint(endpoint.Image)))
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
