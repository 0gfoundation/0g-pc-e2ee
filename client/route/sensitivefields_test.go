package route

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The preview body is everything NOT in sensitiveFields, so a set that does not
// match the service type does not fail — it silently ships the payload to the
// (untrusted) router. These two used to be independent options with the chat set
// hardcoded as the default, so configuring an image proxy with WithEndpoint
// alone previewed the prompt in the clear.
func TestSensitiveFieldsFollowTheServiceType(t *testing.T) {
	tests := []struct {
		name            string
		serviceType     string
		mustWithhold    []string
		mustPassThrough []string
	}{
		{
			name:            "chat",
			serviceType:     DefaultServiceType,
			mustWithhold:    []string{"messages", "tools"},
			mustPassThrough: []string{"model"},
		},
		{
			// endpoint.All does not carry Anthropic, so this now exercises the
			// unrecognised-type branch rather than a case of its own — and must still
			// withhold the TOP-LEVEL "system" field the chat set does not cover.
			//
			// That is the whole reason the union is taken over wire.Profiles() and not
			// over endpoint.All: `system` belongs to a profile the protocol defines and
			// this gateway does not mount, so a union over mounted surfaces would drop
			// it. Since the preview body is the COMPLEMENT of this set, dropping a
			// field here does not fail — it uploads it.
			name:            "a profile the table does not carry still withholds its payload",
			serviceType:     "anthropic-chat",
			mustWithhold:    []string{"messages", "tools", "system"},
			mustPassThrough: []string{"model", "max_tokens"},
		},
		{
			name:            "image withholds the prompt",
			serviceType:     ServiceTypeTextToImage,
			mustWithhold:    []string{"prompt"},
			mustPassThrough: []string{"model", "n", "size"},
		},
		{
			// Over-stripping only costs routing fidelity; under-stripping leaks.
			name:            "an unknown service type withholds every payload field",
			serviceType:     "speech-to-text",
			mustWithhold:    []string{"messages", "tools", "prompt", "system"},
			mustPassThrough: []string{"model"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sliceToSet(sensitiveFieldsForServiceType(tt.serviceType))
			for _, f := range tt.mustWithhold {
				if _, ok := got[f]; !ok {
					t.Errorf("%q must be withheld from the preview for service type %q", f, tt.serviceType)
				}
			}
			for _, f := range tt.mustPassThrough {
				if _, ok := got[f]; ok {
					t.Errorf("%q is a routing field and must reach the preview for service type %q", f, tt.serviceType)
				}
			}
		})
	}
}

// End to end through New + preview: an image-configured Router must not put the
// prompt on the wire, with no second option needed to make that true.
func TestImagePreviewDoesNotSendThePromptToTheRouter(t *testing.T) {
	var body map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != previewPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		// An empty candidate list ends Resolve with an error; the assertion is on
		// what was SENT, which is already captured.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providers":[]}`))
	}))
	defer srv.Close()

	req := wire.Request{
		"model":           json.RawMessage(`"z-image"`),
		"n":               json.RawMessage(`2`),
		"size":            json.RawMessage(`"1024x1024"`),
		"response_format": json.RawMessage(`"b64_json"`),
		"prompt":          json.RawMessage(`"my secret prompt"`),
	}
	// No WithSensitiveFields: the withheld set follows the service type of the
	// REQUEST, which is what a caller passes to Resolve. That is the natural
	// configuration and the one that used to leak.
	r := New(srv.URL)
	_, _ = r.Resolve(context.Background(), ServiceTypeTextToImage, req)

	if body == nil {
		t.Fatal("preview was never called")
	}
	if _, leaked := body["prompt"]; leaked {
		t.Fatalf("the prompt was sent to the router in the preview body: %v", body)
	}
	for _, f := range []string{"model", "n", "size"} {
		if _, ok := body[f]; !ok {
			t.Errorf("routing field %q must still reach the preview", f)
		}
	}
	var svcType string
	if err := json.Unmarshal(body["service_type"], &svcType); err != nil {
		t.Fatalf("preview body carries no service_type: %v", err)
	}
	if svcType != ServiceTypeTextToImage {
		t.Errorf("service_type = %q, want %q", svcType, ServiceTypeTextToImage)
	}
}

// A service type endpoint.All does not carry is refused BEFORE anything reaches
// the router: Resolve resolves the upstream path first, so an unmounted surface
// never previews at all.
//
// This is what replaced the end-to-end leak test for /v1/messages. That test
// drove a real preview because upstreamURL had an "anthropic-chat" case; with
// the surface out of the table there is no path to preview, so the assertion
// worth making is the refusal — and that the router heard nothing.
//
// The withheld set is still asserted, directly, in the table above: it is the
// defence that would matter if a future caller ever reached preview without this
// gate, which is exactly why it must be correct on its own terms rather than
// because of the ordering here.
func TestUnmountedServiceTypeIsRefusedBeforePreview(t *testing.T) {
	var body map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != previewPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"providers":[]}`))
	}))
	defer srv.Close()

	req := wire.Request{
		"model":      json.RawMessage(`"claude-x"`),
		"max_tokens": json.RawMessage(`1024`),
		"system":     json.RawMessage(`"my secret system prompt"`),
		"messages":   json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}
	r := New(srv.URL)
	_, err := r.Resolve(context.Background(), "anthropic-chat", req)
	if err == nil {
		t.Fatal("Resolve must refuse a service type the endpoint table does not carry")
	}
	if !strings.Contains(err.Error(), "anthropic-chat") {
		t.Errorf("the refusal must name the service type, got %v", err)
	}
	// The point of refusing early: the untrusted router was never spoken to, so
	// the system prompt could not have reached it whatever the withheld set says.
	if body != nil {
		t.Errorf("preview was called for an unmounted service type; the router saw %v", body)
	}
}

// WithSensitiveFields ADDS to whatever the request's service type withholds. It
// used to replace, which read as "withhold exactly these" — and with one router
// now serving every endpoint, a chat-shaped override would then have become the
// withheld set for image and Anthropic requests too. Since the preview body is
// everything NOT withheld, that does not fail; it uploads the payload. Adding
// cannot.
func TestExplicitSensitiveFieldsAddToTheServiceTypeDefault(t *testing.T) {
	r := New("http://x", WithSensitiveFields([]string{"user", "metadata"}))

	// The operator's extra fields are withheld for every service type...
	for _, st := range []string{DefaultServiceType, ServiceTypeTextToImage, "anthropic-chat"} {
		got := r.withheldForServiceType(st)
		for _, f := range []string{"user", "metadata"} {
			if _, ok := got[f]; !ok {
				t.Errorf("%q must be withheld for service type %q", f, st)
			}
		}
	}
	// ...and the service type's own payload survives alongside them, which is
	// exactly what replacing destroyed.
	if _, ok := r.withheldForServiceType(ServiceTypeTextToImage)["prompt"]; !ok {
		t.Error("an image request must still withhold its prompt")
	}
	if _, ok := r.withheldForServiceType(DefaultServiceType)["messages"]; !ok {
		t.Error("a chat request must still withhold its messages")
	}
	if _, ok := r.withheldForServiceType("anthropic-chat")["system"]; !ok {
		t.Error("an Anthropic request must still withhold its top-level system prompt")
	}
}

// A chat-shaped override — which is what -seal-fields is — must not be able to
// strip the image payload out of the withheld set. This is the concrete leak the
// additive semantics prevent, stated as its own case because it is the one that
// motivated the change.
func TestAChatOverrideCannotUnwithholdTheImagePrompt(t *testing.T) {
	r := New("http://x", WithSensitiveFields(wire.DefaultSealedFieldsFor(wire.ProfileChat)))
	if _, ok := r.withheldForServiceType(ServiceTypeTextToImage)["prompt"]; !ok {
		t.Fatal("a chat-shaped override must not expose the image prompt to the preview")
	}
}

// A router with no options withholds the chat payload for a chat request —
// existing callers (the gateway, the sidecar) must be unaffected.
func TestDefaultRouterKeepsTheChatSensitiveSet(t *testing.T) {
	got := New("http://x").withheldForServiceType(DefaultServiceType)
	want := sliceToSet(wire.DefaultSealedFieldsFor(wire.ProfileChat))
	if len(got) != len(want) {
		t.Fatalf("withheld = %v, want the chat set %v", got, want)
	}
	for f := range want {
		if _, ok := got[f]; !ok {
			t.Errorf("chat sealed field %q must still be withheld by default", f)
		}
	}
}

// A nil or empty set is a no-op. It was never able to mean "withhold nothing"
// under the additive semantics, but the option still ignores it explicitly so a
// caller that computes an empty list gets the profile default rather than a
// silently unchanged router it might read as configured.
func TestWithSensitiveFieldsIgnoresAnEmptySet(t *testing.T) {
	for _, tt := range []struct {
		name   string
		fields []string
	}{
		{"nil", nil},
		{"empty", []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := New("http://x", WithSensitiveFields(tt.fields)).withheldForServiceType(ServiceTypeTextToImage)
			if _, ok := got["prompt"]; !ok {
				t.Errorf("the service-type default must survive: %v", got)
			}
		})
	}
}

// The upstream path is derived from the request's service type, not fixed at
// construction. Fixing it is how every sealed image request came to be POSTed to
// /v1/chat/completions — where the router hands it to the chatbot handler, whose
// pool does not contain the pinned image provider, so every real image request
// would have failed.
//
// Nothing caught that: the core e2e pinned Provider.URL directly and bypassed
// this package, and the gateway tests passed a nil image client. Neither ever
// reached the line that builds the URL. This is that line.
func TestUpstreamURLFollowsTheServiceType(t *testing.T) {
	r := New("http://router.example")
	for _, tc := range []struct {
		serviceType string
		want        string
	}{
		{DefaultServiceType, "http://router.example/v1/chat/completions"},
		{ServiceTypeTextToImage, "http://router.example/v1/images/generations"},
	} {
		t.Run(tc.serviceType, func(t *testing.T) {
			got, err := r.upstreamURL(tc.serviceType)
			if err != nil {
				t.Fatalf("upstreamURL(%q): %v", tc.serviceType, err)
			}
			if got != tc.want {
				t.Errorf("upstreamURL(%q) = %q, want %q", tc.serviceType, got, tc.want)
			}
		})
	}
}

// An unknown service type has no upstream path, and there is no safe guess:
// falling back to chat would preview the wrong pool AND send the request to the
// chat endpoint AND withhold the chat payload fields from a body that does not
// have them — uploading whatever it does have. Refuse before any of that.
func TestUnknownServiceTypeHasNoUpstreamURL(t *testing.T) {
	r := New("http://router.example")
	for _, st := range []string{"speech-to-text", "image-editing", "video-generation", ""} {
		if _, err := r.upstreamURL(st); err == nil {
			t.Errorf("service type %q must have no upstream path", st)
		}
	}
	// And Resolve refuses before it previews anything, so the router never even
	// learns the request exists.
	if _, err := r.Resolve(context.Background(), "speech-to-text", wire.Request{}); err == nil {
		t.Error("Resolve must refuse an unknown service type")
	}
}

// The end-to-end shape of the fix: a candidate materialized for an image request
// carries the image endpoint as its upstream URL.
func TestResolvedProviderURLMatchesTheRequestsServiceType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case previewPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"providers": []map[string]any{{
				"address":      "0x1111111111111111111111111111111111111111",
				"endpoint":     "http://provider.example",
				"canonical_id": "z-image",
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cands, err := New(srv.URL).Resolve(context.Background(), ServiceTypeTextToImage, wire.Request{
		"model":  json.RawMessage(`"z-image"`),
		"prompt": json.RawMessage(`"secret"`),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	rc, ok := cands.(*routeCandidates)
	if !ok {
		t.Fatalf("candidates type = %T", cands)
	}
	want := srv.URL + endpoint.Image.UpstreamPath
	if rc.upstreamURL != want {
		t.Errorf("candidate upstream URL = %q, want %q", rc.upstreamURL, want)
	}
}
