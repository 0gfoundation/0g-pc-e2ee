package route

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The preview body is everything NOT in sensitiveFields, so a set that does not
// match the service type does not fail — it silently ships the payload to the
// (untrusted) router. These two used to be independent options with the chat set
// hardcoded as the default, so configuring an image proxy with WithServiceType
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
			name:            "anthropic chat maps to the chat profile",
			serviceType:     serviceTypeAnthropicChat,
			mustWithhold:    []string{"messages"},
			mustPassThrough: []string{"model"},
		},
		{
			name:            "image withholds the prompt",
			serviceType:     ServiceTypeTextToImage,
			mustWithhold:    []string{"prompt"},
			mustPassThrough: []string{"model", "n", "size"},
		},
		{
			// Over-stripping only costs routing fidelity; under-stripping leaks.
			name:            "an unknown service type withholds every profile's payload",
			serviceType:     "speech-to-text",
			mustWithhold:    []string{"messages", "tools", "prompt"},
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
	// Deliberately ONLY WithServiceType — no WithSensitiveFields. That is the
	// configuration a caller would naturally write, and the one that used to leak.
	r := New(srv.URL, WithServiceType(ServiceTypeTextToImage))
	_, _ = r.Resolve(context.Background(), req)

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

// An explicit WithSensitiveFields still wins, in either option order, so an
// operator who seals extra fields can withhold those too.
func TestExplicitSensitiveFieldsOverrideTheServiceTypeDefault(t *testing.T) {
	custom := []string{"prompt", "user"}

	for _, name := range []string{"sensitive first", "service type first"} {
		t.Run(name, func(t *testing.T) {
			var r *Router
			if name == "sensitive first" {
				r = New("http://x", WithSensitiveFields(custom), WithServiceType(ServiceTypeTextToImage))
			} else {
				r = New("http://x", WithServiceType(ServiceTypeTextToImage), WithSensitiveFields(custom))
			}
			if _, ok := r.sensitiveFields["user"]; !ok {
				t.Error("an explicit sensitive-field set must survive New's service-type default")
			}
			if len(r.sensitiveFields) != len(custom) {
				t.Errorf("sensitiveFields = %v, want exactly the explicit set", r.sensitiveFields)
			}
		})
	}
}

// The default with no options at all stays the chat set — existing callers
// (the gateway, the sidecar) must be unaffected.
func TestDefaultRouterKeepsTheChatSensitiveSet(t *testing.T) {
	r := New("http://x")
	want := sliceToSet(wire.DefaultSealedFieldsFor(wire.ProfileChat))
	if len(r.sensitiveFields) != len(want) {
		t.Fatalf("sensitiveFields = %v, want the chat set %v", r.sensitiveFields, want)
	}
	for f := range want {
		if _, ok := r.sensitiveFields[f]; !ok {
			t.Errorf("chat sealed field %q must still be withheld by default", f)
		}
	}
}
