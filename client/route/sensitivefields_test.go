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
		ep              endpoint.Endpoint
		mustWithhold    []string
		mustPassThrough []string
	}{
		{
			name:            "chat",
			ep:              endpoint.Chat,
			mustWithhold:    []string{"messages", "tools"},
			mustPassThrough: []string{"model"},
		},
		{
			// The Anthropic row's own set, not the unrecognised-profile branch it used
			// to fall into. The field that matters is the TOP-LEVEL "system", which the
			// chat set does not cover: serving this surface under the chat profile
			// would upload the system prompt to the router, because the preview body is
			// the COMPLEMENT of this set — dropping a field here does not fail, it
			// leaks.
			//
			// max_tokens must pass through: it is cleartext, required by the surface,
			// and a routing signal the router filters providers on.
			name:            "anthropic withholds the top-level system prompt",
			ep:              endpoint.Anthropic,
			mustWithhold:    []string{"messages", "tools", "system"},
			mustPassThrough: []string{"model", "max_tokens"},
		},
		{
			name:            "image withholds the prompt",
			ep:              endpoint.Image,
			mustWithhold:    []string{"prompt"},
			mustPassThrough: []string{"model", "n", "size"},
		},
		{
			// A row whose profile wire does not know — the zero Endpoint is the
			// reachable case — withholds every payload field any profile has.
			// Over-stripping only costs routing fidelity; under-stripping leaks, and
			// the empty answer wire gives for an unknown profile is the leaking one.
			name:            "a row with an unknown profile withholds every payload field",
			ep:              endpoint.Endpoint{ServiceType: "speech-to-text"},
			mustWithhold:    []string{"messages", "tools", "prompt", "system"},
			mustPassThrough: []string{"model"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sliceToSet(sensitiveFieldsFor(tt.ep))
			for _, f := range tt.mustWithhold {
				if _, ok := got[f]; !ok {
					t.Errorf("%q must be withheld from the preview for %s", f, tt.name)
				}
			}
			for _, f := range tt.mustPassThrough {
				if _, ok := got[f]; ok {
					t.Errorf("%q is a routing field and must reach the preview for %s", f, tt.name)
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
	_, _ = r.Resolve(context.Background(), endpoint.Image, req)

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

// End to end through New + preview for the Anthropic surface: the two facts the
// router needs and the one it must never see.
//
// This replaces a test that asserted /v1/messages was REFUSED before preview,
// which was correct only while the surface was out of the endpoint table. Now
// that it is a row, the assertions worth making are the positive ones — and they
// are the two independent ways this surface can go wrong:
//
//   - the top-level `system` must not be on the wire. It is payload the CHAT
//     profile has no opinion about, so a row serving /v1/messages under
//     ProfileChat would upload it here, silently, since the preview body is the
//     complement of the withheld set.
//   - `api_format: "anthropic"` must be on the wire, alongside the plain
//     `chatbot` service type. The router refuses "anthropic-chat" AS a
//     service_type (its previewServiceType takes only the four catalog values)
//     and reads the surface off this separate field, so sending the pair as one
//     string 400s every request while omitting the field previews the OpenAI pool
//     and can pin a provider that does not serve /v1/messages at all.
func TestAnthropicPreviewWithholdsSystemAndNamesItsSurface(t *testing.T) {
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
		"model":      json.RawMessage(`"claude-x"`),
		"max_tokens": json.RawMessage(`1024`),
		"system":     json.RawMessage(`"my secret system prompt"`),
		"messages":   json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}
	// No WithSensitiveFields: the withheld set follows the row, which is the
	// natural configuration and the one that used to leak.
	_, _ = New(srv.URL).Resolve(context.Background(), endpoint.Anthropic, req)

	if body == nil {
		t.Fatal("preview was never called")
	}
	for _, f := range []string{"system", "messages"} {
		if _, leaked := body[f]; leaked {
			t.Errorf("%q was sent to the router in the preview body: %v", f, body)
		}
	}
	for _, f := range []string{"model", "max_tokens"} {
		if _, ok := body[f]; !ok {
			t.Errorf("routing field %q must still reach the preview", f)
		}
	}
	var svcType, apiFormat string
	if err := json.Unmarshal(body["service_type"], &svcType); err != nil {
		t.Fatalf("preview body carries no service_type: %v", err)
	}
	if svcType != endpoint.Anthropic.ServiceType {
		t.Errorf("service_type = %q, want %q — the router refuses %q as a service type",
			svcType, endpoint.Anthropic.ServiceType, "anthropic-chat")
	}
	raw, ok := body["api_format"]
	if !ok {
		t.Fatalf("preview body carries no api_format; the router would rank the OpenAI pool: %v", body)
	}
	if err := json.Unmarshal(raw, &apiFormat); err != nil {
		t.Fatalf("api_format is not a JSON string: %v", err)
	}
	if apiFormat != "anthropic" {
		t.Errorf("api_format = %q, want %q", apiFormat, "anthropic")
	}
}

// The chat surface must NOT send api_format. Omitted and "openai" mean the same
// thing to the router — neither narrows, because OpenAI is the default surface
// every chat provider answers and many do not enumerate it in `api_formats` —
// so the field would be noise on the one hand, and on the other its presence
// here is what proves the Anthropic assertion above is testing the row rather
// than a constant someone added to every preview body.
func TestChatPreviewSendsNoAPIFormat(t *testing.T) {
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

	_, _ = New(srv.URL).Resolve(context.Background(), endpoint.Chat, chatReq())
	if body == nil {
		t.Fatal("preview was never called")
	}
	if raw, sent := body["api_format"]; sent {
		t.Errorf("chat sent api_format=%s; omitted and \"openai\" are equivalent upstream, so it must be omitted", raw)
	}
}

// A row with no UpstreamPath is refused BEFORE anything reaches the router:
// Resolve resolves the upstream path first, so a malformed row never previews at
// all. Left unchecked it would POST the sealed request to the bare router origin.
//
// The withheld set deliberately does NOT fail for the same row — sensitiveFieldsFor
// answers over-strippingly — because the two questions have opposite safe answers:
// refusing to send is safe, refusing to withhold is a leak.
func TestRowWithoutUpstreamPathIsRefusedBeforePreview(t *testing.T) {
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
		"model":    json.RawMessage(`"claude-x"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}
	broken := endpoint.Endpoint{ServiceType: "chatbot", Profile: endpoint.Chat.Profile, Path: "/v1/nowhere"}
	_, err := New(srv.URL).Resolve(context.Background(), broken, req)
	if err == nil {
		t.Fatal("Resolve must refuse a row with no upstream path")
	}
	if !strings.Contains(err.Error(), "/v1/nowhere") {
		t.Errorf("the refusal must name the row, got %v", err)
	}
	// The point of refusing early: the untrusted router was never spoken to, so
	// the payload could not have reached it whatever the withheld set says.
	if body != nil {
		t.Errorf("preview was called for a malformed row; the router saw %v", body)
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

	// The operator's extra fields are withheld on every surface — every row in
	// the table, so a row added later is covered here the day it lands...
	for _, ep := range endpoint.All {
		got := r.withheldFor(ep)
		for _, f := range []string{"user", "metadata"} {
			if _, ok := got[f]; !ok {
				t.Errorf("%q must be withheld for %s", f, ep.Path)
			}
		}
	}
	// ...and the service type's own payload survives alongside them, which is
	// exactly what replacing destroyed.
	if _, ok := r.withheldFor(endpoint.Image)["prompt"]; !ok {
		t.Error("an image request must still withhold its prompt")
	}
	if _, ok := r.withheldFor(endpoint.Chat)["messages"]; !ok {
		t.Error("a chat request must still withhold its messages")
	}
	if _, ok := r.withheldFor(endpoint.Anthropic)["system"]; !ok {
		t.Error("an Anthropic request must still withhold its top-level system prompt")
	}
}

// A chat-shaped override — which is what -seal-fields is — must not be able to
// strip the image payload out of the withheld set. This is the concrete leak the
// additive semantics prevent, stated as its own case because it is the one that
// motivated the change.
func TestAChatOverrideCannotUnwithholdTheImagePrompt(t *testing.T) {
	r := New("http://x", WithSensitiveFields(wire.DefaultSealedFieldsFor(wire.ProfileChat)))
	if _, ok := r.withheldFor(endpoint.Image)["prompt"]; !ok {
		t.Fatal("a chat-shaped override must not expose the image prompt to the preview")
	}
}

// A router with no options withholds the chat payload for a chat request —
// existing callers (the gateway, the sidecar) must be unaffected.
func TestDefaultRouterKeepsTheChatSensitiveSet(t *testing.T) {
	got := New("http://x").withheldFor(endpoint.Chat)
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
			got := New("http://x", WithSensitiveFields(tt.fields)).withheldFor(endpoint.Image)
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
		ep   endpoint.Endpoint
		want string
	}{
		{endpoint.Chat, "http://router.example/v1/chat/completions"},
		// The Anthropic row's own path. It is NOT /v1/chat/completions even though
		// it shares chat's service type — a separate router endpoint with its own
		// handler and request shape — which is the case a service-type-keyed lookup
		// could not express.
		{endpoint.Anthropic, "http://router.example/v1/messages"},
		{endpoint.Image, "http://router.example/v1/images/generations"},
	} {
		t.Run(tc.ep.Path, func(t *testing.T) {
			got, err := r.upstreamURL(tc.ep)
			if err != nil {
				t.Fatalf("upstreamURL(%s): %v", tc.ep.Path, err)
			}
			if got != tc.want {
				t.Errorf("upstreamURL(%s) = %q, want %q", tc.ep.Path, got, tc.want)
			}
		})
	}
}

// A row with no UpstreamPath has no upstream URL, and there is no safe guess:
// falling back to chat would preview the wrong pool AND send the request to the
// chat endpoint AND withhold the chat payload fields from a body that does not
// have them — uploading whatever it does have. Defaulting to the bare router
// origin, which is what an unchecked concatenation does, is worse still. Refuse
// before any of that.
//
// The zero row is the reachable case: a struct literal that forgot the field, or
// a surface someone sketched without adding a path.
func TestRowWithoutUpstreamPathHasNoUpstreamURL(t *testing.T) {
	r := New("http://router.example")
	for _, ep := range []endpoint.Endpoint{
		{},
		{ServiceType: "speech-to-text"},
		{ServiceType: "chatbot", Path: "/v1/sketch"},
	} {
		if _, err := r.upstreamURL(ep); err == nil {
			t.Errorf("row %+v must have no upstream path", ep)
		}
	}
	// And Resolve refuses before it previews anything, so the router never even
	// learns the request exists.
	if _, err := r.Resolve(context.Background(), endpoint.Endpoint{ServiceType: "speech-to-text"}, wire.Request{}); err == nil {
		t.Error("Resolve must refuse a row with no upstream path")
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

	cands, err := New(srv.URL).Resolve(context.Background(), endpoint.Image, wire.Request{
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

// The ROW decides api_format, and a value in the request body is dropped rather
// than forwarded.
//
// Everything not withheld is copied into the preview payload, so before the
// deletion a caller could put `"api_format": "anthropic"` in an ordinary
// /v1/chat/completions body and have it reach preview — narrowing the pool to
// providers that serve only /v1/messages while the request was sealed under the
// chat profile and POSTed to /v1/chat/completions. On an image request it is
// worse than a mismatch: the router refuses a surface on a non-chat service
// type, so the preview 400s and the request fails outright.
//
// Passing unknown body fields through is deliberate and unchanged — the router
// ignores what it does not know. This one it now ACTS on, which is what moves it
// from noise to ours to state. Asserted for both rows that leave APIFormat
// empty, since the two failure modes differ.
func TestCallerSuppliedAPIFormatDoesNotReachThePreview(t *testing.T) {
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

	for _, tc := range []struct {
		ep  endpoint.Endpoint
		req wire.Request
	}{
		{endpoint.Chat, wire.Request{
			"model":      json.RawMessage(`"gpt-x"`),
			"messages":   json.RawMessage(`[{"role":"user","content":"hi"}]`),
			"api_format": json.RawMessage(`"anthropic"`),
		}},
		{endpoint.Image, wire.Request{
			"model":      json.RawMessage(`"z-image"`),
			"prompt":     json.RawMessage(`"a cat"`),
			"api_format": json.RawMessage(`"anthropic"`),
		}},
	} {
		t.Run(tc.ep.Path, func(t *testing.T) {
			body = nil
			_, _ = New(srv.URL).Resolve(context.Background(), tc.ep, tc.req)
			if body == nil {
				t.Fatal("preview was never called")
			}
			if raw, sent := body["api_format"]; sent {
				t.Errorf("the caller's api_format=%s reached the preview; the row (empty) decides it", raw)
			}
			// The rest of the body still passes through: the fix is scoped to the one
			// field the router acts on, not a new allowlist.
			if _, ok := body["model"]; !ok {
				t.Error("model must still reach the preview")
			}
		})
	}

	// And the Anthropic row still sends its OWN value — a deletion that fired on
	// every row would silently un-narrow the surface this branch exists to add.
	t.Run("the row's own value survives", func(t *testing.T) {
		body = nil
		_, _ = New(srv.URL).Resolve(context.Background(), endpoint.Anthropic, wire.Request{
			"model":      json.RawMessage(`"claude-x"`),
			"max_tokens": json.RawMessage(`16`),
			"messages":   json.RawMessage(`[{"role":"user","content":"hi"}]`),
			// A caller value that DISAGREES with the row: the row still wins.
			"api_format": json.RawMessage(`"openai"`),
		})
		if body == nil {
			t.Fatal("preview was never called")
		}
		var got string
		if err := json.Unmarshal(body["api_format"], &got); err != nil {
			t.Fatalf("api_format missing or not a string: %v", err)
		}
		if got != "anthropic" {
			t.Errorf("api_format = %q, want the row's %q", got, "anthropic")
		}
	})
}
