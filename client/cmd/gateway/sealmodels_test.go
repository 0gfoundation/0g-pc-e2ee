package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

const sealedModel = "glm-5"

func modelBody(model string) string {
	return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hello"}]}`, model)
}

// postChat returns the response and whatever the router received, so a case can
// assert on BOTH — a 200 that reached the router and a 200 that did not are the
// same status and opposite outcomes.
func postChat(t *testing.T, gwURL, body, contentType string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, gwURL+endpoint.Chat.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(got)
}

// A model on the list is sealed; one that is not goes to the router VERBATIM.
//
// Byte-for-byte matters: the dispatcher has to read the body to find the model
// and then hand the same bytes on, so "the router got a request" is not enough —
// it has to be the caller's request.
func TestSealModelsRoutesByModel(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{sealModels: parseSealModels(sealedModel)})

	// Not on the list → the router's own answer, marked unencrypted.
	body := modelBody("some-other-model")
	resp, got := postChat(t, gw.URL, body, "application/json")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 — the router's answer (body %s)", resp.StatusCode, got)
	}
	if m := resp.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueNone {
		t.Errorf("%s = %q, want %q", openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueNone)
	}

	// On the list → sealed, so the router must never see it.
	sealedResp, _ := postChat(t, gw.URL, modelBody(sealedModel), "application/json")
	if m := sealedResp.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueSealed {
		t.Errorf("%s = %q, want %q", openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueSealed)
	}

	_, _, bodies := rr.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("router saw %d requests, want exactly 1 (the unlisted model only)", len(bodies))
	}
	if bodies[0] != body {
		t.Errorf("router got %q, want the caller's bytes %q", bodies[0], body)
	}
}

// The empty list is today's behaviour: every model sealed, nothing reaches the
// router. It is also the zero value of the field, so a caller that says nothing
// about models gets the deployment that runs today.
func TestEmptySealModelsSealsEverything(t *testing.T) {
	if !(sealModels{}).all() {
		t.Error("the zero sealModels must mean ALL models")
	}
	if !(sealModels{}).seals("anything") {
		t.Error("the zero sealModels must seal an arbitrary model")
	}
	// A list of nothing but separators is still a list of nothing.
	if !parseSealModels(" , ,, ").all() {
		t.Error(`parseSealModels(" , ,, ") must be empty, not a set of blank model names`)
	}

	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	for _, model := range []string{sealedModel, "some-other-model", ""} {
		resp, _ := postChat(t, gw.URL, modelBody(model), "application/json")
		if m := resp.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueSealed {
			t.Errorf("model %q: %s = %q, want %q", model, openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueSealed)
		}
	}
	if _, _, bodies := rr.snapshot(); len(bodies) != 0 {
		t.Errorf("router saw %d requests with no model list, want 0", len(bodies))
	}
}

// "Cannot tell" resolves toward SEALING, never toward the clear. Every one of
// these would otherwise be a prompt disclosed to the router because of a parse
// failure, which is not a trade worth making.
func TestUnreadableModelIsSealedNotForwarded(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{sealModels: parseSealModels(sealedModel)})

	for _, tc := range []struct{ name, body, contentType string }{
		{"not json", `this is not json at all`, "application/json"},
		{"json but not an object", `["a","b"]`, "application/json"},
		{"no model field", `{"messages":[{"role":"user","content":"hi"}]}`, "application/json"},
		{"empty model", `{"model":"   "}`, "application/json"},
		// Multipart shapes that genuinely cannot be read. A multipart body that
		// DOES name its model is a different case and must not be here — see
		// TestMultipartModelRoutesByModel.
		{"multipart with no boundary", multipartBody("b", "model", sealedModel), "multipart/form-data"},
		{"multipart truncated mid-part", "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n",
			"multipart/form-data; boundary=b"},
		{"multipart naming no model", multipartBody("b", "file", "audio-bytes"),
			"multipart/form-data; boundary=b"},
		{"multipart with an empty model", multipartBody("b", "model", "   "),
			"multipart/form-data; boundary=b"},
		{"multipart with an absurd model field", multipartBody("b", "model", strings.Repeat("x", 4096)),
			"multipart/form-data; boundary=b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(bodiesOf(rr))
			postChat(t, gw.URL, tc.body, tc.contentType)
			if after := len(bodiesOf(rr)); after != before {
				t.Errorf("the router received a request whose model could not be read: " +
					"an unparseable body must be SEALED (and refused there), never forwarded")
			}
		})
	}
}

func bodiesOf(rr *recordingRouter) []string {
	_, _, b := rr.snapshot()
	return b
}

// multipartBody builds a one-part multipart body by hand rather than with
// multipart.Writer, so a case can write a boundary the reader will reject.
func multipartBody(boundary string, parts ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(parts); i += 2 {
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n",
			boundary, parts[i], parts[i+1])
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}

// postSpeech sends a transcription request the way an SDK does: multipart, with
// the audio part first and `model` after it.
func postSpeech(t *testing.T, gwURL, model string) *http.Response {
	t.Helper()
	body := multipartBody("zgb", "file", "fake-audio-bytes", "model", model)
	req, _ := http.NewRequest(http.MethodPost, gwURL+endpoint.Speech.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", `multipart/form-data; boundary=zgb`)
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	return resp
}

// The transcription surface routes by model like every other one.
//
// This is the case the model list exists for and the one it used to get wrong.
// /v1/audio/transcriptions is in endpoint.All, so it is sealed; its body is
// multipart, which the dispatcher used to bucket as "cannot tell" and therefore
// SEAL — for every model, whatever the list said. On a deployment whose list is
// chat models, that is not a conservative default: transcription has no sealable
// provider, its route-preview comes back empty, and an empty preview is terminal
// with no retry. A surface that works today would have started failing outright
// the moment this gateway became the only entry.
//
// Asserting the marker rather than the status because the sealed branch cannot
// complete against a test router: "did this reach the router in the clear" is
// the whole question, and the marker answers it on both branches.
func TestMultipartModelRoutesByModel(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{sealModels: parseSealModels(sealedModel)})

	// A transcription model nobody listed: to the router, in the clear, marked.
	resp := postSpeech(t, gw.URL, "whisper-1")
	if m := resp.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueNone {
		t.Errorf("%s = %q for an UNLISTED transcription model, want %q: the model list must "+
			"narrow this surface too, or a chat-only list silently seals (and so breaks) "+
			"every transcription", openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueNone)
	}
	if got := bodiesOf(rr); len(got) != 1 {
		t.Fatalf("router saw %d requests, want 1 — the unlisted transcription", len(got))
	}

	// And a listed one is still sealed: reading the field must not become a way
	// to reach the router with a model the operator asked to seal.
	sealed := postSpeech(t, gw.URL, sealedModel)
	if m := sealed.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueSealed {
		t.Errorf("%s = %q for a LISTED transcription model, want %q",
			openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueSealed)
	}
	if got := bodiesOf(rr); len(got) != 1 {
		t.Errorf("router saw %d requests after the sealed one, want still 1", len(got))
	}
}

// The model field is found wherever it sits, and matched the same way JSON's is.
//
// Order matters in practice: OpenAI's SDKs put the audio first, so the field is
// behind a part that can be megabytes. A reader that gave up at the first part
// it did not recognise would seal every real transcription while passing the
// hand-written ones in tests.
func TestMultipartModelFieldPosition(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"model first", multipartBody("zgb", "model", sealedModel, "file", "audio")},
		{"model last", multipartBody("zgb", "file", "audio", "model", sealedModel)},
		{"model between", multipartBody("zgb", "file", "audio", "model", sealedModel, "language", "en")},
		{"cased differently", multipartBody("zgb", "file", "audio", "model", strings.ToUpper(sealedModel))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model, reason := modelOf([]byte(tc.body), "multipart/form-data; boundary=zgb", nil, len(tc.body))
			if reason != "" {
				t.Fatalf("reason = %q, want the model to be readable", reason)
			}
			if !parseSealModels(sealedModel).seals(model) {
				t.Errorf("model = %q, which does not match the configured %q", model, sealedModel)
			}
		})
	}
}

// The multipart reader's exact verdict per shape, asserted on the REASON rather
// than on "it got sealed".
//
// Sealing is the outcome of every row here, so a test that only checked the
// outcome would pass whether the reader worked or not — and would keep passing
// if a shape started being read as some arbitrary model that happened to be on
// the list. Two of these were written from a wrong reading of FormName and
// passed anyway for that reason; the reason string is what distinguishes
// "correctly could not tell" from "accidentally agreed".
func TestMultipartUnreadableShapesAndTheirReasons(t *testing.T) {
	for _, tc := range []struct{ name, body, contentType, want string }{
		{"no boundary parameter", multipartBody("b", "model", sealedModel),
			"multipart/form-data", "multipart_unreadable"},
		{"truncated mid-part", "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n",
			"multipart/form-data; boundary=b", "no_model_field"},
		// Form field names are case-sensitive, so this is genuinely not the field.
		{"field named Model", "--b\r\nContent-Disposition: form-data; name=\"Model\"\r\n\r\n" +
			sealedModel + "\r\n--b--\r\n", "multipart/form-data; boundary=b", "no_model_field"},
		{"no model part", multipartBody("b", "file", "audio"),
			"multipart/form-data; boundary=b", "no_model_field"},
		{"blank model", multipartBody("b", "model", "   "),
			"multipart/form-data; boundary=b", "no_model_field"},
		{"model field over the cap", multipartBody("b", "model", strings.Repeat("x", maxModelFieldBytes+1)),
			"multipart/form-data; boundary=b", "multipart_unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model, reason := modelOf([]byte(tc.body), tc.contentType, nil, len(tc.body))
			if reason != tc.want {
				t.Errorf("reason = %q (model %q), want %q", reason, model, tc.want)
			}
			if model != "" {
				t.Errorf("model = %q, want empty: a shape that cannot be read must not "+
					"produce one, or it routes on something nobody sent", model)
			}
		})
	}

	// Just under the cap is a normal read, so the cap is a boundary and not a
	// blanket refusal of long names.
	body := multipartBody("b", "model", strings.Repeat("x", maxModelFieldBytes))
	if model, reason := modelOf([]byte(body), "multipart/form-data; boundary=b", nil, len(body)); reason != "" ||
		len(model) != maxModelFieldBytes {
		t.Errorf("a model field exactly at the cap gave (%q…, %q), want it read whole", model[:min(8, len(model))], reason)
	}
}

// With no list, nothing is parsed at all: dispatch hands back the sealed handler
// unchanged, so the ordinary deployment does not pay for multipart reading — and
// a transcription is sealed as it is today, whatever its model field says.
func TestEmptyListDoesNotParseMultipart(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{})

	resp := postSpeech(t, gw.URL, "whisper-1")
	if m := resp.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueSealed {
		t.Errorf("%s = %q, want %q: an empty list seals every model on every sealed surface",
			openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueSealed)
	}
	if got := bodiesOf(rr); len(got) != 0 {
		t.Errorf("router saw %d requests with no model list, want 0", len(got))
	}
}

// A name for a path the dispatcher is not mounted on does nothing, and nothing
// says so. Pinned because it is the shape of a plausible mistake: adding an
// embedding or completion model to the list ahead of the surface, seeing no
// error, and reading that as "configured".
func TestSealModelsOnlyAppliesToSealedSurfaces(t *testing.T) {
	sealedPaths := map[string]bool{}
	for _, ep := range endpoint.All {
		sealedPaths[ep.Path] = true
	}
	for _, p := range []string{"/v1/embeddings", "/v1/completions"} {
		if sealedPaths[p] {
			t.Errorf("%s is now a sealed surface. Naming its models in -seal-models finally "+
				"does something — update the note on sealModels, which says it cannot", p)
		}
	}

	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	// The list names an embeddings model. It must not change what that path does.
	gw := catalogGateway(t, router, entryPolicy{sealModels: parseSealModels("text-embedding-3-small")})

	body := `{"model":"text-embedding-3-small","input":"hello"}`
	req, _ := http.NewRequest(http.MethodPost, gw.URL+"/v1/embeddings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if m := resp.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueNone {
		t.Errorf("%s = %q, want %q", openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueNone)
	}
	if got := bodiesOf(rr); len(got) != 1 || got[0] != body {
		t.Errorf("router saw %v, want the one verbatim request: a model named for a surface "+
			"that is not sealed is a no-op, not a configuration", got)
	}
}

// Matching is case-insensitive in both directions, so a caller's casing cannot
// silently drop a model out of the sealed set.
func TestSealModelsMatchingIsCaseInsensitive(t *testing.T) {
	s := parseSealModels("GLM-5, Claude-Opus-5 ")
	for _, m := range []string{"glm-5", "GLM-5", "gLm-5", "claude-opus-5", "CLAUDE-OPUS-5"} {
		if !s.seals(m) {
			t.Errorf("seals(%q) = false, want true", m)
		}
	}
	if s.seals("glm-5-air") {
		t.Error(`seals("glm-5-air") = true: matching must be exact, not a prefix`)
	}
}

// The metric label is bounded by the CONFIGURED set, never by what a caller
// sends — otherwise one client could mint a Prometheus time series per request.
func TestSealModelsMetricLabelIsBounded(t *testing.T) {
	s := parseSealModels("glm-5,claude-opus-5")
	if got := s.label("GLM-5"); got != "glm-5" {
		t.Errorf("label(%q) = %q, want the canonical configured name", "GLM-5", got)
	}
	for _, unbounded := range []string{"attacker-chosen-" + strings.Repeat("x", 64), "", "   "} {
		if got := s.label(unbounded); got != "other" {
			t.Errorf("label(%q) = %q, want \"other\": an unconfigured model must not become a label", unbounded, got)
		}
	}
}

// -seal-policy=off wins outright: with nothing sealed there is no per-model
// decision to make, and a model on the list must not be sealed anyway.
func TestSealPolicyOffBeatsTheModelList(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{
		sealPolicy: sealPolicyOff,
		sealModels: parseSealModels(sealedModel),
	})

	body := modelBody(sealedModel)
	resp, _ := postChat(t, gw.URL, body, "application/json")
	if m := resp.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueNone {
		t.Errorf("%s = %q, want %q: -seal-policy=off is not overridable per model",
			openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueNone)
	}
	_, _, bodies := rr.snapshot()
	if len(bodies) != 1 || bodies[0] != body {
		t.Errorf("router saw %v, want the one verbatim request", bodies)
	}
}

// The trailing-slash spelling of a sealed surface must route by model too.
// It is served through canonicalPath, which is a separate mount — an easy place
// for the two spellings to drift into different policies, which is exactly how
// the earlier trailing-slash prompt leak happened.
func TestTrailingSlashSpellingAlsoRoutesByModel(t *testing.T) {
	rr := &recordingRouter{}
	router := rr.server(nil)
	defer router.Close()
	gw := catalogGateway(t, router, entryPolicy{sealModels: parseSealModels(sealedModel)})

	req, _ := http.NewRequest(http.MethodPost, gw.URL+endpoint.Chat.Path+"/",
		strings.NewReader(modelBody(sealedModel)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	if m := resp.Header.Get(openaiproxy.HeaderE2EE); m != openaiproxy.E2EEValueSealed {
		t.Errorf("%s = %q on the trailing-slash form, want %q", openaiproxy.HeaderE2EE, m, openaiproxy.E2EEValueSealed)
	}
	if _, _, bodies := rr.snapshot(); len(bodies) != 0 {
		t.Errorf("router saw %d requests for a SEALED model on the trailing-slash path, want 0: "+
			"the two spellings must not carry different policies", len(bodies))
	}
}

// composeSealModels reads the deployed default out of the compose manifest.
var composeSealModels = regexp.MustCompile(
	`ZG_GATEWAY_SEAL_MODELS=\$\{ZG_GATEWAY_SEAL_MODELS:-([^}]*)\}`)

// The deployed model list is pinned here because a typo in it does not fail —
// it SEALS NOTHING for the misspelt model and forwards its prompts to the
// router in the clear, looking exactly like a correct rollout. That is the one
// silent failure this whole feature has, and the compose value is where it
// would be introduced.
//
// This asserts behaviour rather than string equality: what matters is that the
// deployed value seals the model it is meant to, and does not accidentally
// sweep in the neighbouring canonical id that differs by one suffix.
func TestComposeSealModelsSealsTheIntendedModel(t *testing.T) {
	compose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	m := composeSealModels.FindSubmatch(compose)
	if m == nil {
		t.Fatalf("no ZG_GATEWAY_SEAL_MODELS=${...:-<default>} entry in %s; if the entry was "+
			"reshaped deliberately, update this test rather than dropping it", composePath)
	}
	deployed := parseSealModels(string(m[1]))
	if deployed.all() {
		t.Fatalf("the compose seal-model list is empty, which seals EVERY model — including the "+
			"ones with no sealable provider, whose route-preview comes back empty and is "+
			"terminal. If that is deliberate, say so here rather than leaving it to look "+
			"like a deletion (%q)", m[1])
	}

	// The 0G in-house model, and its only registry alias — the on-chain spelling,
	// which differs from the canonical id in case alone.
	for _, spelling := range []string{"0gm-1.0-35b-a3b", "0GM-1.0-35B-A3B"} {
		if !deployed.seals(spelling) {
			t.Errorf("the deployed list %q does not seal %q. A model missing from this list is "+
				"not an error anywhere — its prompts simply go to the router in the clear, "+
				"which is indistinguishable from a correct rollout", m[1], spelling)
		}
	}
	// A different canonical model whose id is this one plus a suffix. Matching is
	// exact, so it must NOT be swept in by the entry above; it gets sealed only
	// when somebody adds it by name.
	if deployed.seals("0gm-1.0-35b-a3b-sia") {
		t.Errorf("the deployed list %q seals 0gm-1.0-35b-a3b-sia, a separate canonical model. "+
			"Matching must stay exact — if that model is meant to be sealed, name it", m[1])
	}
}
