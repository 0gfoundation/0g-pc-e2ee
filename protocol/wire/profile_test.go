package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// a representative OpenAI image-generation request; only `prompt` is sensitive,
// the rest (model, n, size) is what the router needs to route and bill.
const sampleImageReq = `{
  "model": "z-image",
  "n": 2,
  "size": "1024x1024",
  "response_format": "b64_json",
  "prompt": "my secret prompt"
}`

func TestImageProfileSealsPromptAndLeavesRoutingFieldsCleartext(t *testing.T) {
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}

	env, err := wire.SealRequestFor(wire.ProfileImage, pub, mustReq(t, sampleImageReq),
		nil, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, ok := env["prompt"]; ok {
		t.Fatal("prompt must not remain as a cleartext field")
	}
	for _, f := range []string{"model", "n", "size", "response_format"} {
		if _, ok := env[f]; !ok {
			t.Errorf("routing/billing field %q must stay cleartext", f)
		}
	}
	// The prompt must not survive anywhere in the serialized envelope.
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if strings.Contains(string(raw), "my secret prompt") {
		t.Fatal("plaintext prompt leaked into the sealed envelope")
	}

	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if got := e2ee.SealedFields; len(got) != 1 || got[0] != "prompt" {
		t.Fatalf("sealed_fields = %v, want [prompt]", got)
	}

	// The enclave reconstructs the original request.
	out, err := wire.OpenRequest(priv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var gotPrompt string
	if err := json.Unmarshal(out["prompt"], &gotPrompt); err != nil {
		t.Fatalf("decode reconstructed prompt: %v", err)
	}
	if gotPrompt != "my secret prompt" {
		t.Fatalf("reconstructed prompt = %q", gotPrompt)
	}
	if string(out["n"]) != "2" {
		t.Fatalf("reconstructed n = %s, want 2", out["n"])
	}
}

// The whole point of the profile: an image request whose sealed set omits
// "prompt" is refused at seal time rather than shipping the prompt in the clear.
func TestImageProfileRejectsSealedSetWithoutPrompt(t *testing.T) {
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	_, err = wire.SealRequestFor(wire.ProfileImage, pub, mustReq(t, sampleImageReq),
		[]string{"size"}, testProvider, ephPub)
	if err == nil {
		t.Fatal("expected an error sealing an image request without prompt")
	}
	if !strings.Contains(err.Error(), "prompt") {
		t.Fatalf("error should name the missing payload field, got: %v", err)
	}
}

// Sealing the prompt is not enough on its own: `response_format: "url"` tells
// the enclave to publish the GENERATED IMAGES from a plain URL, outside the
// sealed channel — a worse leak than the prompt. The check is at seal time, so
// such a request is never built.
//
// Omitting the field is rejected too, and that is the case that matters: OpenAI's
// own default for the DALL·E family is "url", so silence is a request to leak.
func TestImageProfileRequiresExplicitB64ResponseFormat(t *testing.T) {
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	seal := func(t *testing.T, body string) error {
		t.Helper()
		_, err := wire.SealRequestFor(wire.ProfileImage, pub, mustReq(t, body), nil, testProvider, ephPub)
		return err
	}

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			"explicit b64_json is the only accepted value",
			`{"model":"z-image","response_format":"b64_json","prompt":"p"}`,
			false,
		},
		{
			"explicit url is rejected",
			`{"model":"z-image","response_format":"url","prompt":"p"}`,
			true,
		},
		{
			"OMITTED is rejected — the server default is url, so silence leaks",
			`{"model":"z-image","prompt":"p"}`,
			true,
		},
		{
			"null is rejected like any other non-b64_json value",
			`{"model":"z-image","response_format":null,"prompt":"p"}`,
			true,
		},
		{
			"a non-string value is rejected rather than coerced",
			`{"model":"z-image","response_format":1,"prompt":"p"}`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := seal(t, tt.body)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected the seal to be refused")
				}
				if !strings.Contains(err.Error(), "response_format") {
					t.Fatalf("error should name the offending field, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
		})
	}
}

// The pin is image-only: a chat request has no response_format constraint, and
// a chat request that happens to carry one is not second-guessed.
func TestChatProfileHasNoResponseFormatPin(t *testing.T) {
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	body := `{"model":"gpt-4o","response_format":{"type":"json_object"},"messages":[{"role":"user","content":"hi"}]}`
	if _, err := wire.SealRequestFor(wire.ProfileChat, pub, mustReq(t, body), []string{"messages"}, testProvider, ephPub); err != nil {
		t.Fatalf("a chat request's own response_format must pass through untouched: %v", err)
	}
}

// The response sealed set may not swallow a field the router reads without a
// key — sealing `usage` makes the response unbillable (and for image, hides
// usage.output_images, the only count the router has).
func TestResponseSealedFieldsMustLeaveRouterInputsCleartext(t *testing.T) {
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rs, err := wire.NewResponseSealer(ephPub)
	if err != nil {
		t.Fatalf("response sealer: %v", err)
	}
	frame := wire.Response{
		"choices": json.RawMessage(`[]`),
		"usage":   json.RawMessage(`{"output_images":1}`),
	}
	if _, err := rs.SealFrame(frame, []string{"choices", "usage"}, true); err == nil {
		t.Fatal("sealing `usage` must be refused — the router bills on it without a key")
	}
}

// Each profile requires its OWN payload field: a chat set does not satisfy the
// image profile and vice versa, so a caller cannot pass the wrong profile and
// still get an envelope.
func TestProfilesDoNotAcceptEachOthersSealedSets(t *testing.T) {
	if err := wire.ValidateSealedFieldsFor(wire.ProfileImage, []string{"messages"}); err == nil {
		t.Error("image profile must reject a chat sealed set")
	}
	if err := wire.ValidateSealedFieldsFor(wire.ProfileChat, []string{"prompt"}); err == nil {
		t.Error("chat profile must reject an image sealed set")
	}
	if err := wire.ValidateSealedFieldsFor("audio", []string{"file"}); err == nil {
		t.Error("an unknown profile must be rejected, not silently allowed")
	}
}

// TestProfileDefaults pins the frameless default accessors for EVERY profile,
// and the enumeration is the point rather than the coverage: the loop walks
// wire.Profiles() and fails on any profile this table does not mention, so
// adding a profile forces a decision about its frameless answer instead of
// letting it inherit an untested one.
//
// That is what was missing. The table listed chat and image only, so
// ProfileSpeech's response default — which §7.3 makes a MUST, because the
// plausible answer `["text"]` is valid for every `json` transcription and
// invalid for every `verbose_json` one — was enforced by code that no test
// touched. Reverting the guard left the whole suite green.
func TestProfileDefaults(t *testing.T) {
	tests := map[wire.Profile]struct {
		request  []string
		response []string
		// why documents a profile whose frameless response default is EMPTY. An
		// empty answer is the interesting one: it means "there is no profile-wide
		// answer, resolve against the frame", and a reader needs to know which
		// reason applies.
		why string
	}{
		wire.ProfileChat:  {request: []string{"messages", "tools", "tool_choice"}, response: []string{"choices"}},
		wire.ProfileImage: {request: []string{"prompt"}, response: []string{"data"}},
		wire.ProfileAnthropic: {
			request:  []string{"messages", "system", "tools", "tool_choice"},
			response: []string{},
			why:      "frame-typed (§7.2): what a frame seals is a property of the frame",
		},
		wire.ProfileSpeech: {
			request:  []string{"file_base64", "filename", "language", "prompt"},
			response: []string{},
			why:      "conditionally sealed response fields (§7.3): `[\"text\"]` would be valid for json and invalid for verbose_json, so a broker holding it fails 100% of verbose responses after the billed upstream call",
		},
	}

	profiles := wire.Profiles()
	if len(profiles) == 0 {
		t.Fatal("Profiles() is empty; this test would assert nothing")
	}
	for _, p := range profiles {
		tt, ok := tests[p]
		if !ok {
			t.Errorf("profile %q has no row here: state its frameless defaults (and, if the response default is empty, why) rather than leaving them unasserted", p)
			continue
		}
		t.Run(string(p), func(t *testing.T) {
			if got := wire.DefaultSealedFieldsFor(p); !equalStrings(got, tt.request) {
				t.Errorf("request defaults = %v, want %v", got, tt.request)
			}
			got := wire.DefaultResponseSealedFieldsFor(p)
			if !equalStrings(got, tt.response) {
				t.Errorf("response defaults = %v, want %v (%s)", got, tt.response, tt.why)
			}
			// Empty must be empty-NON-NIL: both Seal entry points read nil as "use
			// the default", which would send them back here and loop, or worse
			// resolve to another profile's set.
			if len(tt.response) == 0 && got == nil {
				t.Errorf("response defaults for %q are nil; want an empty non-nil slice so a caller fails closed", p)
			}
		})
	}
	// Defaults are fresh slices: mutating one must not poison the next caller.
	d := wire.DefaultSealedFieldsFor(wire.ProfileImage)
	d[0] = "tampered"
	if got := wire.DefaultSealedFieldsFor(wire.ProfileImage); got[0] != "prompt" {
		t.Fatalf("defaults are shared state: got %v after mutation", got)
	}
}

// Both Seal entry points read a nil sealedFields as "use the default set", so a
// default lookup for an unknown profile MUST NOT come back nil — that would seal
// the CHAT fields for a profile that does not exist, silently and with no error.
// An empty non-nil slice makes the same call fail closed instead.
func TestUnknownProfileDefaultsFailClosedRatherThanSealingChatFields(t *testing.T) {
	const unknown wire.Profile = "audio"

	reqDefaults := wire.DefaultSealedFieldsFor(unknown)
	if reqDefaults == nil || len(reqDefaults) != 0 {
		t.Fatalf("request defaults for an unknown profile = %v, want an empty NON-nil slice", reqDefaults)
	}
	respDefaults := wire.DefaultResponseSealedFieldsFor(unknown)
	if respDefaults == nil || len(respDefaults) != 0 {
		t.Fatalf("response defaults for an unknown profile = %v, want an empty NON-nil slice", respDefaults)
	}

	// Feeding those straight into the seal path must error, not seal
	// "messages" / "choices" behind the caller's back.
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}

	if _, err := wire.SealRequest(encPub, mustReq(t, sampleReq), reqDefaults, testProvider, ephPub); err == nil {
		t.Error("SealRequest with an unknown profile's defaults must fail, not seal the chat set")
	}

	rs, err := wire.NewResponseSealer(ephPub)
	if err != nil {
		t.Fatalf("response sealer: %v", err)
	}
	frame := wire.Response{"choices": json.RawMessage(`[{"index":0}]`)}
	if _, err := rs.SealFrame(frame, respDefaults, true); err == nil {
		t.Error("SealFrame with an unknown profile's defaults must fail, not seal choices")
	}
}

// The chat shorthands must stay exactly the chat profile — existing callers
// (the broker, the client core) go through them.
func TestChatShorthandsMatchChatProfile(t *testing.T) {
	if got := wire.DefaultSealedFields(); !equalStrings(got, wire.DefaultSealedFieldsFor(wire.ProfileChat)) {
		t.Errorf("DefaultSealedFields() = %v, diverged from the chat profile", got)
	}
	if err := wire.ValidateSealedFields([]string{"prompt"}); err == nil {
		t.Error("ValidateSealedFields must still enforce the chat payload field")
	}
	if err := wire.ValidateSealedFields([]string{"messages"}); err != nil {
		t.Errorf("ValidateSealedFields rejected a valid chat set: %v", err)
	}
}

// An image response seals data[] and leaves usage/created cleartext, so the
// router bills on the image count without holding the images.
func TestImageResponseSealsDataAndLeavesUsageCleartext(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	resp := wire.Response{
		"created": json.RawMessage(`1700000000`),
		"model":   json.RawMessage(`"z-image"`),
		"usage":   json.RawMessage(`{"output_images":2}`),
		"data":    json.RawMessage(`[{"b64_json":"c2VjcmV0"},{"b64_json":"aW1hZ2U"}]`),
	}
	frame, err := wire.SealResponseFor(wire.ProfileImage, ephPub, resp,
		wire.DefaultResponseSealedFieldsFor(wire.ProfileImage), "model", "x_0g_trace")
	if err != nil {
		t.Fatalf("seal response: %v", err)
	}
	if _, ok := frame["data"]; ok {
		t.Fatal("data must not remain cleartext")
	}
	if string(frame["usage"]) != `{"output_images":2}` {
		t.Fatalf("usage must stay cleartext for billing, got %s", frame["usage"])
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	if strings.Contains(string(raw), "c2VjcmV0") {
		t.Fatal("image bytes leaked into the sealed frame")
	}

	out, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, frame)
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	var data []struct {
		B64JSON string `json:"b64_json"`
	}
	if err := json.Unmarshal(out["data"], &data); err != nil {
		t.Fatalf("decode reconstructed data: %v", err)
	}
	if len(data) != 2 || data[0].B64JSON != "c2VjcmV0" {
		t.Fatalf("reconstructed data = %+v", data)
	}
}

// The router rewrites `model` and injects `x_0g_trace` on the way back. Both are
// declared unbound, so those edits must NOT break the client's Open — while a
// bound field (usage) stays tamper-evident.
func TestImageResponseSurvivesRouterRewritesButDetectsUsageTampering(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	base := func() wire.Response {
		return wire.Response{
			"created": json.RawMessage(`1700000000`),
			"model":   json.RawMessage(`"z-image-canonical"`),
			"usage":   json.RawMessage(`{"output_images":2}`),
			"data":    json.RawMessage(`[{"b64_json":"aW1n"}]`),
		}
	}
	seal := func() wire.Response {
		t.Helper()
		f, err := wire.SealResponseFor(wire.ProfileImage, ephPub, base(),
			wire.DefaultResponseSealedFieldsFor(wire.ProfileImage), "model", "x_0g_trace")
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		return f
	}

	rewritten := seal()
	rewritten["model"] = json.RawMessage(`"z-image"`) // router restores the alias
	rewritten["x_0g_trace"] = json.RawMessage(`{"provider":"0xabc"}`)
	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, rewritten); err != nil {
		t.Fatalf("unbound router rewrites must not break Open: %v", err)
	}

	tampered := seal()
	tampered["usage"] = json.RawMessage(`{"output_images":99}`) // bound → must fail closed
	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, tampered); err == nil {
		t.Fatal("tampering with the bound usage field must fail Open")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// `unbound_fields` is the escape hatch that makes every other guard optional, so
// the fields whose value must be TRUSTED have to be excluded from it explicitly.
//
// Cleartext is only half the requirement. An unbound field is excluded from the
// seal AAD, so an intermediary can rewrite it, Open still succeeds, and — because
// the §8 binding hashes that same AAD — respH comes out byte-identical. Declaring
// `usage` unbound therefore lets a router restate the billable count with nothing
// anywhere detecting it, which is exactly what §7.1 promises cannot happen.
func TestUsageCannotBeDeclaredUnboundInAResponse(t *testing.T) {
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	resp := wire.Response{
		"usage": json.RawMessage(`{"output_images":2}`),
		"data":  json.RawMessage(`[{"b64_json":"aW1n"}]`),
	}
	if _, err := wire.SealResponse(ephPub, resp, []string{"data"}, "model", "usage"); err == nil {
		t.Fatal("declaring `usage` unbound must be refused — it would hide billing tampering from both Open and the §8 binding")
	}
	if _, err := wire.NewResponseSealer(ephPub, "usage"); err == nil {
		t.Fatal("the streaming sealer must refuse it too — the unbound set is fixed for the whole stream")
	}

	// `model` stays legitimately unbound: the broker declares it so the router can
	// substitute the alias back, a known trade-off. Refusing it would break the
	// shipped chat path.
	if _, err := wire.SealResponseFor(wire.ProfileImage, ephPub, resp, []string{"data"}, "model", "x_0g_trace"); err != nil {
		t.Fatalf("the broker's own unbound set must stay valid: %v", err)
	}
}

// Same hole on the request side: a pinned cleartext field that is unbound is
// pinned only at seal time. The router flips `response_format` to "url" in
// transit, OpenRequest recomputes an AAD that excludes it, and the enclave is
// handed a request that publishes the images in the clear.
func TestPinnedCleartextFieldCannotBeDeclaredUnbound(t *testing.T) {
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	req := mustReq(t, sampleImageReq)

	_, err = wire.SealRequestFor(wire.ProfileImage, pub, req, nil, testProvider, ephPub, "model", "response_format")
	if err == nil {
		t.Fatal("declaring the pinned `response_format` unbound must be refused")
	}
	if !strings.Contains(err.Error(), "response_format") {
		t.Fatalf("error should name the pinned field, got: %v", err)
	}

	// The default unbound set (model only) stays valid for an image request.
	if _, err := wire.SealRequestFor(wire.ProfileImage, pub, req, nil, testProvider, ephPub,
		wire.DefaultUnboundFields()...); err != nil {
		t.Fatalf("the default unbound set must stay valid for the image profile: %v", err)
	}
}

// The bound-ness requirement has to hold on the RECEIVING side to be worth
// anything. Checking only at seal time stops a conforming enclave from
// misconfiguring itself; the threat is an enclave that declares `usage` unbound
// deliberately, so a router can restate the billable count while Open and the §8
// verification both still pass. Only the client can refuse that.
func TestOpenFrameRefusesAFrameThatFreesUsage(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Seal legitimately, then rewrite the frame's declared unbound set the way a
	// non-conforming enclave would have emitted it in the first place.
	frame, err := wire.SealResponseFor(wire.ProfileImage, ephPub, wire.Response{
		"usage": json.RawMessage(`{"output_images":2}`),
		"data":  json.RawMessage(`[{"b64_json":"aW1n"}]`),
	}, []string{"data"}, "model")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	e2ee, err := frame.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	e2ee.UnboundFields = []string{"model", "usage"}
	raw, err := json.Marshal(e2ee)
	if err != nil {
		t.Fatalf("marshal _e2ee: %v", err)
	}
	frame[e2eeKeyForTest] = raw

	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, frame); err == nil {
		t.Fatal("the client must refuse a frame declaring `usage` unbound, whoever sealed it")
	} else if !strings.Contains(err.Error(), "usage") {
		t.Fatalf("error should name the field, got: %v", err)
	}
}

// The one way to satisfy the pin's VALUE check and still leak: seal the pinned
// field. The value is verified against the pre-seal request, then the field is
// encrypted away, so the enclave reads nothing where the pin should be and falls
// back to its own default — `url` for the image profile.
func TestPinnedCleartextFieldCannotBeSealed(t *testing.T) {
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	_, err = wire.SealRequestFor(wire.ProfileImage, pub, mustReq(t, sampleImageReq),
		[]string{"prompt", "response_format"}, testProvider, ephPub)
	if err == nil {
		t.Fatal("sealing the pinned `response_format` must be refused — it would leave the enclave nothing to read")
	}
	if !strings.Contains(err.Error(), "response_format") {
		t.Fatalf("error should name the pinned field, got: %v", err)
	}
}
