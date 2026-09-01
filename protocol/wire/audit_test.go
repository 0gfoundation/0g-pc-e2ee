package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The response-side twin of "the sealed set must cover the payload", and silent
// in the same way: an enclave declares a sealed set that does NOT cover the
// generated content, seals something incidental, and ships `choices` in the
// CLEAR. Open succeeds — the decrypted keys DO match the declared set — the
// content merges back exactly as the caller expects, and the §8 signature
// verifies too, since the cleartext content sits inside the AAD the binding
// hashes. Without this check the caller gets a correct, complete answer and no
// way to learn that every intermediary read it.
func TestClientRefusesAResponseThatDidNotSealTheContent(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	frame, err := wire.SealResponse(ephPub, wire.Response{
		"created": json.RawMessage(`1700000000`),
		"choices": json.RawMessage(`[{"message":{"content":"THE MODEL OUTPUT"}}]`),
	}, []string{"created"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), "THE MODEL OUTPUT") {
		t.Fatal("precondition: this frame is supposed to carry the content in the clear")
	}

	_, err = wire.OpenResponse(ephPriv, frame)
	if err == nil {
		t.Fatal("the client must refuse a response that never sealed its content")
	}
	if !strings.Contains(err.Error(), "choices") {
		t.Fatalf("error should name the field that was supposed to be sealed, got: %v", err)
	}
}

// Per frame, not once on the first: sealed_fields rides on every frame, so a
// stream may seal the content for a while and then quietly stop.
func TestClientRefusesAStreamThatStopsSealingTheContent(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rs, err := wire.NewResponseSealer(ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	first, err := rs.SealFrame(wire.Response{
		"choices": json.RawMessage(`[{"delta":{"content":"ok so far"}}]`),
	}, []string{"choices"}, false)
	if err != nil {
		t.Fatalf("seal first: %v", err)
	}
	// Second frame stops sealing the content and ships it cleartext instead.
	second, err := rs.SealFrame(wire.Response{
		"created": json.RawMessage(`1`),
		"choices": json.RawMessage(`[{"delta":{"content":"LEAKED"}}]`),
	}, []string{"created"}, true)
	if err != nil {
		t.Fatalf("seal second: %v", err)
	}

	ro, err := wire.NewResponseOpener(ephPriv, first)
	if err != nil {
		t.Fatalf("opener: %v", err)
	}
	if _, err := ro.OpenFrame(first); err != nil {
		t.Fatalf("the conforming first frame must open: %v", err)
	}
	if _, err := ro.OpenFrame(second); err == nil {
		t.Fatal("a later frame that stops sealing the content must be refused")
	}
}

// The image profile is checked against its own content field, and the opener is
// bound to the profile the REQUEST used — so a chat opener will not accept an
// image-shaped response, or vice versa.
func TestResponseOpenerIsBoundToTheRequestProfile(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	imageFrame, err := wire.SealResponse(ephPub, wire.Response{
		"usage": json.RawMessage(`{"output_images":1}`),
		"data":  json.RawMessage(`[{"b64_json":"aW1n"}]`),
	}, wire.DefaultResponseSealedFieldsFor(wire.ProfileImage))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, imageFrame); err != nil {
		t.Fatalf("an image response must open under the image profile: %v", err)
	}
	if _, err := wire.OpenResponse(ephPriv, imageFrame); err == nil {
		t.Error("the chat shorthand must not accept a response that sealed no `choices`")
	}
	if _, err := wire.OpenResponseFor("audio", ephPriv, imageFrame); err == nil {
		t.Error("an unknown profile must be rejected")
	}
}

// The enclave's one-stop entry: every receiver-side profile check, then the
// open. A check a caller has to remember to make separately eventually is not
// made — which is why the response side builds these into the opener, and why
// the request side now matches.
func TestOpenRequestForRunsEveryReceiverSideCheck(t *testing.T) {
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	sealed, err := wire.SealRequestFor(wire.ProfileImage, pub, mustReq(t, sampleImageReq),
		nil, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// The happy path still reconstructs the request.
	out, err := wire.OpenRequestFor(wire.ProfileImage, priv, sealed)
	if err != nil {
		t.Fatalf("a conforming envelope must open: %v", err)
	}
	if string(out["prompt"]) != `"my secret prompt"` {
		t.Fatalf("prompt = %s, want it merged back", out["prompt"])
	}

	// Each check the enclave would otherwise have had to remember, exercised
	// through the single entry point. Every mutation is one an intermediary or a
	// non-conforming client could make; OpenRequest alone accepts all of them.
	tests := []struct {
		name   string
		mutate func(wire.Request, map[string]json.RawMessage)
		want   string
	}{
		{
			"sealed set does not cover the payload",
			func(_ wire.Request, e2ee map[string]json.RawMessage) {
				e2ee["sealed_fields"] = json.RawMessage(`["size"]`)
			},
			"prompt",
		},
		{
			"pinned field rewritten in transit",
			func(env wire.Request, _ map[string]json.RawMessage) {
				env["response_format"] = json.RawMessage(`"url"`)
			},
			"response_format",
		},
		{
			"pinned field freed from the AAD",
			func(_ wire.Request, e2ee map[string]json.RawMessage) {
				e2ee["unbound_fields"] = json.RawMessage(`["response_format"]`)
			},
			"response_format",
		},
		{
			"pinned field sealed away, so nothing is left to read",
			func(env wire.Request, e2ee map[string]json.RawMessage) {
				e2ee["sealed_fields"] = json.RawMessage(`["prompt","response_format"]`)
				delete(env, "response_format")
			},
			"response_format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := wire.Request{}
			for k, v := range sealed {
				env[k] = v
			}
			var e2ee map[string]json.RawMessage
			if err := json.Unmarshal(env[e2eeKeyForTest], &e2ee); err != nil {
				t.Fatalf("unmarshal _e2ee: %v", err)
			}
			tt.mutate(env, e2ee)
			raw, err := json.Marshal(e2ee)
			if err != nil {
				t.Fatalf("marshal _e2ee: %v", err)
			}
			env[e2eeKeyForTest] = raw

			_, err = wire.OpenRequestFor(wire.ProfileImage, priv, env)
			if err == nil {
				t.Fatal("OpenRequestFor must refuse this envelope")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error should name %q, got: %v", tt.want, err)
			}
		})
	}
}

// §7.1 requires a sealed image response to restate its billable count in
// cleartext, because sealing `data` makes the images uncountable from outside.
// The failure mode when it is missing is the reason this is a MUST and not a
// convention: the router parses the frame perfectly well, counts zero images,
// and bills nothing — no error, no log line, no bounded blast radius. A missing
// count and a genuine zero are the same bytes.
func TestSealedImageResponseMustCarryTheBillableCount(t *testing.T) {
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sealed := wire.DefaultResponseSealedFieldsFor(wire.ProfileImage)
	seal := func(resp wire.Response) error {
		_, err := wire.SealResponseFor(wire.ProfileImage, ephPub, resp, sealed)
		return err
	}
	base := func() wire.Response {
		return wire.Response{
			"created": json.RawMessage(`1700000000`),
			"data":    json.RawMessage(`[{"b64_json":"aW1n"}]`),
		}
	}

	withUsage := base()
	withUsage["usage"] = json.RawMessage(`{"output_images":1}`)
	if err := seal(withUsage); err != nil {
		t.Fatalf("a conforming image response must still seal: %v", err)
	}

	for _, tc := range []struct {
		name  string
		usage json.RawMessage // nil → omit `usage` entirely
	}{
		{name: "no usage at all"},
		{name: "usage without the count", usage: json.RawMessage(`{"input_tokens":10}`)},
		{name: "count is not a number", usage: json.RawMessage(`{"output_images":"2"}`)},
		{name: "count is negative", usage: json.RawMessage(`{"output_images":-1}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := base()
			if tc.usage != nil {
				resp["usage"] = tc.usage
			}
			err := seal(resp)
			if err == nil {
				t.Fatal("an image response that cannot be billed must not be sealed")
			}
			if !strings.Contains(err.Error(), "output_images") {
				t.Fatalf("error should name the missing count, got: %v", err)
			}
		})
	}

	// A zero count is a legitimate value (a request that produced nothing), and
	// must not be confused with the absence this test is about.
	zero := base()
	zero["usage"] = json.RawMessage(`{"output_images":0}`)
	if err := seal(zero); err != nil {
		t.Fatalf("an explicit zero is a valid count, not an omission: %v", err)
	}
}

// The receiving half of the same rule, and the half that holds against an
// enclave which is not running this library — a third-party enclave, or one that
// drops the count on purpose to be served for free. The client is the only party
// with both an interest and a way to notice.
func TestClientRefusesASealedImageResponseWithoutTheBillableCount(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Seal through the CHAT profile to model a non-conforming enclave: the wire
	// format is identical across profiles, so this produces exactly the frame an
	// enclave that skipped the §7.1 check would emit.
	frame, err := wire.SealResponse(ephPub, wire.Response{
		"created": json.RawMessage(`1700000000`),
		"data":    json.RawMessage(`[{"b64_json":"aW1n"}]`),
	}, wire.DefaultResponseSealedFieldsFor(wire.ProfileImage))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, ok := frame["usage"]; ok {
		t.Fatal("precondition: this frame is supposed to be missing its billable count")
	}

	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, frame); err == nil {
		t.Fatal("the client must refuse an image response that states no billable count")
	} else if !strings.Contains(err.Error(), "output_images") {
		t.Fatalf("error should name the missing count, got: %v", err)
	}
}

// FINAL frames only. `usage` is a property of the whole response, so a streaming
// profile legitimately withholds it until the last frame; requiring it on every
// frame would make streaming impossible for any profile that ever needs one.
func TestOnlyTheFinalFrameOwesTheBillableCount(t *testing.T) {
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rs, err := wire.NewResponseSealerFor(wire.ProfileImage, ephPub)
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}
	sealed := wire.DefaultResponseSealedFieldsFor(wire.ProfileImage)
	partial := wire.Response{"data": json.RawMessage(`[{"b64_json":"cGFydA"}]`)}
	if _, err := rs.SealFrame(partial, sealed, false); err != nil {
		t.Fatalf("a non-final frame owes no count yet: %v", err)
	}
	last := wire.Response{"data": json.RawMessage(`[{"b64_json":"cmVzdA"}]`)}
	if _, err := rs.SealFrame(last, sealed, true); err == nil {
		t.Fatal("the frame that closes the response must carry the count")
	}
}

// ValidateSealedFieldsFor is documented as the fail-fast validator for an
// operator-supplied set (the sidecar's -seal-fields). Both rules it enforces
// depend on nothing but (profile, fields), so an operator must get both verdicts
// at startup. With the pinned half checked only inside SealRequestFor,
// `prompt,response_format` validated clean and then failed every single request
// — precisely the outcome the up-front call exists to rule out.
func TestConfigTimeValidationRejectsASetThatSealsThePin(t *testing.T) {
	err := wire.ValidateSealedFieldsFor(wire.ProfileImage, []string{"prompt", "response_format"})
	if err == nil {
		t.Fatal("a sealed set that swallows the pinned cleartext field must be rejected at config time")
	}
	if !strings.Contains(err.Error(), "response_format") {
		t.Fatalf("error should name the pinned field, got: %v", err)
	}
	if err := wire.ValidateSealedFieldsFor(wire.ProfileImage, []string{"prompt"}); err != nil {
		t.Fatalf("the conforming set must still validate: %v", err)
	}
	// Chat pins nothing, so the same field name is an ordinary extra there.
	if err := wire.ValidateSealedFieldsFor(wire.ProfileChat, []string{"messages", "response_format"}); err != nil {
		t.Fatalf("chat has no pin to violate: %v", err)
	}
}
