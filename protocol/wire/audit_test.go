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
	frame, err := wire.SealResponseNonConforming(ephPub, wire.Response{
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
	rs, err := wire.NewResponseSealerNonConforming(ephPub)
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
	imageFrame, err := wire.SealResponseFor(wire.ProfileImage, ephPub, wire.Response{
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
	// An unknown profile has no requirements to check against, so opening under
	// one must fail rather than degrade into an unchecked open.
	if _, err := wire.OpenRequestFor("audio", priv, sealed); err == nil {
		t.Error("an unknown profile must be rejected")
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
		// null is the one that reads as a perfectly good 0: decoding it into a
		// bare numeric is a no-op that returns no error, so the check meant to
		// tell a real count from the absence of one saw the value §7.1 spells
		// out as legitimate.
		{name: "count is null", usage: json.RawMessage(`{"output_images":null}`)},
		// Fractional and exponent forms are legal JSON numbers the router's own
		// *int parse rejects. The protocol must not seal what its consumer will
		// refuse to bill.
		{name: "count is fractional", usage: json.RawMessage(`{"output_images":2.5}`)},
		{name: "count is in exponent form", usage: json.RawMessage(`{"output_images":1e3}`)},
		{name: "usage is null", usage: json.RawMessage(`null`)},
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
	// A sealer with the profile checks dropped, modelling a third-party enclave
	// that never ran them: the wire format is identical, so this is exactly the
	// frame one that skipped the §7.1 check would emit.
	frame, err := wire.SealResponseNonConforming(ephPub, wire.Response{
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

// ValidateSealedFieldsFor is documented as the fail-fast validator for a
// caller-supplied set (core.WithSealFields). Both rules it enforces depend on
// nothing but (profile, fields), so a caller checking a set up front must get
// both verdicts. With the pinned half checked only inside SealRequestFor,
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

// §12 lists a sender column for "response sealed set covers the generated
// content", and for a while only the receiver column was implemented. The gap
// mattered more than the request-side equivalent: by the time the client refuses
// such a frame, the generated content has already crossed the wire in cleartext
// and every intermediary has read it. Refusing to build it is the only place the
// leak is prevented rather than detected.
func TestSealerRefusesToShipTheContentInTheClear(t *testing.T) {
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	for _, tc := range []struct {
		name    string
		profile wire.Profile
		frame   wire.Response
		want    string
	}{
		{
			"image response seals the timestamp instead of the images",
			wire.ProfileImage,
			wire.Response{
				"created": json.RawMessage(`1700000000`),
				"usage":   json.RawMessage(`{"output_images":1}`),
				"data":    json.RawMessage(`[{"b64_json":"SECRET"}]`),
			},
			"data",
		},
		{
			"chat response seals the timestamp instead of the completion",
			wire.ProfileChat,
			wire.Response{
				"created": json.RawMessage(`1700000000`),
				"choices": json.RawMessage(`[{"message":{"content":"SECRET"}}]`),
			},
			"choices",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := wire.SealResponseFor(tc.profile, ephPub, tc.frame, []string{"created"})
			if err == nil {
				raw, _ := json.Marshal(frame)
				t.Fatalf("the sealer must refuse this; it put the content on the wire: %s", raw)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should name the content field, got: %v", err)
			}
		})
	}

	// Sealing a SUPERSET stays legal — only the profile's content field is
	// mandatory, which is what lets this check run at seal time at all.
	if _, err := wire.SealResponseFor(wire.ProfileImage, ephPub, wire.Response{
		"created": json.RawMessage(`1700000000`),
		"usage":   json.RawMessage(`{"output_images":1}`),
		"data":    json.RawMessage(`[{"b64_json":"aW1n"}]`),
	}, []string{"data", "created"}); err != nil {
		t.Fatalf("a superset of the profile's default must still seal: %v", err)
	}
}

// "nil means this profile's v1 default" — SealFrame read that default from a
// fixed profile, so it held only for chat, and a nil for any other profile
// silently meant "seal choices". The request side never had the bug
// (SealRequestFor reads DefaultSealedFieldsFor(profile)); the response side got
// its profile later and the nil branch was not moved onto it.
//
// It failed closed rather than leaking, but it made the documented contract
// false for every profile added after chat — including every future one.
func TestNilSealedFieldsMeansThisProfilesDefault(t *testing.T) {
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	for _, tc := range []struct {
		profile wire.Profile
		frame   wire.Response
		sealed  string // the field nil must have selected
		clear   string // a field that must remain cleartext
	}{
		{
			wire.ProfileImage,
			wire.Response{
				"usage": json.RawMessage(`{"output_images":1}`),
				"data":  json.RawMessage(`[{"b64_json":"aW1n"}]`),
			},
			"data", "usage",
		},
		{
			wire.ProfileChat,
			wire.Response{
				"usage":   json.RawMessage(`{"total_tokens":3}`),
				"choices": json.RawMessage(`[{"message":{"content":"hi"}}]`),
			},
			"choices", "usage",
		},
	} {
		t.Run(string(tc.profile), func(t *testing.T) {
			frame, err := wire.SealResponseFor(tc.profile, ephPub, tc.frame, nil)
			if err != nil {
				t.Fatalf("nil must select the %s profile's own default: %v", tc.profile, err)
			}
			if _, still := frame[tc.sealed]; still {
				t.Errorf("%q should have been sealed away", tc.sealed)
			}
			if _, ok := frame[tc.clear]; !ok {
				t.Errorf("%q must stay cleartext", tc.clear)
			}
			e2ee, err := frame.E2EE()
			if err != nil {
				t.Fatalf("read _e2ee: %v", err)
			}
			if len(e2ee.SealedFields) != 1 || e2ee.SealedFields[0] != tc.sealed {
				t.Errorf("sealed_fields = %v, want [%q]", e2ee.SealedFields, tc.sealed)
			}
		})
	}
}

// `final` is a bit the SEALER chooses, and the §7.1 obligations fall due on the
// final frame — so hanging a receive-side check on it hands the sender a way to
// skip it. A non-streaming response is exactly one frame, which by definition is
// the final one, so OpenResponseFor requires it: otherwise an enclave ships
// `data` sealed with no `usage` and `final: false`, and the client — using the
// only response shape §7.1 describes — gets a complete answer having verified
// none of what §7.1 promises.
func TestNonStreamingOpenRequiresTheFinalFrame(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rs, err := wire.NewResponseSealerNonConforming(ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	// Everything a conforming image response has, except the billable count —
	// and final:false, which is what used to make that omission unreachable.
	frame, err := rs.SealFrame(wire.Response{
		"created": json.RawMessage(`1700000000`),
		"data":    json.RawMessage(`[{"b64_json":"aW1n"}]`),
	}, []string{"data"}, false)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, frame); err == nil {
		t.Fatal("a non-final frame must not be accepted as a whole response")
	} else if !strings.Contains(err.Error(), "final") {
		t.Fatalf("error should name the missing final marker, got: %v", err)
	}

	// The same omission on a frame that admits to being final is caught by the
	// §7.1 check itself — the two together leave no spelling that gets through.
	// A fresh sealer, since only a first frame carries the enc a lone frame needs.
	rs2, err := wire.NewResponseSealerNonConforming(ephPub)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	final, err := rs2.SealFrame(wire.Response{
		"created": json.RawMessage(`1700000000`),
		"data":    json.RawMessage(`[{"b64_json":"aW1n"}]`),
	}, []string{"data"}, true)
	if err != nil {
		t.Fatalf("seal final: %v", err)
	}
	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, final); err == nil {
		t.Fatal("a final frame with no billable count must not be accepted either")
	} else if !strings.Contains(err.Error(), "output_images") {
		t.Fatalf("error should name the missing count, got: %v", err)
	}

	// And a conforming non-streaming response still opens.
	good, err := wire.SealResponseFor(wire.ProfileImage, ephPub, wire.Response{
		"created": json.RawMessage(`1700000000`),
		"usage":   json.RawMessage(`{"output_images":1}`),
		"data":    json.RawMessage(`[{"b64_json":"aW1n"}]`),
	}, nil)
	if err != nil {
		t.Fatalf("seal good: %v", err)
	}
	if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, good); err != nil {
		t.Fatalf("a conforming single-frame response must open: %v", err)
	}
}

// The receive-side half of the same rule. A client opening a sealed image
// response is the last party that can tell a stated count from a missing one,
// so every spelling of "no usable count" must be refused there too — `null`
// included, which is the spelling that survives a naive numeric decode.
func TestClientRefusesAnUnusableBillableCount(t *testing.T) {
	ephPriv, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	for _, tc := range []struct {
		name  string
		usage string
	}{
		{"null count", `{"output_images":null}`},
		{"fractional count", `{"output_images":2.5}`},
		{"exponent-form count", `{"output_images":1e3}`},
		{"string count", `{"output_images":"2"}`},
		{"negative count", `{"output_images":-1}`},
		{"null usage", `null`},
		{"usage without the count", `{"input_tokens":10}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := wire.SealResponseNonConforming(ephPub, wire.Response{
				"usage": json.RawMessage(tc.usage),
				"data":  json.RawMessage(`[{"b64_json":"aW1n"}]`),
			}, []string{"data"})
			if err != nil {
				t.Fatalf("the non-conforming sealer should still build this: %v", err)
			}
			if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, frame); err == nil {
				t.Fatal("the client must refuse a response it cannot read a count from")
			} else if !strings.Contains(err.Error(), "output_images") {
				t.Fatalf("error should name the count, got: %v", err)
			}
		})
	}

	// A whole non-negative number still opens, zero included.
	for _, ok := range []string{`{"output_images":0}`, `{"output_images":2}`} {
		frame, err := wire.SealResponseFor(wire.ProfileImage, ephPub, wire.Response{
			"usage": json.RawMessage(ok),
			"data":  json.RawMessage(`[{"b64_json":"aW1n"}]`),
		}, nil)
		if err != nil {
			t.Fatalf("seal %s: %v", ok, err)
		}
		if _, err := wire.OpenResponseFor(wire.ProfileImage, ephPriv, frame); err != nil {
			t.Errorf("%s must open: %v", ok, err)
		}
	}
}
