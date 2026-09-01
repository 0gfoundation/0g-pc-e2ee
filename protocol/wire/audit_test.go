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
