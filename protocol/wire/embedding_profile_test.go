package wire_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A representative embedding request. `input` is an ARRAY here rather than a
// single string on purpose: the batch form is what a retrieval pipeline actually
// sends, and it is the form where the payload is a corpus rather than a query —
// the case the profile exists for.
//
// It carries `encoding_format` and `dimensions` because they are the two fields
// this profile deliberately leaves cleartext: a fixture without them would pass
// just as well if they were being sealed, which is the regression that matters
// here. (The pin test below additionally covers the case where both are absent.)
const sampleEmbeddingReq = `{
  "model": "qwen3.7-text-embedding",
  "encoding_format": "base64",
  "dimensions": 256,
  "input": ["patient chart 4471: presenting complaint", "internal roadmap Q3"]
}`

// The response shape: the vectors in `data`, the billable token count in
// cleartext `usage`. One frame, never streamed.
const sampleEmbeddingResp = `{
  "object": "list",
  "model": "qwen3.7-text-embedding",
  "usage": { "prompt_tokens": 14, "total_tokens": 14 },
  "data": [
    {"object": "embedding", "index": 0, "embedding": [0.0231, -0.0917, 0.4412]},
    {"object": "embedding", "index": 1, "embedding": [0.1104, 0.2280, -0.3319]}
  ]
}`

func TestEmbeddingProfileSealsInputAndLeavesRoutingFieldsCleartext(t *testing.T) {
	// speechKeys despite the name: it is this package's generic
	// (recipient, recipient-pub, ephemeral-pub) keygen, with nothing
	// speech-specific in it. Reused rather than cloned a third time.
	priv, pub, ephPub := speechKeys(t)

	env, err := wire.SealRequestFor(wire.ProfileEmbedding, pub, mustReq(t, sampleEmbeddingReq),
		nil, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, ok := env["input"]; ok {
		t.Error("`input` must not remain as a cleartext field")
	}
	for _, f := range []string{"model", "encoding_format", "dimensions"} {
		if _, ok := env[f]; !ok {
			t.Errorf("cleartext field %q must survive sealing: the router routes on it "+
				"and this profile pins nothing", f)
		}
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	for _, secret := range []string{"patient chart 4471", "internal roadmap Q3"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("payload %q leaked into the sealed envelope", secret)
		}
	}

	got, err := wire.OpenRequestFor(wire.ProfileEmbedding, priv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var input []string
	if err := json.Unmarshal(got["input"], &input); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	if len(input) != 2 || !strings.Contains(input[0], "patient chart 4471") {
		t.Fatalf("round-tripped input = %v, want the two original strings", input)
	}
}

// The payload field is `input`, and a set without it defeats the profile.
//
// Asserted against the IMAGE set specifically, in both directions, because the
// two profiles seal a response field of the same name: `data` is shared by
// coincidence of the OpenAI surface, not because the profiles are related, and a
// reader who notices the shared name could conclude the request rules are
// interchangeable too. `prompt` is also just a plausible thing to send to an
// endpoint that takes text.
func TestEmbeddingAndImageSealedSetsAreNotInterchangeable(t *testing.T) {
	if err := wire.ValidateSealedFieldsFor(wire.ProfileEmbedding, []string{"prompt"}); err == nil {
		t.Error("the embedding profile must reject an image sealed set")
	} else if !strings.Contains(err.Error(), "input") {
		t.Errorf("error should name the missing payload field, got %v", err)
	}
	if err := wire.ValidateSealedFieldsFor(wire.ProfileImage, []string{"input"}); err == nil {
		t.Error("the image profile must reject an embedding sealed set")
	}
}

// This profile pins NOTHING, and that is a decision rather than an omission — so
// it is asserted, not left to the absence of a test.
//
// `encoding_format` is the field that invites a pin: it reads exactly like the
// image profile's `response_format`, which IS pinned, to the one value
// `b64_json`. The difference is what the other values do. Image's `url` has the
// enclave publish the generated images from a plain URL, outside the sealed
// channel — the result itself leaks. Embedding's `float` and `base64` both put
// the vectors in `data`, which this profile seals either way: the field selects
// an encoding, not a destination.
//
// So every value, and the field's ABSENCE, must seal cleanly. A pin copied over
// from the image profile would fail this test, which is the point — and note
// which case does the most work: a pin requires the field to be PRESENT (silence
// selects the server's default, which is what a pin guards against), so the
// third fixture below, which omits both fields, is the ordinary request a pin
// would reject.
func TestEmbeddingProfilePinsNoCleartextField(t *testing.T) {
	_, pub, ephPub := speechKeys(t)

	for _, body := range []string{
		`{"model":"m","input":"x","encoding_format":"float","dimensions":256}`,
		`{"model":"m","input":"x","encoding_format":"base64","dimensions":256}`,
		`{"model":"m","input":"x"}`, // neither field present
		`{"model":"m","input":"x","encoding_format":"float"}`,
	} {
		if _, err := wire.SealRequestFor(wire.ProfileEmbedding, pub, mustReq(t, body),
			nil, testProvider, ephPub); err != nil {
			t.Errorf("this profile pins nothing, so %s must seal: %v", body, err)
		}
	}
}

// The enclave half of the same rule: an envelope arriving with any of those
// values must open, not be refused. validatePinnedFor is a no-op for a profile
// with no pins, and this is what keeps it that way.
func TestEmbeddingEnclaveAcceptsEveryEncodingFormat(t *testing.T) {
	priv, pub, ephPub := speechKeys(t)

	for _, format := range []string{`"float"`, `"base64"`} {
		body := `{"model":"m","input":"x","encoding_format":` + format + `}`
		env, err := wire.SealRequestFor(wire.ProfileEmbedding, pub, mustReq(t, body),
			nil, testProvider, ephPub)
		if err != nil {
			t.Fatalf("seal %s: %v", body, err)
		}
		if _, err := wire.OpenRequestFor(wire.ProfileEmbedding, priv, env); err != nil {
			t.Errorf("enclave must accept encoding_format %s: %v", format, err)
		}
	}
}

func TestEmbeddingResponseSealsTheVectorsAndLeavesUsageReadable(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	sealed, err := wire.SealResponseFor(wire.ProfileEmbedding, ephPub,
		mustResp(t, sampleEmbeddingResp), nil)
	if err != nil {
		t.Fatalf("seal response: %v", err)
	}

	if _, ok := sealed["data"]; ok {
		t.Error("`data` must not remain cleartext: the vectors are the sensitive content")
	}
	if _, ok := sealed["usage"]; !ok {
		t.Error("`usage` must stay cleartext: it is what the router bills on")
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	// A vector is recoverable content: two embeddings of the same corpus are
	// comparable, so leaking them leaks the corpus' structure even without the
	// text. 0.0231 is one coordinate of the fixture.
	if strings.Contains(string(raw), "0.0231") {
		t.Error("a vector coordinate leaked into the sealed frame")
	}

	got, err := wire.OpenResponseFor(wire.ProfileEmbedding, ephPriv, sealed)
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	var data []struct {
		Index     int       `json:"index"`
		Embedding []float64 `json:"embedding"`
	}
	if err := json.Unmarshal(got["data"], &data); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if len(data) != 2 || len(data[0].Embedding) != 3 {
		t.Fatalf("round-tripped data = %v, want two 3-dimensional vectors", data)
	}
}

// A sealed embedding response MUST restate `usage.prompt_tokens` in cleartext,
// on both sides (§7.4). This is the regression test for a wrong argument, not
// just for the rule: the first version of this profile required nothing here, on
// the grounds that `usage` is already kept readable, unsealable and bound by the
// profile-independent floor. Those floors forbid SEALING and UNBINDING the
// field; they never require it to EXIST, so a frame with no `usage` at all
// sealed and opened cleanly.
//
// What that costs is not a missed count but a priced one. The router's estimator
// for a provider that omits usage measures the request's `input`, since an
// embedding response echoes no text back to measure instead — and this profile
// seals `input`, so the estimate floors to a constant while the enclave, holding
// the decrypted input, bills the provider accurately.
//
// Both halves are asserted because §12 gives them to different parties: the
// sealer must refuse to build the frame, and the client must refuse to accept one
// a third-party enclave built anyway.
func TestSealedEmbeddingResponseMustRestateTheBillableTokenCount(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	noUsage := `{"object":"list","model":"m","data":[{"index":0,"embedding":[0.5]}]}`
	if _, err := wire.SealResponseFor(wire.ProfileEmbedding, ephPub, mustResp(t, noUsage), nil); err == nil {
		t.Error("the sealer must refuse an embedding response that states no billable count")
	} else if !strings.Contains(err.Error(), "prompt_tokens") {
		t.Errorf("error should name the missing count, got: %v", err)
	}

	// A `usage` block that exists but omits the count is the same violation, and
	// the one the "it's already cleartext" argument most invited: the field the
	// floor protects IS present.
	emptyUsage := `{"object":"list","model":"m","usage":{"total_tokens":14},` +
		`"data":[{"index":0,"embedding":[0.5]}]}`
	if _, err := wire.SealResponseFor(wire.ProfileEmbedding, ephPub, mustResp(t, emptyUsage), nil); err == nil {
		t.Error("a usage block without prompt_tokens must be refused too")
	}

	// The receive side, against a sealer with the profile checks dropped —
	// exactly the frame a third-party enclave that never ran them would emit.
	frame, err := wire.SealResponseNonConforming(ephPub, mustResp(t, noUsage),
		wire.DefaultResponseSealedFieldsFor(wire.ProfileEmbedding))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, ok := frame["usage"]; ok {
		t.Fatal("precondition: this frame is supposed to be missing its billable count")
	}
	if _, err := wire.OpenResponseFor(wire.ProfileEmbedding, ephPriv, frame); err == nil {
		t.Error("the client must refuse an embedding response that states no billable count")
	} else if !strings.Contains(err.Error(), "prompt_tokens") {
		t.Errorf("error should name the missing count, got: %v", err)
	}

	// And the conforming frame still round-trips, so the rule above is a
	// requirement rather than a blanket refusal.
	ok := `{"object":"list","model":"m","usage":{"prompt_tokens":14,"total_tokens":14},` +
		`"data":[{"index":0,"embedding":[0.5]}]}`
	sealed, err := wire.SealResponseFor(wire.ProfileEmbedding, ephPub, mustResp(t, ok), nil)
	if err != nil {
		t.Fatalf("a conforming embedding response must seal: %v", err)
	}
	if _, err := wire.OpenResponseFor(wire.ProfileEmbedding, ephPriv, sealed); err != nil {
		t.Fatalf("and open: %v", err)
	}
}

// The vector COUNT, by contrast, is correctly not required: nothing bills on how
// many vectors came back, so a rule restating it would enforce a number no party
// reads. Asserted so the fix above is not over-applied into image's shape.
func TestEmbeddingResponseOwesNoVectorCount(t *testing.T) {
	_, ephPub := ephKeys(t)

	// `usage` carries the token count and nothing resembling image's
	// `output_images` / an embedding count anywhere.
	frame := `{"object":"list","model":"m","usage":{"prompt_tokens":14,"total_tokens":14},` +
		`"data":[{"index":0,"embedding":[0.5]},{"index":1,"embedding":[0.25]}]}`
	if _, err := wire.SealResponseFor(wire.ProfileEmbedding, ephPub, mustResp(t, frame), nil); err != nil {
		t.Fatalf("two vectors and no restated vector count must still seal: %v", err)
	}
}

// The profile must be enumerated with its payload fields, for the reason
// Profiles() exists: route's withheld-field set is the COMPLEMENT of the union
// over every profile, so a profile missing from it turns its payload into an
// upload rather than an error.
func TestEmbeddingProfileIsEnumeratedWithItsPayloadField(t *testing.T) {
	if !slices.Contains(wire.Profiles(), wire.ProfileEmbedding) {
		t.Fatalf("Profiles() omits the embedding profile: %v", wire.Profiles())
	}
	var union []string
	for _, p := range wire.Profiles() {
		union = append(union, wire.DefaultSealedFieldsFor(p)...)
	}
	if !slices.Contains(union, "input") {
		t.Errorf("the union over Profiles() is missing `input`: %v", union)
	}
}
