package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The two response shapes the speech profile's permitted formats produce
// (SPEC §7.3). `json` reports the billable duration inside `usage`;
// `verbose_json` commonly carries no `usage` at all and reports it as a
// top-level `duration`, which is why the requirement has two locators.
const (
	speechJSONFrame = `{
  "model": "whisper-large-v3",
  "usage": { "type": "duration", "seconds": 12.5 },
  "text": "the transcript"
}`

	speechVerboseFrame = `{
  "model": "whisper-large-v3",
  "task": "transcribe",
  "duration": 12.5,
  "text": "the transcript",
  "language": "en",
  "segments": [{"id": 0, "start": 0.0, "end": 12.5, "text": "the transcript"}]
}`
)

func ephKeys(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	return priv, pub
}

// ---------------------------------------------------------------------------
// Round trips, and the non-constant sealed set (SPEC §7.3)
// ---------------------------------------------------------------------------

func TestSpeechJSONResponseSealsOnlyTheTranscript(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	sealed, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, speechJSONFrame), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, ok := sealed["text"]; ok {
		t.Error("the transcript must not remain cleartext")
	}
	if _, ok := sealed["usage"]; !ok {
		t.Error("usage must stay cleartext so the router can bill without a key")
	}
	e2ee, err := sealed.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	if got := e2ee.SealedFields; len(got) != 1 || got[0] != "text" {
		t.Fatalf("sealed_fields = %v, want [text]", got)
	}

	opened, err := wire.OpenResponseFor(wire.ProfileSpeech, ephPriv, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var text string
	if err := json.Unmarshal(opened["text"], &text); err != nil {
		t.Fatalf("decode text: %v", err)
	}
	if text != "the transcript" {
		t.Fatalf("text = %q", text)
	}
}

// The point of an OPTIONAL response payload field: a nil sealed set resolves against THIS
// frame, so the verbose shape's `segments` and inferred `language` are sealed
// without the caller naming them, and the json shape above is not asked for
// fields it does not have.
func TestSpeechVerboseResponseSealsSegmentsAndInferredLanguage(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	frame := mustResp(t, speechVerboseFrame)
	resolved, err := wire.ResponseSealedFieldsForFrame(wire.ProfileSpeech, frame)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, want := range []string{"text", "segments", "language"} {
		if !containsString(resolved, want) {
			t.Errorf("resolved sealed set %v should contain %q", resolved, want)
		}
	}
	if containsString(resolved, "words") {
		t.Errorf("resolved sealed set %v must not contain a field the frame lacks", resolved)
	}

	sealed, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, frame, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "the transcript") {
		t.Fatal("the transcript leaked into the sealed frame (segments carry it too)")
	}
	if _, ok := sealed["duration"]; !ok {
		t.Error("the top-level duration must stay cleartext: it is what the router bills on here")
	}

	opened, err := wire.OpenResponseFor(wire.ProfileSpeech, ephPriv, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, ok := opened["segments"]; !ok {
		t.Error("segments must come back after opening")
	}
}

// The frameless accessor MUST answer with the empty set for this profile
// (SPEC §7.3), and this is the behavioural half: the answer has to make a caller
// that uses it FAIL, on the first request, rather than work by accident.
//
// The property is worth stating precisely, because the plausible answer is
// dangerous in a way an incomplete one is not. `["text"]` is valid for every
// `json` transcription and invalid for every `verbose_json` one, so a broker
// holding it passes all of its own testing and then fails 100% of verbose
// responses the first time a client asks for timestamps — after the upstream
// call, which is already paid for. The empty set fails on request one.
//
// TestProfileDefaults pins the accessor's value; this pins what the value buys.
func TestSpeechFramelessDefaultFailsClosedOnBothShapes(t *testing.T) {
	_, ephPub := ephKeys(t)

	defaults := wire.DefaultResponseSealedFieldsFor(wire.ProfileSpeech)
	if len(defaults) != 0 {
		t.Fatalf("frameless response defaults for speech = %v, want empty: there is no profile-wide answer, and a plausible-looking one is latent (see the doc comment)", defaults)
	}

	// Both shapes, because the failure has to be immediate on the SHAPE THAT
	// WOULD OTHERWISE WORK too. A guard that only rejected verbose frames would
	// leave the latent bug exactly where it was.
	for name, frame := range map[string]string{
		"json":         speechJSONFrame,
		"verbose_json": speechVerboseFrame,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, frame), defaults); err == nil {
				t.Fatal("sealing with the frameless defaults must fail closed; a caller must be pushed to ResponseSealedFieldsForFrame")
			}
		})
	}

	// And the correct route works for both shapes, so the refusal above is a
	// signpost rather than a dead end.
	for name, frame := range map[string]string{
		"json":         speechJSONFrame,
		"verbose_json": speechVerboseFrame,
	} {
		t.Run("resolved/"+name, func(t *testing.T) {
			resolved, err := wire.ResponseSealedFieldsForFrame(wire.ProfileSpeech, mustResp(t, frame))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if _, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, frame), resolved); err != nil {
				t.Fatalf("the frame-resolved set must seal: %v", err)
			}
		})
	}
}

// `words` is present only when word granularity was requested, which is exactly
// why the set cannot be a constant.
func TestSpeechResponseSealsWordsWhenPresent(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	frame := mustResp(t, speechVerboseFrame)
	frame["words"] = json.RawMessage(`[{"word":"transcript","start":1.0,"end":1.5}]`)

	sealed, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, frame, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, ok := sealed["words"]; ok {
		t.Fatal("words carries the transcript per word and must be sealed")
	}
	if _, err := wire.OpenResponseFor(wire.ProfileSpeech, ephPriv, sealed); err != nil {
		t.Fatalf("open: %v", err)
	}
}

// A caller naming the set explicitly and forgetting a conditional field is
// refused at seal time — the only place the leak is prevented rather than
// detected.
func TestSpeechSealerRefusesAFrameThatLeavesSegmentsCleartext(t *testing.T) {
	_, ephPub := ephKeys(t)

	_, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, speechVerboseFrame), []string{"text"})
	if err == nil {
		t.Fatal("a verbose frame sealing only text leaves the transcript in segments, in the clear")
	}
	if !strings.Contains(err.Error(), "segments") {
		t.Errorf("error should name the field, got %v", err)
	}
}

// The receiver half, and the load-bearing one: a non-conforming enclave can emit
// this frame, a router forwards it unremarkably, and the client is the only
// party that can tell `segments` was never sealed.
func TestSpeechClientRefusesAFrameCarryingSegmentsInCleartext(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	// Seal a conforming json-shaped frame, then add what a non-conforming enclave
	// would have shipped in the clear. The AAD covers the addition so Open would
	// fail regardless — the point is that the PROFILE check fires first, with a
	// message that says what is wrong instead of an opaque AEAD failure.
	sealed, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, speechJSONFrame), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sealed["segments"] = json.RawMessage(`[{"id":0,"text":"the transcript"}]`)

	_, err = wire.OpenResponseFor(wire.ProfileSpeech, ephPriv, sealed)
	if err == nil {
		t.Fatal("the client must refuse a frame carrying segments in cleartext")
	}
	if !strings.Contains(err.Error(), "segments") {
		t.Errorf("the profile check should fire before the AEAD, naming the field; got %v", err)
	}
}

// Chat and image list no conditional response fields, so the union is inert for
// them: their resolved set is still exactly the profile default.
func TestConditionalResponseSealingIsInertForOtherProfiles(t *testing.T) {
	for _, tc := range []struct {
		profile wire.Profile
		frame   string
		want    string
	}{
		{wire.ProfileChat, `{"model":"gpt-4o","choices":[],"segments":[1]}`, "choices"},
		{wire.ProfileImage, `{"model":"z-image","data":[],"usage":{"output_images":0}}`, "data"},
	} {
		t.Run(string(tc.profile), func(t *testing.T) {
			got, err := wire.ResponseSealedFieldsForFrame(tc.profile, mustResp(t, tc.frame))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("resolved = %v, want [%s] — a stray same-named field must not be pulled in", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The billable quantity: two alternative locators (SPEC §7.3)
// ---------------------------------------------------------------------------

func TestSpeechResponseAcceptsEitherDurationLocator(t *testing.T) {
	for name, frame := range map[string]string{
		"usage.seconds":      speechJSONFrame,
		"top-level duration": speechVerboseFrame,
	} {
		t.Run(name, func(t *testing.T) {
			_, ephPub := ephKeys(t)
			if _, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, frame), nil); err != nil {
				t.Fatalf("%s must satisfy the requirement on its own: %v", name, err)
			}
		})
	}
}

func TestSpeechResponseRefusesAFrameWithNoDurationAtAll(t *testing.T) {
	_, ephPub := ephKeys(t)
	frame := mustResp(t, speechJSONFrame)
	delete(frame, "usage")

	_, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, frame, nil)
	if err == nil {
		t.Fatal("a frame with neither locator must be refused: the router would bill a fabricated constant")
	}
	if !strings.Contains(err.Error(), "duration") {
		t.Errorf("error should name the quantity, got %v", err)
	}
}

// The client half. An omitted duration does not under-bill quietly here — the
// router estimates from a transcript sealing made empty and charges a flat
// constant — so the client is the party that must refuse the frame.
func TestSpeechClientRefusesAFinalFrameWithNoDuration(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	sealed, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, speechJSONFrame), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	delete(sealed, "usage")

	if _, err := wire.OpenResponseFor(wire.ProfileSpeech, ephPriv, sealed); err == nil {
		t.Fatal("the client must refuse a final frame that states no duration")
	}
}

func TestSpeechResponseAcceptsBothLocatorsWhenTheyAgree(t *testing.T) {
	_, ephPub := ephKeys(t)
	frame := mustResp(t, speechVerboseFrame)
	frame["usage"] = json.RawMessage(`{"type":"duration","seconds":12.50}`)

	if _, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, frame, nil); err != nil {
		t.Fatalf("12.5 and 12.50 are the same number and must be accepted: %v", err)
	}
}

// The rule alternation brings with it: one reader bills usage.seconds, another
// opens duration, so a frame stating two different numbers is one response
// transacted at two prices.
func TestSpeechResponseRefusesDisagreeingLocators(t *testing.T) {
	_, ephPub := ephKeys(t)
	frame := mustResp(t, speechVerboseFrame)
	frame["usage"] = json.RawMessage(`{"type":"duration","seconds":900}`)

	_, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, frame, nil)
	if err == nil {
		t.Fatal("a frame stating the duration twice and disagreeing must be refused")
	}
	if !strings.Contains(err.Error(), "disagrees") {
		t.Errorf("error should say the two locators disagree, got %v", err)
	}
}

func TestSpeechDurationNumericDomain(t *testing.T) {
	tests := []struct {
		name    string
		usage   string
		wantErr string
	}{
		{"fractional is valid, unlike an image count", `{"type":"duration","seconds":12.5}`, ""},
		{"an explicit zero is a quantity", `{"type":"duration","seconds":0}`, ""},
		{"an integral value is fine too", `{"type":"duration","seconds":13}`, ""},
		{"a quoted number is refused rather than tolerated", `{"type":"duration","seconds":"12.5"}`, "quoted string"},
		{"null is the absence of a value, not a zero", `{"type":"duration","seconds":null}`, "null"},
		{"negative is not a duration", `{"type":"duration","seconds":-1}`, "negative"},
		{"a non-object usage is malformed, not an unused alternative", `"twelve"`, "JSON object"},
		// `null` decodes into a map with NO error, yielding a nil map, so it would
		// have read as "this alternative is unused" and been satisfied by the other
		// locator. It is also the likeliest junk value for a block an upstream did
		// not populate — `usage: 7` was already refused while `usage: null` sealed
		// cleanly.
		{"a null usage block is not the absence of the block", `null`, "got null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ephPub := ephKeys(t)
			frame := mustResp(t, speechJSONFrame)
			frame["usage"] = json.RawMessage(tt.usage)

			_, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, frame, nil)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("want accepted, got %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("want refused (%s), got accepted", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("error %v should mention %q", err, tt.wantErr)
			}
		})
	}
}

// A malformed `usage` must not be skipped as "the alternative was not used": the
// field is there and wrong, and the router reads it.
func TestSpeechMalformedUsageIsNotRescuedByTheOtherLocator(t *testing.T) {
	_, ephPub := ephKeys(t)
	frame := mustResp(t, speechVerboseFrame) // has a valid top-level duration
	frame["usage"] = json.RawMessage(`"twelve"`)

	if _, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, frame, nil); err == nil {
		t.Fatal("a malformed usage must be an error even when the other locator is valid")
	}
}

// The billable quantity must stay BOUND, not merely cleartext, and the
// profile-independent floor cannot enforce that here: it is the name `usage`,
// so it protects `usage.seconds` and has nothing to say about a top-level
// `duration`. Unbound, the number sits outside the AAD — a router restates it
// and the client's Open AND the §8 binding, which hashes the same AAD, both
// still pass.
func TestSpeechDurationCannotBeDeclaredUnbound(t *testing.T) {
	_, ephPub := ephKeys(t)

	_, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, speechVerboseFrame), nil, "duration")
	if err == nil {
		t.Fatal("unbinding the top-level duration must be refused: it is the billed quantity")
	}
	if !strings.Contains(err.Error(), "duration") {
		t.Errorf("error should name the field, got %v", err)
	}
}

// The client half of the same rule: a non-conforming enclave declares it unbound
// on purpose, and no other verification the client runs would notice.
func TestSpeechClientRefusesAFrameThatFreesTheDuration(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	sealed, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, speechVerboseFrame), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	e2ee, err := sealed.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	e2ee.UnboundFields = []string{"duration"}
	rewritten, err := json.Marshal(e2ee)
	if err != nil {
		t.Fatalf("marshal _e2ee: %v", err)
	}
	sealed[e2eeKeyForTest] = rewritten

	if _, err := wire.OpenResponseFor(wire.ProfileSpeech, ephPriv, sealed); err == nil {
		t.Fatal("the client must refuse a frame that declares the billed duration unbound")
	}
}

// A locator MUST NOT be sealed either, and with ALTERNATIVES that does not
// follow from the presence check: a frame can seal `duration` and still satisfy
// §7.3 through a cleartext `usage.seconds`, so the presence check passes and the
// sealed value is invisible.
//
// What refusing the seal buys is the client's half of the agreement rule. At
// seal time both values are in hand and a disagreement is caught; at open time a
// sealed locator is gone from the cleartext, so a client would have nothing to
// compare and a non-conforming enclave could seal a `duration` contradicting the
// number the router bills on.
func TestSpeechDurationLocatorCannotBeSealed(t *testing.T) {
	_, ephPub := ephKeys(t)
	frame := mustResp(t, speechVerboseFrame)
	frame["usage"] = json.RawMessage(`{"type":"duration","seconds":12.5}`)

	_, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, frame,
		[]string{"text", "segments", "language", "duration"})
	if err == nil {
		t.Fatal("sealing the duration locator must be refused even when the other locator stays cleartext")
	}
	if !strings.Contains(err.Error(), "duration") {
		t.Errorf("error should name the field, got %v", err)
	}
}

// The client half of the same rule, on a frame a non-conforming enclave would
// emit: the sealed set names `duration` and the cleartext no longer has it.
func TestSpeechClientRefusesAFrameThatSealedALocator(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	sealed, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, speechJSONFrame), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	e2ee, err := sealed.E2EE()
	if err != nil {
		t.Fatalf("read _e2ee: %v", err)
	}
	e2ee.SealedFields = append(e2ee.SealedFields, "duration")
	rewritten, err := json.Marshal(e2ee)
	if err != nil {
		t.Fatalf("marshal _e2ee: %v", err)
	}
	sealed[e2eeKeyForTest] = rewritten

	if _, err := wire.OpenResponseFor(wire.ProfileSpeech, ephPriv, sealed); err == nil {
		t.Fatal("the client must refuse a frame whose sealed set swallows a quantity locator")
	}
}

// `usage` stays covered by the floor, so the derived rule must not have replaced
// it — both paths have to hold.
func TestSpeechUsageStillCannotBeDeclaredUnbound(t *testing.T) {
	_, ephPub := ephKeys(t)

	if _, err := wire.SealResponseFor(wire.ProfileSpeech, ephPub, mustResp(t, speechJSONFrame), nil, "usage"); err == nil {
		t.Fatal("unbinding usage must still be refused")
	}
}

// The image profile's count stays a WHOLE number: making duration fractional
// must not have relaxed it.
func TestImageCountIsStillWholeNumberOnly(t *testing.T) {
	_, ephPub := ephKeys(t)
	frame := mustResp(t, `{"model":"z-image","data":[],"usage":{"output_images":2.5}}`)

	if _, err := wire.SealResponseFor(wire.ProfileImage, ephPub, frame, []string{"data"}); err == nil {
		t.Fatal("2.5 images must still be refused")
	}
}
