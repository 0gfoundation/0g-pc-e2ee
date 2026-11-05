package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A representative decisions request: the state is a conversation opening, the
// question a choice whose criteria are the caller's own descriptions.
const sampleDecisionsReq = `{
  "model": "vela-2.0-9b",
  "state": "<user_message>\npatient 4471 asks about their test results\n</user_message>",
  "questions": {"task": {"type": "choice",
    "instructions": "Which category fits?",
    "criteria": {"qa_knowledge": "Answering a factual question", "math": "Solving a math problem"}}}
}`

// The response: typed answers, and usage in Anthropic's vocabulary.
const sampleDecisionsResp = `{
  "answers": {"task": {"type": "choice", "choice": "qa_knowledge", "confidence": 0.97,
    "probabilities": {"qa_knowledge": 0.97, "math": 0.03}}},
  "usage": {"input_tokens": 212, "output_tokens": 0}
}`

func TestDecisionsProfileSealsStateAndQuestions(t *testing.T) {
	priv, pub, ephPub := speechKeys(t)

	env, err := wire.SealRequestFor(wire.ProfileDecisions, pub, mustReq(t, sampleDecisionsReq),
		nil, testProvider, ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for _, f := range []string{"state", "questions"} {
		if _, ok := env[f]; ok {
			t.Errorf("`%s` must not remain cleartext", f)
		}
	}
	if _, ok := env["model"]; !ok {
		t.Error("`model` must stay cleartext: the router routes on it")
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	// The question's own text is the caller's: it must not leak either.
	for _, s := range []string{"patient 4471", "Answering a factual question", "qa_knowledge"} {
		if strings.Contains(string(raw), s) {
			t.Errorf("%q leaked into the sealed envelope", s)
		}
	}

	got, err := wire.OpenRequestFor(wire.ProfileDecisions, priv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var state string
	if err := json.Unmarshal(got["state"], &state); err != nil || !strings.Contains(state, "patient 4471") {
		t.Fatalf("round-tripped state = %q (%v)", state, err)
	}
	if _, ok := got["questions"]; !ok {
		t.Fatal("round-tripped request lost `questions`")
	}
}

func TestDecisionsProfileRefusesAHalfSealedRequest(t *testing.T) {
	_, pub, ephPub := speechKeys(t)
	// Sealing only `state` would leave the questions readable.
	if _, err := wire.SealRequestFor(wire.ProfileDecisions, pub, mustReq(t, sampleDecisionsReq),
		[]string{"state"}, testProvider, ephPub); err == nil {
		t.Error("a sealed set without `questions` must be refused")
	}
}

func TestDecisionsResponseSealsAnswersAndLeavesUsageReadable(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)

	sealed, err := wire.SealResponseFor(wire.ProfileDecisions, ephPub, mustResp(t, sampleDecisionsResp), nil)
	if err != nil {
		t.Fatalf("seal response: %v", err)
	}
	if _, ok := sealed["answers"]; ok {
		t.Error("`answers` must not remain cleartext")
	}
	if _, ok := sealed["usage"]; !ok {
		t.Error("`usage` must stay cleartext: it is what the router bills on")
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	if strings.Contains(string(raw), "qa_knowledge") {
		t.Error("the chosen criterion leaked into the sealed frame")
	}

	got, err := wire.OpenResponseFor(wire.ProfileDecisions, ephPriv, sealed)
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	var answers map[string]struct {
		Choice string `json:"choice"`
	}
	if err := json.Unmarshal(got["answers"], &answers); err != nil || answers["task"].Choice != "qa_knowledge" {
		t.Fatalf("round-tripped answers = %v (%v)", answers, err)
	}
}

func TestSealedDecisionsResponseMustRestateInputTokens(t *testing.T) {
	ephPriv, ephPub := ephKeys(t)
	noUsage := `{"answers": {"task": {"type": "choice", "choice": "math"}}}`
	if _, err := wire.SealResponseFor(wire.ProfileDecisions, ephPub, mustResp(t, noUsage), nil); err == nil {
		t.Error("an enclave must not seal a decisions response without usage.input_tokens")
	}
	// The usage the router does not bill on is not enough.
	outputOnly := `{"answers": {}, "usage": {"output_tokens": 3}}`
	if _, err := wire.SealResponseFor(wire.ProfileDecisions, ephPub, mustResp(t, outputOnly), nil); err == nil {
		t.Error("output_tokens alone must not satisfy the billable count")
	}

	// The receive side, against a sealer with the profile checks dropped.
	frame, err := wire.SealResponseNonConforming(ephPub, mustResp(t, noUsage),
		wire.DefaultResponseSealedFieldsFor(wire.ProfileDecisions))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := wire.OpenResponseFor(wire.ProfileDecisions, ephPriv, frame); err == nil {
		t.Error("the client must refuse a decisions response that states no billable count")
	} else if !strings.Contains(err.Error(), "input_tokens") {
		t.Errorf("the refusal should name the missing count: %v", err)
	}
}
