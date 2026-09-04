package wire_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The object form is what makes this payload: it names the operation being
// invoked, in the caller's own vocabulary.
const (
	chatToolChoice = `{"type":"function","function":{"name":"transfer_funds"}}`
	anthToolChoice = `{"type":"tool","name":"transfer_funds"}`
)

func toolChoiceFor(p wire.Profile) string {
	if p == wire.ProfileAnthropic {
		return anthToolChoice
	}
	return chatToolChoice
}

// toolChoiceReq is a minimal valid request for a surface, carrying tool_choice
// and the tools it selects from — the shape a real tool-calling request has.
func toolChoiceReq(t *testing.T, p wire.Profile, choice string) wire.Request {
	t.Helper()
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":` + toolsJSON + `}`
	if p == wire.ProfileAnthropic {
		body = `{"model":"claude-x","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"tools":` + toolsJSON + `}`
	}
	r := mustReq(t, body)
	if choice != "" {
		r["tool_choice"] = json.RawMessage(choice)
	}
	return r
}

func toolChoiceProfiles() []wire.Profile {
	return []wire.Profile{wire.ProfileChat, wire.ProfileAnthropic}
}

// The sender half. A set that seals every schema but leaves `tool_choice`
// cleartext is the exact shape this change exists to refuse: it hides the menu
// of operations and hands over the one being invoked.
func TestToolChoiceMustBeSealedWheneverPresent(t *testing.T) {
	for _, p := range toolChoiceProfiles() {
		t.Run(string(p), func(t *testing.T) {
			_, encPub, ephPub := toolsKeys(t)

			_, err := wire.SealRequestFor(p, encPub, toolChoiceReq(t, p, toolChoiceFor(p)),
				[]string{"messages", "tools"}, testProvider, ephPub)
			if err == nil {
				t.Fatal("sealing the schemas while leaving tool_choice cleartext must be refused")
			}
			if !strings.Contains(err.Error(), "tool_choice") {
				t.Errorf("error should name the field left in the clear, got %v", err)
			}
		})
	}
}

// The enum forms carry nothing, and are sealed anyway. The rule is about the
// FIELD, not its value: a value-shaped exemption is what a sender would aim at,
// and "auto" is not a safe spelling of "cleartext".
func TestToolChoiceEnumFormsAreSealedToo(t *testing.T) {
	for _, choice := range []string{`"auto"`, `"none"`, `"required"`, `null`} {
		t.Run(choice, func(t *testing.T) {
			_, encPub, ephPub := toolsKeys(t)
			_, err := wire.SealRequestFor(wire.ProfileChat, encPub,
				toolChoiceReq(t, wire.ProfileChat, choice),
				[]string{"messages", "tools"}, testProvider, ephPub)
			if err == nil {
				t.Errorf("tool_choice:%s is present and must be sealed like any other value", choice)
			}
		})
	}
}

// The receiver half, which is the load-bearing one (SPEC §12). The envelope
// must be SELF-CONSISTENT — built with tool_choice in the cleartext half rather
// than edited afterwards, which the AAD would catch on its own. Built through
// the image profile, whose payload is `prompt`, with the target profile's
// mandatory fields sealed as extras so the request reaches the check under
// test.
func TestEnclaveRefusesAnEnvelopeCarryingToolChoiceInTheClear(t *testing.T) {
	for _, p := range toolChoiceProfiles() {
		t.Run(string(p), func(t *testing.T) {
			encPriv, encPub, ephPub := toolsKeys(t)

			hostile := wire.Request{
				"model":           json.RawMessage(`"m"`),
				"prompt":          json.RawMessage(`"a cat"`),
				"response_format": json.RawMessage(`"b64_json"`),
				"messages":        json.RawMessage(`[{"role":"user","content":"hi"}]`),
				"max_tokens":      json.RawMessage(`16`),
				"tools":           json.RawMessage(toolsJSON),
				"tool_choice":     json.RawMessage(toolChoiceFor(p)),
			}
			env, err := wire.SealRequestFor(wire.ProfileImage, encPub, hostile,
				[]string{"prompt", "messages", "tools"}, testProvider, ephPub)
			if err != nil {
				t.Fatalf("building the hostile envelope: %v", err)
			}
			if _, ok := env["tool_choice"]; !ok {
				t.Fatal("precondition: the image profile should have left tool_choice cleartext")
			}
			// Crypto-valid: the AAD was computed over a cleartext half that
			// includes tool_choice, so the profile-less open accepts it. Without
			// this the test could pass for the AEAD's reasons.
			if _, err := wire.OpenRequest(encPriv, env); err != nil {
				t.Fatalf("precondition: the envelope must be crypto-valid: %v", err)
			}

			_, err = wire.OpenRequestFor(p, encPriv, env)
			if err == nil {
				t.Fatal("an enclave must refuse a request whose tool_choice arrived in the clear")
			}
			if !strings.Contains(err.Error(), "tool_choice") {
				t.Errorf("error should name the field that arrived in the clear, got %v", err)
			}
		})
	}
}

// A request that sets no tool_choice is the common case and must not be
// burdened — the whole point of the optional flag.
func TestRequestWithoutToolChoiceIsUnaffected(t *testing.T) {
	for _, p := range toolChoiceProfiles() {
		t.Run(string(p), func(t *testing.T) {
			encPriv, encPub, ephPub := toolsKeys(t)
			env, err := wire.SealRequestFor(p, encPub, toolChoiceReq(t, p, ""),
				[]string{"messages", "tools"}, testProvider, ephPub)
			if err != nil {
				t.Fatalf("a request with no tool_choice must seal: %v", err)
			}
			if _, err := wire.OpenRequestFor(p, encPriv, env); err != nil {
				t.Errorf("and must open: %v", err)
			}
		})
	}
}

// The round trip must return it — the rule is "seal it", not "drop it" — and the
// selected tool's name must appear nowhere in the envelope's bytes.
func TestSealedToolChoiceSurvivesAndLeavesNoCleartext(t *testing.T) {
	for _, p := range toolChoiceProfiles() {
		t.Run(string(p), func(t *testing.T) {
			encPriv, encPub, ephPub := toolsKeys(t)
			req := toolChoiceReq(t, p, toolChoiceFor(p))

			var fields []string
			for _, f := range wire.DefaultSealedFieldsFor(p) {
				if _, present := req[f]; present {
					fields = append(fields, f)
				}
			}
			env, err := wire.SealRequestFor(p, encPub, req, fields, testProvider, ephPub)
			if err != nil {
				t.Fatalf("seal with the presence-filtered default %v: %v", fields, err)
			}
			if _, leaked := env["tool_choice"]; leaked {
				t.Error("the default sealed set left tool_choice in the cleartext half")
			}
			raw, err := json.Marshal(env)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(raw), "transfer_funds") {
				t.Error("the selected tool's name appears in the sealed envelope's bytes")
			}

			got, err := wire.OpenRequestFor(p, encPriv, env)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !strings.Contains(string(got["tool_choice"]), "transfer_funds") {
				t.Errorf("reconstructed request lost its tool_choice: %s", got["tool_choice"])
			}
		})
	}
}

// The default sealed set must contain it, or the default itself produces the
// envelope the rule above refuses.
func TestToolChoiceIsInTheDefaultSealedSet(t *testing.T) {
	for _, p := range toolChoiceProfiles() {
		found := false
		for _, f := range wire.DefaultSealedFieldsFor(p) {
			if f == "tool_choice" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s default sealed set %v omits tool_choice", p, wire.DefaultSealedFieldsFor(p))
		}
	}
}
