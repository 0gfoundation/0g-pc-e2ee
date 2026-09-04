package route

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The tool schemas themselves must never reach the preview — that is what
// withholding `tools` is for, and the whole reason a signal is needed instead of
// just forwarding the field.
const secretToolSchema = `[{"type":"function","function":{"name":"transfer_funds",` +
	`"description":"Move money between the customer's accounts",` +
	`"parameters":{"type":"object","properties":{"iban":{"type":"string"}}}}}]`

// secretToolLeaks are the strings that must not survive into a preview body.
var secretToolLeaks = []string{"transfer_funds", "iban", "Move money"}

func previewOn(t *testing.T, ep endpoint.Endpoint, req wire.Request) map[string]json.RawMessage {
	t.Helper()
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	if _, err := New(router.srv.URL).Resolve(context.Background(), ep, req); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return router.lastPreview
}

// toolsRequest is a minimal valid request for a surface, carrying `tools`.
func toolsRequest(ep endpoint.Endpoint, tools string) wire.Request {
	r := wire.Request{"model": json.RawMessage(`"m"`)}
	switch ep.Profile {
	case wire.ProfileImage:
		r["prompt"] = json.RawMessage(`"a cat"`)
		r["response_format"] = json.RawMessage(`"b64_json"`)
	default:
		r["messages"] = json.RawMessage(`[{"role":"user","content":"hi"}]`)
		r["max_tokens"] = json.RawMessage(`16`)
	}
	if tools != "" {
		r["tools"] = json.RawMessage(tools)
	}
	return r
}

// surfacesWithheldingTools are the surfaces the signal has to work on. Derived
// rather than listed: a fourth surface that withholds `tools` joins these tests
// by existing, which is the only way they keep pace with the endpoint table.
func surfacesWithheldingTools(t *testing.T) []endpoint.Endpoint {
	t.Helper()
	r := New("http://unused")
	var out []endpoint.Endpoint
	for _, ep := range endpoint.All {
		if _, ok := r.withheldFor(ep)["tools"]; ok {
			out = append(out, ep)
		}
	}
	if len(out) == 0 {
		t.Fatal("premise broken: no surface withholds tools, so no signal is needed")
	}
	return out
}

// The bug this fixes, on EVERY surface that withholds the field: before the
// signal the preview said "no tools" and the router's function-calling hard
// filter stopped applying — silently, since a ranking still comes back.
func TestPreviewSignalsToolsWithoutTheSchemas(t *testing.T) {
	for _, ep := range surfacesWithheldingTools(t) {
		t.Run(string(ep.Profile), func(t *testing.T) {
			preview := previewOn(t, ep, toolsRequest(ep, secretToolSchema))

			raw, ok := preview["tools"]
			if !ok {
				t.Fatal("preview omits tools entirely: the router cannot tell this request needs function calling")
			}
			if !nonEmptyJSONArray(raw) {
				t.Errorf("the signal must satisfy the router's detection, got %s", raw)
			}

			body, err := json.Marshal(preview)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			for _, leak := range secretToolLeaks {
				if strings.Contains(string(body), leak) {
					t.Errorf("preview leaked %q from the tool schemas: %s", leak, body)
				}
			}
		})
	}
}

// The placeholder must be the shape of the SURFACE it is sent on. Sending
// OpenAI's `{"type":"function",…}` on a /v1/messages preview is well-formed for
// the wrong schema — harmless while the router only checks presence, and a 400
// on every sealed Anthropic tool request the day it validates the body per
// api_format.
func TestPlaceholderMatchesTheSurfaceSchema(t *testing.T) {
	shapeChecks := map[wire.Profile]func(map[string]any) bool{
		wire.ProfileChat: func(e map[string]any) bool {
			_, hasType := e["type"]
			_, hasFn := e["function"]
			return hasType && hasFn
		},
		wire.ProfileAnthropic: func(e map[string]any) bool {
			_, hasName := e["name"]
			_, hasSchema := e["input_schema"]
			return hasName && hasSchema
		},
	}
	for _, ep := range surfacesWithheldingTools(t) {
		t.Run(string(ep.Profile), func(t *testing.T) {
			check, known := shapeChecks[ep.Profile]
			if !known {
				t.Skipf("no shape expectation recorded for %s", ep.Profile)
			}
			preview := previewOn(t, ep, toolsRequest(ep, secretToolSchema))
			var entries []map[string]any
			if err := json.Unmarshal(preview["tools"], &entries); err != nil {
				t.Fatalf("signal is not an array of objects: %v", err)
			}
			if len(entries) == 0 {
				t.Fatal("signal is an empty array")
			}
			if !check(entries[0]) {
				t.Errorf("%s signal is not that surface's tool shape: %s", ep.Profile, preview["tools"])
			}
		})
	}
}

// `detected` mirrors the router's rule rather than "the field is present", and
// it must do so on the CALLER'S bytes: json.RawMessage keeps them verbatim, so
// a client that pretty-prints sends `[ ]` or "[\n]". A string comparison
// against "[]" lets those through and hard-filters for function calling on a
// request that uses none — under require_parameters, a 400 on a request that
// works today.
func TestPreviewDoesNotSignalToolsForAnEmptyArray(t *testing.T) {
	empties := []string{`[]`, `[ ]`, "[\n]", "[\n   \n]", `null`}
	for _, ep := range surfacesWithheldingTools(t) {
		for _, empty := range empties {
			t.Run(string(ep.Profile)+"/"+strings.NewReplacer("\n", "\\n", " ", "_").Replace(empty), func(t *testing.T) {
				preview := previewOn(t, ep, toolsRequest(ep, empty))
				if raw, ok := preview["tools"]; ok && nonEmptyJSONArray(raw) {
					t.Errorf("tools:%q must not produce a capability signal, got %s", empty, raw)
				}
			})
		}
	}
}

// A request with no tools at all must preview exactly as before.
func TestPreviewAddsNoSignalWhenTheFieldIsAbsent(t *testing.T) {
	for _, ep := range surfacesWithheldingTools(t) {
		t.Run(string(ep.Profile), func(t *testing.T) {
			preview := previewOn(t, ep, toolsRequest(ep, ""))
			if _, ok := preview["tools"]; ok {
				t.Error("a request that sends no tools must not preview as if it did")
			}
			for _, payload := range wire.DefaultSealedFieldsFor(ep.Profile) {
				if _, leaked := preview[payload]; leaked && payload != "tools" {
					t.Errorf("payload field %q leaked to preview", payload)
				}
			}
		})
	}
}

// The reverse invariant. On a surface that does NOT withhold the field, the
// preview forwards the caller's own value and the signal must not touch it —
// replacing a real value with a placeholder is the opposite of the intent, and
// it would silently change what the router ranks on.
func TestUnwithheldFieldKeepsTheCallersValue(t *testing.T) {
	r := New("http://unused")
	for _, ep := range endpoint.All {
		if _, withheld := r.withheldFor(ep)["tools"]; withheld {
			continue
		}
		t.Run(string(ep.Profile), func(t *testing.T) {
			preview := previewOn(t, ep, toolsRequest(ep, secretToolSchema))
			raw, ok := preview["tools"]
			if !ok {
				t.Fatal("a field this surface does not withhold must reach the preview")
			}
			if !strings.Contains(string(raw), "transfer_funds") {
				t.Errorf("the caller's own value was replaced by a placeholder: %s", raw)
			}
		})
	}
}

// Every signal must be for a field that is actually WITHHELD on some surface.
// A signal for a field the preview forwards anyway would overwrite the caller's
// real value — the case TestUnwithheldFieldKeepsTheCallersValue guards from the
// other side.
func TestEverySignalIsForAWithheldField(t *testing.T) {
	r := New("http://unused")
	for field := range previewCapabilitySignals {
		withheldSomewhere := false
		for _, ep := range endpoint.All {
			if _, ok := r.withheldFor(ep)[field]; ok {
				withheldSomewhere = true
				break
			}
		}
		if !withheldSomewhere {
			t.Errorf("%q has a capability signal but is withheld on no surface: "+
				"the preview forwards the caller's own value, and the signal would replace it", field)
		}
	}
}

// A profile with no placeholder sends no signal — safe, but it reinstates the
// bug for that surface, silently. This is where that gap is meant to be caught.
func TestEveryWithheldSurfaceHasAPlaceholder(t *testing.T) {
	r := New("http://unused")
	for field, sig := range previewCapabilitySignals {
		for _, ep := range endpoint.All {
			if _, withheld := r.withheldFor(ep)[field]; !withheld {
				continue
			}
			if _, ok := sig.placeholder[ep.Profile]; !ok {
				t.Errorf("%s withholds %q but has no placeholder: the router sees the field as absent "+
					"on that surface, which is the bug this table exists to fix", ep.Profile, field)
			}
		}
	}
}

// Every placeholder must satisfy its own detection and carry nothing derived
// from a request.
func TestSignalPlaceholdersAreSelfContained(t *testing.T) {
	for field, sig := range previewCapabilitySignals {
		for profile, placeholder := range sig.placeholder {
			if !sig.detected(placeholder) {
				t.Errorf("%s/%q placeholder %s does not satisfy its own detected(): "+
					"the router would read it as absent", profile, field, placeholder)
			}
			if !json.Valid(placeholder) {
				t.Errorf("%s/%q placeholder is not valid JSON: %s", profile, field, placeholder)
			}
		}
	}
}

// `tool_choice` joined the signal table in the same change that made it
// payload, and the two had to ship together: the moment it becomes payload the
// preview withholds it automatically, so without this the router's soft
// preference — and, under `require_parameters`, its HARD filter — would stop
// applying with nothing reporting it.
func TestPreviewSignalsToolChoiceWithoutTheSelectedTool(t *testing.T) {
	choices := map[wire.Profile]string{
		wire.ProfileChat:      `{"type":"function","function":{"name":"transfer_funds"}}`,
		wire.ProfileAnthropic: `{"type":"tool","name":"transfer_funds"}`,
	}
	r := New("http://unused")
	for _, ep := range endpoint.All {
		if _, withheld := r.withheldFor(ep)["tool_choice"]; !withheld {
			continue
		}
		t.Run(string(ep.Profile), func(t *testing.T) {
			req := toolsRequest(ep, secretToolSchema)
			req["tool_choice"] = json.RawMessage(choices[ep.Profile])
			preview := previewOn(t, ep, req)

			raw, ok := preview["tool_choice"]
			if !ok {
				t.Fatal("preview omits tool_choice: the router cannot tell the request sets it, " +
					"so require_parameters would stop enforcing it")
			}
			if !presentAndNotNull(raw) {
				t.Errorf("the signal must satisfy the router's detection, got %s", raw)
			}
			body, err := json.Marshal(preview)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(body), "transfer_funds") {
				t.Errorf("preview leaked the SELECTED tool's name: %s", body)
			}
		})
	}
}

// A request that sets no tool_choice must not preview as if it did.
func TestPreviewAddsNoToolChoiceSignalWhenAbsent(t *testing.T) {
	r := New("http://unused")
	for _, ep := range endpoint.All {
		if _, withheld := r.withheldFor(ep)["tool_choice"]; !withheld {
			continue
		}
		t.Run(string(ep.Profile), func(t *testing.T) {
			preview := previewOn(t, ep, toolsRequest(ep, secretToolSchema))
			if _, ok := preview["tool_choice"]; ok {
				t.Error("a request that sets no tool_choice must not preview as if it did")
			}
		})
	}
}
