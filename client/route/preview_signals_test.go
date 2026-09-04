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

func previewFor(t *testing.T, req wire.Request) map[string]json.RawMessage {
	t.Helper()
	broker := newMockBroker(t)
	router := newMockRouter(t, broker)
	if _, err := New(router.srv.URL).Resolve(context.Background(), endpoint.Chat, req); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return router.lastPreview
}

// The bug this fixes: `tools` is withheld, so before the signal the preview said
// "no tools" on every sealed request and the router's function-calling hard
// filter stopped applying — silently, since a ranking still comes back.
func TestPreviewSignalsToolsWithoutTheSchemas(t *testing.T) {
	preview := previewFor(t, wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
		"tools":    json.RawMessage(secretToolSchema),
	})

	raw, ok := preview["tools"]
	if !ok {
		t.Fatal("preview omits tools entirely: the router cannot tell this request needs function calling")
	}
	// The router's own rule (capabilities.go: len > 0 && != null && != []).
	if s := strings.TrimSpace(string(raw)); s == "" || s == "null" || s == "[]" {
		t.Errorf("the signal must satisfy the router's detection, got %s", raw)
	}

	// And the point of withholding it in the first place.
	body, err := json.Marshal(preview)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{"transfer_funds", "iban", "Move money"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("preview leaked %q from the tool schemas: %s", leak, body)
		}
	}
}

// The signal mirrors the router's rule rather than "the field is present", and
// this is the case that distinction exists for: `tools: []` means NO tools
// there, so signalling on it would hard-filter for function calling on a request
// that does not use it — a 400 under require_parameters for a request that
// works today.
func TestPreviewDoesNotSignalToolsForAnEmptyArray(t *testing.T) {
	for _, empty := range []string{`[]`, `null`} {
		t.Run(empty, func(t *testing.T) {
			preview := previewFor(t, wire.Request{
				"model":    json.RawMessage(`"gpt-4o"`),
				"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
				"tools":    json.RawMessage(empty),
			})
			if raw, ok := preview["tools"]; ok {
				if s := strings.TrimSpace(string(raw)); s != "" && s != "null" && s != "[]" {
					t.Errorf("tools:%s must not produce a capability signal, got %s", empty, raw)
				}
			}
		})
	}
}

// A request with no tools at all must preview exactly as before.
func TestPreviewAddsNoSignalWhenTheFieldIsAbsent(t *testing.T) {
	preview := previewFor(t, wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	})
	if _, ok := preview["tools"]; ok {
		t.Error("a request that sends no tools must not preview as if it did")
	}
	if _, leaked := preview["messages"]; leaked {
		t.Error("messages leaked to preview")
	}
}

// Every signal must be for a field that is actually WITHHELD on some surface.
// A signal for a field the preview forwards anyway would overwrite the caller's
// real value with a placeholder — the opposite of the intent.
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

// The placeholder must not itself trip a leak: it has to satisfy the router's
// detection while containing nothing derived from a request.
func TestSignalPlaceholdersAreSelfContained(t *testing.T) {
	for field, sig := range previewCapabilitySignals {
		if !sig.detected(sig.placeholder) {
			t.Errorf("%q placeholder %s does not satisfy its own detected(): the router would read it as absent",
				field, sig.placeholder)
		}
		if !json.Valid(sig.placeholder) {
			t.Errorf("%q placeholder is not valid JSON: %s", field, sig.placeholder)
		}
	}
}
