package wire

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// Phase 2: unbound_fields (SPEC §5.2 / D3–D5). An unbound cleartext field is
// excluded from the AAD, so an intermediary may add/modify it without breaking
// Open; the list itself is bound, so it cannot be enlarged in transit.

func mustEph(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	priv, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// A request unbound field may be mutated in transit and Open still succeeds,
// returning the mutated value.
func TestRequestUnboundFieldMutableInTransit(t *testing.T) {
	priv, pub := mustEph(t)
	_, ephPub := mustEph(t)

	req := Request{
		"model":      json.RawMessage(`"m"`),
		"messages":   json.RawMessage(`[{"role":"user","content":"secret"}]`),
		"x_0g_trace": json.RawMessage(`{"cost":1}`),
	}
	env, err := SealRequest(pub, req, []string{"messages"}, guardProviderID, []byte(ephPub), "x_0g_trace")
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}

	// Router rewrites the unbound field.
	env["x_0g_trace"] = json.RawMessage(`{"cost":999}`)

	out, err := OpenRequest(priv, env)
	if err != nil {
		t.Fatalf("OpenRequest after mutating an unbound field: %v", err)
	}
	if !bytes.Contains([]byte(out["x_0g_trace"]), []byte("999")) {
		t.Fatalf("expected mutated unbound value, got %s", out["x_0g_trace"])
	}
}

// A BOUND field is still tamper-evident even when an unbound set is declared.
func TestRequestBoundFieldStillProtectedWithUnbound(t *testing.T) {
	priv, pub := mustEph(t)
	_, ephPub := mustEph(t)

	req := Request{
		"model":      json.RawMessage(`"m"`),
		"messages":   json.RawMessage(`[{"role":"user","content":"secret"}]`),
		"x_0g_trace": json.RawMessage(`{"cost":1}`),
	}
	env, err := SealRequest(pub, req, []string{"messages"}, guardProviderID, []byte(ephPub), "x_0g_trace")
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}
	env["model"] = json.RawMessage(`"downgraded"`) // model is bound
	if _, err := OpenRequest(priv, env); err == nil {
		t.Fatal("expected Open to fail when a bound field is tampered, got nil")
	}
}

// Enlarging unbound_fields in transit (to free a bound field) is defeated: the
// list is itself bound, so changing it breaks the AAD.
func TestRequestEnlargingUnboundListFailsClosed(t *testing.T) {
	priv, pub := mustEph(t)
	_, ephPub := mustEph(t)

	req := Request{
		"model":      json.RawMessage(`"m"`),
		"messages":   json.RawMessage(`[{"role":"user","content":"secret"}]`),
		"x_0g_trace": json.RawMessage(`{"cost":1}`),
	}
	env, err := SealRequest(pub, req, []string{"messages"}, guardProviderID, []byte(ephPub), "x_0g_trace")
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}

	// Attacker adds "model" to unbound_fields AND downgrades model.
	e2ee, err := env.E2EE()
	if err != nil {
		t.Fatal(err)
	}
	e2ee.UnboundFields = []string{"x_0g_trace", "model"}
	if err := env.setE2EE(e2ee); err != nil {
		t.Fatal(err)
	}
	env["model"] = json.RawMessage(`"downgraded"`)

	if _, err := OpenRequest(priv, env); err == nil {
		t.Fatal("expected Open to fail when unbound_fields is enlarged, got nil")
	}
}

// H1: a non-array unbound_fields fails closed before unsealing.
func TestMalformedUnboundFieldsFailsClosed(t *testing.T) {
	priv, pub := mustEph(t)
	_, ephPub := mustEph(t)

	req := Request{
		"model":    json.RawMessage(`"m"`),
		"messages": json.RawMessage(`[{"role":"user","content":"secret"}]`),
	}
	env, err := SealRequest(pub, req, []string{"messages"}, guardProviderID, []byte(ephPub))
	if err != nil {
		t.Fatalf("SealRequest: %v", err)
	}

	// Splice a string where an array is required.
	var e2ee map[string]json.RawMessage
	if err := json.Unmarshal(env[e2eeKey], &e2ee); err != nil {
		t.Fatal(err)
	}
	e2ee["unbound_fields"] = json.RawMessage(`"model"`)
	raw, err := json.Marshal(e2ee)
	if err != nil {
		t.Fatal(err)
	}
	env[e2eeKey] = raw

	if _, err := OpenRequest(priv, env); err == nil {
		t.Fatal("expected Open to reject a non-array unbound_fields, got nil")
	}
}

// A response unbound field can be injected in transit (absent at seal time) and
// OpenResponse still succeeds, returning the injected value.
func TestResponseUnboundFieldInjectableInTransit(t *testing.T) {
	ephPriv, ephPub := mustEph(t)

	resp := Response{
		"model":   json.RawMessage(`"m"`),
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"a"}}]`),
	}
	sealed, err := SealResponse(ephPub, resp, nil, "x_0g_trace")
	if err != nil {
		t.Fatalf("SealResponse: %v", err)
	}
	if _, present := sealed["x_0g_trace"]; present {
		t.Fatal("x_0g_trace should not exist at seal time")
	}

	// Router injects the trace after the enclave sealed the response.
	sealed["x_0g_trace"] = json.RawMessage(`{"total_cost":337}`)

	out, err := OpenResponse(ephPriv, sealed)
	if err != nil {
		t.Fatalf("OpenResponse after injecting an unbound field: %v", err)
	}
	if !bytes.Contains([]byte(out["x_0g_trace"]), []byte("337")) {
		t.Fatalf("expected injected unbound value, got %s", out["x_0g_trace"])
	}
}

func TestValidateUnboundFields(t *testing.T) {
	sealed := []string{"messages", "tools"}
	bad := map[string][]string{
		"overlaps sealed": {"messages"},
		"reserved _e2ee":  {e2eeKey},
		"empty name":      {""},
		"duplicate":       {"a", "a"},
	}
	for name, unbound := range bad {
		if err := ValidateUnboundFields(unbound, sealed); err == nil {
			t.Errorf("%s: expected ValidateUnboundFields to reject %v, got nil", name, unbound)
		}
	}
	// Empty and a well-formed disjoint set are accepted; presence is NOT required.
	if err := ValidateUnboundFields(nil, sealed); err != nil {
		t.Errorf("empty unbound set should be valid: %v", err)
	}
	if err := ValidateUnboundFields([]string{"x_0g_trace", "not_present_yet"}, sealed); err != nil {
		t.Errorf("disjoint unbound set should be valid: %v", err)
	}
}
