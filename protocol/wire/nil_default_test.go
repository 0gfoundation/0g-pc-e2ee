package wire_test

import (
	"encoding/json"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// A nil sealed set resolves to the profile default NARROWED to what the request
// carries, and this is the property that makes the narrowing safe rather than
// lax: a payload field the request HAS must always end up sealed. Filtering may
// only ever drop a field that is absent, and an absent field cannot ride in the
// cleartext half.
//
// Asserted across every profile, from the profile's own default rather than a
// list written here, so a profile that gains a payload field is covered by
// existing.
func TestNilSealedSetNeverLeavesPayloadCleartext(t *testing.T) {
	_, encPub, ephPub := toolsKeys(t)

	// Each body carries every payload field its profile defines, so there is
	// something for the filter to get wrong.
	bodies := map[wire.Profile]string{
		wire.ProfileChat: `{"model":"m","messages":[{"role":"user","content":"hi"}],` +
			`"tools":[{"type":"function","function":{"name":"f"}}],` +
			`"tool_choice":{"type":"function","function":{"name":"f"}}}`,
		wire.ProfileAnthropic: `{"model":"m","max_tokens":16,"messages":[],"system":"s",` +
			`"tools":[{"name":"f","input_schema":{"type":"object"}}],` +
			`"tool_choice":{"type":"tool","name":"f"}}`,
		wire.ProfileSpeech: `{"model":"m","file_base64":"AA","filename":"board-meeting.m4a",` +
			`"language":"en","prompt":"hint","response_format":"json"}`,
		wire.ProfileImage: `{"model":"m","prompt":"a cat","response_format":"b64_json"}`,
	}

	for _, p := range wire.Profiles() {
		body, ok := bodies[p]
		if !ok {
			t.Errorf("profile %q has no body here: add one carrying its payload fields, "+
				"or this test silently stops covering it", p)
			continue
		}
		t.Run(string(p), func(t *testing.T) {
			var req wire.Request
			if err := json.Unmarshal([]byte(body), &req); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			env, err := wire.SealRequestFor(p, encPub, req, nil, testProvider, ephPub)
			if err != nil {
				t.Fatalf("a nil set must seal a request carrying every default field: %v", err)
			}
			for _, f := range wire.DefaultSealedFieldsFor(p) {
				if _, inReq := req[f]; !inReq {
					continue
				}
				if _, leaked := env[f]; leaked {
					t.Errorf("%q was in the request and reached the cleartext half: "+
						"the filter dropped a field that is PRESENT", f)
				}
			}
		})
	}
}

// The narrowing must not rescue a request that has no payload at all. It cannot
// — the filtered set cannot contain what the request does not have — and this
// pins that the failure is still closed rather than an empty seal going out.
func TestNilSealedSetFailsClosedWithNoPayload(t *testing.T) {
	_, encPub, ephPub := toolsKeys(t)
	for _, p := range wire.Profiles() {
		t.Run(string(p), func(t *testing.T) {
			req := wire.Request{
				"model":       json.RawMessage(`"m"`),
				"temperature": json.RawMessage(`0.5`),
			}
			if _, err := wire.SealRequestFor(p, encPub, req, nil, testProvider, ephPub); err == nil {
				t.Error("a request carrying no payload field must not seal under a nil set")
			}
		})
	}
}

// An explicit set is NOT narrowed: it is the caller stating exactly what to
// seal, and shrinking it silently would hide a mistake rather than serve one.
func TestExplicitSealedSetIsNotNarrowed(t *testing.T) {
	_, encPub, ephPub := toolsKeys(t)
	req := mustReq(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)

	_, err := wire.SealRequestFor(wire.ProfileChat, encPub, req,
		[]string{"messages", "tools"}, testProvider, ephPub)
	if err == nil {
		t.Fatal("an explicit set naming a field the request lacks must still fail")
	}
}

// The narrowing makes STARTUP validation the worst case, and that is worth
// pinning rather than leaving as an accident.
//
// ValidateUnboundFieldsFor judges the set it is GIVEN. A caller validating its
// configuration up front passes the raw profile default, so an unbound entry
// that names an optional payload field is refused: it would be both sealed and
// unbound. At seal time with nil, the same entry is fine for a request that does
// not carry the field — the narrowing removed it from the sealed set, so there
// is no overlap left to conflict.
//
// The two verdicts therefore differ, and the direction is the safe one: startup
// flags a configuration that WILL fail on every request that carries the field,
// instead of letting it through to surprise the caller later. What it is not is
// the failure TestValidateUnboundFieldsForMatchesWhatSealEnforces guards
// against, which is startup being more LENIENT than the seal.
//
// Asserted per profile so a new optional payload field is covered by existing.
func TestNilNarrowingMakesStartupValidationTheWorstCase(t *testing.T) {
	_, encPub, ephPub := toolsKeys(t)

	// One optional payload field per profile, and a request that does NOT carry
	// it — the case where the two verdicts come apart.
	cases := map[wire.Profile]struct {
		optional string
		body     string
	}{
		wire.ProfileChat: {"tool_choice",
			`{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"a":1}]}`},
		wire.ProfileAnthropic: {"system",
			`{"model":"m","max_tokens":16,"messages":[]}`},
		wire.ProfileSpeech: {"prompt",
			`{"model":"m","file_base64":"AA","response_format":"json"}`},
	}
	for p, tc := range cases {
		t.Run(string(p), func(t *testing.T) {
			unbound := []string{tc.optional}

			// Startup, on the raw default: refused, because the field is in both sets.
			if err := wire.ValidateUnboundFieldsFor(p, unbound, wire.DefaultSealedFieldsFor(p)); err == nil {
				t.Errorf("startup validation must refuse unbinding %q, which the default seals", tc.optional)
			}

			// Per request with nil, on a request lacking the field: accepted, because
			// the narrowing already removed it from the sealed set.
			var req wire.Request
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			if _, present := req[tc.optional]; present {
				t.Fatalf("premise broken: the body must NOT carry %q", tc.optional)
			}
			if _, err := wire.SealRequestFor(p, encPub, req, nil, testProvider, ephPub, unbound...); err != nil {
				t.Errorf("a request that does not carry %q has no conflict to report: %v", tc.optional, err)
			}

			// And the configuration startup warned about does fail, on a request
			// that DOES carry the field — which is what makes the strictness right.
			req[tc.optional] = json.RawMessage(`"x"`)
			if _, err := wire.SealRequestFor(p, encPub, req, nil, testProvider, ephPub, unbound...); err == nil {
				t.Errorf("a request carrying %q must hit the conflict startup predicted", tc.optional)
			}
		})
	}
}
