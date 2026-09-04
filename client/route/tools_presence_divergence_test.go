package route

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Two rules in this repository read the SAME field and answer OPPOSITELY, on
// purpose, and nothing else pins that:
//
//   - route.nonEmptyJSONArray asks "does this request USE tools?", for capability
//     routing. `[]` is NO — it parses rather than comparing bytes precisely so
//     that a pretty-printed `[ ]` answers no too, and signalling on it was called
//     out as a bug when this was fixed.
//   - wire's payload rule asks "is a payload field sitting in the cleartext?",
//     for leak prevention. `[]` is YES: presence is literal, so the field must be
//     sealed whatever its value.
//
// Both are right for their own question, and the divergence is what a later
// "let's make these consistent" would quietly remove — in either direction, and
// either direction is a real regression. Unifying on the routing rule lets a
// sender keep `tools` cleartext by emptying it, which is a value-shaped
// exemption to a leak check. Unifying on the payload rule reinstates the
// hard-filter false positive for requests that use no tools.
//
// So this test asserts the disagreement itself. It is the only thing standing
// between the two rules and a well-meaning refactor.
func TestEmptyToolsMeansNoToolsToRoutingAndPresentToSealing(t *testing.T) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc keygen: %v", err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("eph keygen: %v", err)
	}
	signer := "0x" + strings.Repeat("1", 40)

	// Every spelling of "an empty tools array", including the pretty-printed
	// ones that a byte comparison misses.
	for _, empty := range []string{`[]`, `[ ]`, "[\n]", "[\n   \n]"} {
		t.Run(strings.NewReplacer("\n", "\\n", " ", "_").Replace(empty), func(t *testing.T) {
			raw := json.RawMessage(empty)

			// Routing side: not tools, so no capability signal and no hard filter.
			if nonEmptyJSONArray(raw) {
				t.Errorf("routing must read %s as NO tools: signalling here hard-filters "+
					"for function calling on a request that uses none", empty)
			}

			// Sealing side: present, so it must be sealed. The same value, the
			// opposite answer.
			req := wire.Request{
				"model":    json.RawMessage(`"m"`),
				"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
				"tools":    raw,
			}
			_, err := wire.SealRequestFor(wire.ProfileChat, encPub, req,
				[]string{"messages"}, signer, ephPub)
			if err == nil {
				t.Errorf("sealing must read %s as PRESENT and refuse to leave it cleartext: "+
					"a value-shaped exemption is what a sender would aim at", empty)
			} else if !strings.Contains(err.Error(), "tools") {
				t.Errorf("refusal should name the field, got %v", err)
			}

			// And the same on the receiving half, which is the load-bearing one.
			sealed, err := wire.SealRequestFor(wire.ProfileChat, encPub, req,
				[]string{"messages", "tools"}, signer, ephPub)
			if err != nil {
				t.Fatalf("sealing it is always allowed: %v", err)
			}
			if _, err := wire.OpenRequestFor(wire.ProfileChat, encPriv, sealed); err != nil {
				t.Errorf("a sealed empty array must open: %v", err)
			}
		})
	}
}
