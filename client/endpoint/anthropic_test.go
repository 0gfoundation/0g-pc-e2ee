package endpoint

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func mustRequest(t *testing.T, body string) wire.Request {
	t.Helper()
	var req wire.Request
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("bad test body: %v", err)
	}
	return req
}

func render(t *testing.T, req wire.Request) string {
	t.Helper()
	out, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Anthropic.PreSeal folds Claude Code's `tool_addition` blocks into `tools`
// before sealing. Same cases as the router's foldToolAdditions (0g-router
// #1146), which cannot see `messages` on a sealed request.
func TestAnthropicPreSealFoldsToolAdditions(t *testing.T) {
	req := mustRequest(t, `{"model":"0GM-1.0-35B-A3B","max_tokens":20,
		"tools":[{"name":"Bash","input_schema":{"type":"object"}}],
		"messages":[
			{"role":"user","content":[
				{"type":"text","text":"say hi"},
				{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"Foo","description":"foo","input_schema":{"type":"object","properties":{}}}}},
				{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"Bash","input_schema":{"type":"object"}}}}]},
			{"role":"assistant","content":"hi"},
			{"role":"user","content":[{"type":"text","text":"go"},{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"Foo","input_schema":{"type":"object"}}}}]}]}`)
	before := render(t, req)

	out, err := Anthropic.PreSeal(req)
	if err != nil {
		t.Fatal(err)
	}
	if render(t, req) != before {
		t.Error("PreSeal mutated its input; the same body is re-sealed to each fallback candidate")
	}

	var got struct {
		Model    string
		Tools    []struct{ Name, Description string }
		Messages []struct {
			Role    string
			Content json.RawMessage
		}
	}
	if err := json.Unmarshal([]byte(render(t, out)), &got); err != nil {
		t.Fatal(err)
	}
	if got.Model != "0GM-1.0-35B-A3B" {
		t.Errorf("model = %q", got.Model)
	}
	if len(got.Tools) != 2 || got.Tools[0].Name != "Bash" || got.Tools[1].Name != "Foo" || got.Tools[1].Description != "foo" {
		t.Errorf("tools = %+v, want Bash then the first Foo definition", got.Tools)
	}
	for i, want := range []string{`[{"type":"text","text":"say hi"}]`, `"hi"`, `[{"type":"text","text":"go"}]`} {
		if string(got.Messages[i].Content) != want {
			t.Errorf("messages[%d].content = %s, want %s", i, got.Messages[i].Content, want)
		}
	}
}

func TestAnthropicPreSealCreatesTools(t *testing.T) {
	for name, body := range map[string]string{
		"absent": `{"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"Foo","input_schema":{"type":"object"}}}}]}]}`,
		"null":   `{"tools":null,"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"Foo","input_schema":{"type":"object"}}}}]}]}`,
	} {
		out, err := Anthropic.PreSeal(mustRequest(t, body))
		if err != nil {
			t.Fatal(err)
		}
		if got := string(out["tools"]); got != `[{"name":"Foo","input_schema":{"type":"object"}}]` {
			t.Errorf("%s: tools = %s", name, got)
		}
	}
}

// Claude Code sends these blocks in role "system" messages, with cache_control
// on the last block.
func TestAnthropicPreSealSystemRoleMessage(t *testing.T) {
	out, err := Anthropic.PreSeal(mustRequest(t, `{"model":"m","messages":[{"role":"user","content":"hi"},{"role":"system","content":[{"type":"text","text":"New tools."},{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"Foo","input_schema":{}}},"cache_control":{"type":"ephemeral"}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"messages":[{"content":"hi","role":"user"},{"content":[{"type":"text","text":"New tools."}],"role":"system"}],"model":"m","tools":[{"name":"Foo","input_schema":{}}]}`
	if got := render(t, out); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestAnthropicPreSealLeavesOtherRequestsUnchanged(t *testing.T) {
	for name, body := range map[string]string{
		"mentioned in string content": `{"messages":[{"role":"user","content":"mentions \"tool_addition\" in text"}]}`,
		"mentioned in a text block":   `{"messages":[{"role":"user","content":[{"type":"text","text":"\"tool_addition\""}]}]}`,
		"messages not an array":       `{"messages":"tool_addition"}`,
		"tools not an array":          `{"tools":{"name":"q"},"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"A","input_schema":{}}}}]}]}`,
		// Folding would leave content empty, which Anthropic rejects.
		"blocks-only message": `{"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"A","input_schema":{}}}}]},{"role":"user","content":[{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"Foo","input_schema":{}}}}]}]}`,
		"tool_reference":      `{"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"tool_addition","tool":{"type":"tool_reference","name":"Foo"}}]}]}`,
		// Remove-then-re-add: folding would drop the re-add as a duplicate.
		"tool_removal": `{"tools":[{"name":"q","input_schema":{}}],"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"tool_removal","tool":{"type":"tool_reference","name":"q"}},{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"q","input_schema":{"b":1}}}}]}]}`,
		"nameless":     `{"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"tool_addition","tool":{"definition":{"description":"x"}}}]}]}`,
	} {
		req := mustRequest(t, body)
		before := render(t, req)
		out, err := Anthropic.PreSeal(req)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := render(t, out); got != before {
			t.Errorf("%s: request changed to %s", name, got)
		}
	}
}

// The fold moves a tool definition from `messages` to `tools`. That must not
// move it out of the envelope: `tools` is sealed payload on ProfileAnthropic,
// and the client seals every payload field that is present.
func TestAnthropicPreSealKeepsFoldedToolsSealed(t *testing.T) {
	const secret = "transfer_funds_secret_tool"
	out, err := Anthropic.PreSeal(mustRequest(t, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"tool_addition","tool":{"type":"tool_definition","definition":{"name":"`+secret+`","input_schema":{}}}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}

	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	_, ephPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, f := range wire.DefaultSealedFieldsFor(Anthropic.Profile) {
		if _, ok := out[f]; ok {
			fields = append(fields, f)
		}
	}
	env, err := wire.SealRequestFor(Anthropic.Profile, encPub, out, fields,
		"0x0000000000000000000000000000000000000001", ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Contains(render(t, env), secret) {
		t.Fatal("the folded tool definition is readable in the sealed envelope")
	}
	opened, err := wire.OpenRequestFor(Anthropic.Profile, encPriv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !strings.Contains(string(opened["tools"]), secret) {
		t.Errorf("opened tools = %s, want the folded definition", opened["tools"])
	}
}
