package endpoint

import (
	"bytes"
	"encoding/json"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

const (
	fieldMessages = "messages"
	fieldTools    = "tools"
)

// anthropicPreSeal folds Anthropic `tool_addition` content blocks
// ({"type":"tool_addition","tool":{"type":"tool_definition","definition":{...}}})
// into entries of the top-level `tools` array, and drops the blocks.
//
// Claude Code (2.1.310+) emits the block to add a tool mid-conversation, and the
// block stays in the history for the rest of the session. Upstreams that check
// content blocks against a fixed list of types reject it with a 400 (the 0GM
// sglang /v1/messages and the glm-5.3 Anthropic endpoint both do). Claude Code
// answers that 400 by stripping the blocks from every later request, which is
// not a request those upstreams handle either, so the session stays broken.
// Declaring the tool up front means the same thing and every upstream accepts it.
//
// The router already does this fold (0g-router #1146, foldToolAdditions), but on
// a sealed request it only sees ciphertext: `messages` is sealed payload. So the
// fold has to happen here, before sealing. Moving a definition out of `messages`
// into `tools` does not move it out of the envelope: `tools` is optional sealed
// payload on ProfileAnthropic, and a present `tools` is sealed.
//
// The rules match the router's so a request behaves the same on both paths. A
// definition whose name is already in `tools` is not added twice. The request is
// returned unchanged when there is no such block or it cannot be parsed, and
// also when folding cannot express it: a block with no named definition (Claude
// Code's {"type":"tool_reference"} form), any tool_removal block (the tool set
// would then depend on block order), or a message that would be left with no
// content (Anthropic rejects empty content but accepts tool_addition natively).
// Those still reach the upstream as sent; the upstream decides.
//
// It never returns an error: a request it cannot fold is still a request.
// It does not mutate req: the same body is re-sealed to each fallback candidate.
func anthropicPreSeal(req wire.Request) (wire.Request, error) {
	messages, tools, ok := foldToolAdditions(req[fieldMessages], req[fieldTools])
	if !ok {
		return req, nil
	}
	out := make(wire.Request, len(req)+1)
	for k, v := range req {
		out[k] = v
	}
	out[fieldMessages] = messages
	out[fieldTools] = tools
	return out, nil
}

// foldToolAdditions does the fold on the two fields it touches. ok is false
// when there is nothing to fold or the fold cannot express the request; the
// caller then keeps the request as it was.
func foldToolAdditions(rawMessages, rawTools json.RawMessage) (messagesOut, toolsOut json.RawMessage, ok bool) {
	if !bytes.Contains(rawMessages, []byte(`"tool_addition"`)) || bytes.Contains(rawMessages, []byte(`"tool_removal"`)) {
		return nil, nil, false
	}
	var messages []map[string]json.RawMessage
	if json.Unmarshal(rawMessages, &messages) != nil {
		return nil, nil, false
	}
	var tools []json.RawMessage
	// A JSON null is the absence of a value, the reading the other rows give it.
	if len(rawTools) > 0 && string(rawTools) != "null" && json.Unmarshal(rawTools, &tools) != nil {
		return nil, nil, false
	}
	names := map[string]bool{}
	for _, t := range tools {
		var named struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(t, &named)
		names[named.Name] = true
	}

	found := false
	for _, msg := range messages {
		var blocks []json.RawMessage
		if json.Unmarshal(msg["content"], &blocks) != nil { // string content
			continue
		}
		kept := blocks[:0:0]
		for _, b := range blocks {
			var block struct {
				Type string
				Tool struct{ Definition json.RawMessage }
			}
			if json.Unmarshal(b, &block) != nil || block.Type != "tool_addition" {
				kept = append(kept, b)
				continue
			}
			found = true
			var def struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(block.Tool.Definition, &def) != nil || def.Name == "" {
				return nil, nil, false
			}
			if !names[def.Name] {
				names[def.Name] = true
				tools = append(tools, block.Tool.Definition)
			}
		}
		if len(kept) == 0 && len(blocks) > 0 {
			return nil, nil, false
		}
		if len(kept) != len(blocks) {
			// msg is a map shared with nothing: it was decoded above, not taken
			// from the caller's request.
			msg["content"], _ = json.Marshal(kept)
		}
	}
	if !found {
		return nil, nil, false
	}
	messagesOut, err := json.Marshal(messages)
	if err != nil {
		return nil, nil, false
	}
	toolsOut, err = json.Marshal(tools)
	if err != nil {
		return nil, nil, false
	}
	return messagesOut, toolsOut, true
}
