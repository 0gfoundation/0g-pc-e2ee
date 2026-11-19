package openaiproxy

import (
	"encoding/json"
	"net/http"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// filePartTypes are the inline file content parts the router reads into text
// for an endpoint that does not declare "file" (router pkg/inference
// file_parts.go): OpenAI chat, Responses, Anthropic.
var filePartTypes = map[string]bool{"file": true, "input_file": true, "document": true}

// HasFilePart reports whether a request attaches a file (a PDF, say) as a
// content part, found where the router's DetectFileParts finds one. Sealed,
// such a part reaches the upstream as sent, since the router cannot read it to
// turn it into text, and no sealed model reads files itself: 0gm answers it
// with a 400 from vLLM ("25 validation errors … 'role' must be one of …").
//
// Unlike the gateway's media scan this does not recurse: it decides whether the
// request may be sealed at all, so it must not see more than the router does.
// A document nested inside another block (the page a server tool fetched, e.g.
// web_fetch_tool_result in a Claude Code history) is tool output the router
// forwards as sent, and counting it would cost the rest of the conversation
// its sealing.
func HasFilePart(req wire.Request) bool {
	for _, key := range []string{"messages", "input"} {
		var items []map[string]json.RawMessage
		if json.Unmarshal(req[key], &items) != nil {
			continue
		}
		for _, item := range items {
			if filePartIn(item["content"], true) {
				return true
			}
			var typ string
			_ = json.Unmarshal(item["type"], &typ)
			if (typ == "function_call_output" || typ == "custom_tool_call_output") && filePartIn(item["output"], false) {
				return true
			}
		}
	}
	return false
}

// filePartIn reports whether a part list holds a file part, or, in a message's
// own list, an Anthropic tool_result whose part list does (a tool_result cannot
// hold another). Other blocks are not looked into.
func filePartIn(raw json.RawMessage, inMessage bool) bool {
	var parts []map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) != nil {
		return false
	}
	for _, part := range parts {
		var typ string
		_ = json.Unmarshal(part["type"], &typ)
		if filePartTypes[typ] {
			return true
		}
		if typ == "tool_result" && inMessage && filePartIn(part["content"], false) {
			return true
		}
	}
	return false
}

// ErrCodeSealedFilePart is error.code on the 400 a sealed request carrying a
// file part gets (refuseFilePart), for a client to tell it apart.
const ErrCodeSealedFilePart = "sealed_request_file_part"

// refuseFilePart answers a request that would be sealed but carries a file
// part, before anything is resolved, sealed or sent. Otherwise it would reach
// the provider as sent and come back as vLLM's own validation error, which
// names none of this. Refused, not sent in the clear: the caller named a model
// this gateway seals, and only the caller's own header may give that up — it
// already did, before this point, when it says off.
//
// The hints name only what this proxy can do: without a cleartext path (the
// sidecar) neither the off header nor another model would change anything.
func (o options) refuseFilePart(w http.ResponseWriter) {
	msg := "This model is served end-to-end encrypted, and an encrypted request cannot carry a file " +
		"(a PDF or other document): files are read into text outside the enclave. Remove the file or paste its text"
	if o.cleartext != nil {
		msg += `, use model "0g/auto", or send the header ` + HeaderEncryptedTransit +
			": off to send this request unencrypted"
	}
	writeErrorObject(w, http.StatusBadRequest, map[string]any{
		"error": map[string]any{"message": msg + ".", "type": "gateway_error", "code": ErrCodeSealedFilePart},
		"_0g":   map[string]any{"source": "gateway"},
	})
}
