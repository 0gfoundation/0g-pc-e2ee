package openaiproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
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

// WithSealedFilePartRefusal makes Register refuse a sealed request carrying a
// file part before anything is resolved (refuseFilePart), rather than seal it
// and send it as is.
//
// Opt-in, because it rests on a fact about the deployment, not the code: that
// no model this proxy seals reads files (THE PRECONDITION, at refuseFilePart).
// The gateway seals the models in its seal list, and TestSealedModelsReadNoFiles
// (cmd/gateway) pins every deployed list to models checked for that; it passes
// this. The sidecar seals EVERY model, about which nothing is known, so it does
// not: a model there whose endpoint declares "file" gets the file part sealed
// and forwarded, as before.
func WithSealedFilePartRefusal() Option {
	return func(o *options) { o.refuseFileParts = true }
}

// WithAutoRouting tells Register that its caller routes a model named
// "0g/auto" itself (the gateway, when it seals some models and not others), so
// a refusal may suggest it. Without it the name would reach this handler and be
// refused the same way, and the suggestion would send the caller in a circle.
func WithAutoRouting() Option {
	return func(o *options) { o.autoRouting = true }
}

type autoRoutedKey struct{}

// MarkAutoRouted marks r as having come through "0g/auto": the model it names
// is the one that routing chose, so a refusal must not suggest "0g/auto".
func MarkAutoRouted(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), autoRoutedKey{}, true))
}

func autoRouted(r *http.Request) bool {
	v, _ := r.Context().Value(autoRoutedKey{}).(bool)
	return v
}

// refuseFilePart answers a request that would be sealed but carries a file
// part, before anything is resolved, sealed or sent. Otherwise it would reach
// the provider as sent and come back as vLLM's own validation error, which
// names none of this. Refused, not sent in the clear: the caller named a model
// this gateway seals, and only the caller's own header may give that up — it
// already did, before this point, when it says off.
//
// THE PRECONDITION. This refuses by the request alone, before the route is
// resolved, so it cannot see the provider. That is right only while no sealed
// model reads files: the router hands a file part through untouched to an
// endpoint whose input modalities declare "file" (router pkg/inference
// file_parts.go), and such a provider could serve this request sealed. Today
// none the gateway seals does — TestSealedModelsReadNoFiles (cmd/gateway) keeps
// the deployed seal lists to models checked for that — and only the gateway
// turns this on (WithSealedFilePartRefusal). When a model is sealed that reads
// files, this check moves after the resolve and asks the candidate's declared
// modalities instead, and the refusal applies only when none of them declares
// "file".
//
// Not for preferred (Register skips it): such a request goes out in the clear
// when no provider of its model can be sealed to (transitFallback), and the
// router then reads the file into text, which works. Refusing it up front
// would turn that into a 400.
//
// The message offers only what can work for this caller:
//   - "0g/auto", where the caller of Register routes it (WithAutoRouting) and
//     this request did not already come that way (MarkAutoRouted);
//   - the off header, where there is a cleartext path and the caller did not
//     itself just ask for required (preferred never gets here). It may still
//     be refused, with 403 encrypted_transit_mismatch, if the account or API
//     key requires encryption, which this proxy cannot see before the
//     preview; it says so.
func (o options) refuseFilePart(w http.ResponseWriter, r *http.Request) {
	ways := []string{"remove the file or paste its text"}
	if o.autoRouting && !autoRouted(r) {
		ways = append(ways, `use model "0g/auto"`)
	}
	if o.cleartext != nil && callerTransit(r) != core.TransitRequired {
		ways = append(ways, "send the header "+HeaderEncryptedTransit+
			": off to send this request unencrypted (unless your account or API key requires encryption)")
	}
	todo := ways[0]
	if n := len(ways); n > 1 {
		todo = strings.Join(ways[:n-1], ", ") + ", or " + ways[n-1]
	}
	msg := "This model is served end-to-end encrypted, and an encrypted request cannot carry a file " +
		"(a PDF or other document): files are read into text outside the enclave. " +
		strings.ToUpper(todo[:1]) + todo[1:] + "."
	writeErrorObject(w, http.StatusBadRequest, map[string]any{
		"error": map[string]any{"message": msg, "type": "gateway_error", "code": ErrCodeSealedFilePart},
		"_0g":   map[string]any{"source": "gateway"},
	})
}
