package openaiproxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func TestHasFilePart(t *testing.T) {
	for body, want := range map[string]bool{
		`{}`: false,
		`{"messages":[{"role":"user","content":"read file a.pdf"}]}`:                                                                                           false,
		`{"messages":[{"role":"user","content":[{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,AA=="}}]}]}`:                true,
		`{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"AA=="}}]}]}`:               true,
		`{"messages":[{"role":"user","content":[{"type":"input_file","filename":"a.pdf"}]}]}`:                                                                  true,
		`{"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"document","source":{}}]}]}]}`:                                        true,
		`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="}}]}]}`:                                     false,
		`{"input":[{"type":"function_call_output","output":[{"type":"input_file","file_data":"data:application/pdf;base64,AA=="}]}]}`:                          true,
		`{"input":["a string, as an embedding input"]}`:                                                                                                        false,
		`{"messages":[{"role":"assistant","content":[{"type":"web_fetch_tool_result","content":{"type":"web_fetch_result","content":{"type":"document"}}}]}]}`: false,
	} {
		var req wire.Request
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if got := HasFilePart(req); got != want {
			t.Errorf("HasFilePart(%s) = %v, want %v", body, got, want)
		}
	}
}

const (
	pdfChat = `{"model":"0gm-1.0-35b-a3b","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"summarize"},` +
		`{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,AA=="}}]}]}`
	pdfChatStream = `{"model":"0gm-1.0-35b-a3b","stream":true,"messages":[{"role":"user","content":[` +
		`{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,AA=="}}]}]}`
	pdfAnthropic = `{"model":"0gm-1.0-35b-a3b","max_tokens":16,"messages":[{"role":"user","content":[` +
		`{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"AA=="}}]}]}`
)

// A sealed request carrying a file part gets a 400 naming the reason, before
// anything is resolved, sealed or sent.
func TestRegister_RefusesSealedFilePart(t *testing.T) {
	for _, tc := range []struct {
		ep   endpoint.Endpoint
		body string
	}{{endpoint.Chat, pdfChat}, {endpoint.Chat, pdfChatStream}, {endpoint.Anthropic, pdfAnthropic}} {
		for _, callerHeader := range []string{"", core.TransitRequired, core.TransitPreferred} {
			res := &transitResolver{transit: core.TransitRequired}
			rec, ct := serveTransit(t, tc.ep, res, true, callerHeader, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s %q: status %d, want 400: %s", tc.ep.Path, callerHeader, rec.Code, rec.Body)
			}
			if res.resolved || res.previewed || ct.hit {
				t.Errorf("%s %q: resolved %v, previewed %v, cleartext %v; want nothing sent", tc.ep.Path, callerHeader, res.resolved, res.previewed, ct.hit)
			}
			var got struct {
				Error struct{ Message, Type, Code string }
				ZG    struct{ Source string } `json:"_0g"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("body is not JSON: %s", rec.Body)
			}
			if got.Error.Code != ErrCodeSealedFilePart || got.Error.Type != "gateway_error" || got.ZG.Source != "gateway" {
				t.Errorf("%s: error = %+v, _0g = %+v", tc.ep.Path, got.Error, got.ZG)
			}
			for _, want := range []string{"end-to-end encrypted", "cannot carry a file", `"0g/auto"`, HeaderEncryptedTransit + ": off"} {
				if !strings.Contains(got.Error.Message, want) {
					t.Errorf("%s: message %q lacks %q", tc.ep.Path, got.Error.Message, want)
				}
			}
		}
	}
}

// Without a cleartext path (the sidecar) the message offers only what helps there.
func TestRegister_SealedFilePartNoCleartextHints(t *testing.T) {
	res := &transitResolver{transit: core.TransitRequired}
	rec, _ := serveTransit(t, endpoint.Chat, res, false, "", pdfChat)
	if rec.Code != http.StatusBadRequest || res.resolved {
		t.Fatalf("status %d, resolved %v", rec.Code, res.resolved)
	}
	if body := rec.Body.String(); strings.Contains(body, "0g/auto") || strings.Contains(body, HeaderEncryptedTransit) {
		t.Errorf("sidecar message names gateway-only options: %s", body)
	}
}

// The caller's own off still forwards as sent: the file reaches the router,
// which reads it into text.
func TestRegister_FilePartCallerOffForwards(t *testing.T) {
	res := &transitResolver{transit: core.TransitRequired}
	_, ct := serveTransit(t, endpoint.Chat, res, true, core.TransitOff, pdfChat)
	if !ct.hit || ct.body != pdfChat || res.resolved {
		t.Errorf("cleartext %v body-intact %v resolved %v", ct.hit, ct.body == pdfChat, res.resolved)
	}
}

// A request without a file part is unaffected: it still reaches the resolver.
func TestRegister_NoFilePartStillSeals(t *testing.T) {
	res := &transitResolver{transit: core.TransitRequired}
	rec, _ := serveTransit(t, endpoint.Chat, res, true, "", transitChat)
	if !res.resolved {
		t.Errorf("a plain request was not resolved (status %d: %s)", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), ErrCodeSealedFilePart) {
		t.Errorf("a plain request got the file refusal: %s", rec.Body)
	}
}
