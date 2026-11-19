package openaiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// serveFile sends body to ep's sealed handler, registered with opts, with the
// caller's X-0G-Encrypted-Transit set to callerHeader ("" = absent), marked as
// having come through "0g/auto" when autoRouted.
func serveFile(t *testing.T, ep endpoint.Endpoint, res *transitResolver, opts []Option, callerHeader, body string, autoRouted bool) (*httptest.ResponseRecorder, *cleartextRecorder) {
	t.Helper()
	ct := &cleartextRecorder{}
	all := append([]Option(nil), opts...)
	for i := range all {
		if all[i] == nil {
			all[i] = WithCleartext(ct)
		}
	}
	mux := http.NewServeMux()
	Register(mux, ep, core.NewWithResolver(res, core.WithEndpoint(ep)), all...)
	req := httptest.NewRequest(http.MethodPost, ep.Path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("Content-Type", "application/json")
	if callerHeader != "" {
		req.Header.Set(HeaderEncryptedTransit, callerHeader)
	}
	if autoRouted {
		req = MarkAutoRouted(req)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec, ct
}

// fileRefusal decodes a refusal, failing unless it is the file-part 400.
func fileRefusal(t *testing.T, what string, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%s: status %d, want 400: %s", what, rec.Code, rec.Body)
	}
	var got struct {
		Error struct{ Message, Type, Code string }
		ZG    struct{ Source string } `json:"_0g"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("%s: body is not JSON: %s", what, rec.Body)
	}
	if got.Error.Code != ErrCodeSealedFilePart || got.Error.Type != "gateway_error" || got.ZG.Source != "gateway" {
		t.Errorf("%s: error = %+v, _0g = %+v", what, got.Error, got.ZG)
	}
	for _, want := range []string{"end-to-end encrypted", "cannot carry a file", "Remove the file or paste its text"} {
		if !strings.Contains(got.Error.Message, want) {
			t.Errorf("%s: message %q lacks %q", what, got.Error.Message, want)
		}
	}
	return got.Error.Message
}

// cleartextOpt stands for WithCleartext(the recorder) in serveFile's opts.
var cleartextOpt Option

// A sealed request carrying a file part gets a 400 naming the reason, before
// anything is resolved, sealed or sent — whatever the surface and the header.
func TestRegister_RefusesSealedFilePart(t *testing.T) {
	for _, tc := range []struct {
		ep   endpoint.Endpoint
		body string
	}{{endpoint.Chat, pdfChat}, {endpoint.Chat, pdfChatStream}, {endpoint.Anthropic, pdfAnthropic}} {
		for _, callerHeader := range []string{"", core.TransitRequired, core.TransitPreferred} {
			what := tc.ep.Path + " " + callerHeader
			res := &transitResolver{transit: core.TransitRequired}
			rec, ct := serveFile(t, tc.ep, res, []Option{cleartextOpt, WithAutoRouting()}, callerHeader, tc.body, false)
			fileRefusal(t, what, rec)
			if res.resolved || res.previewed || ct.hit {
				t.Errorf("%s: resolved %v, previewed %v, cleartext %v; want nothing sent", what, res.resolved, res.previewed, ct.hit)
			}
		}
	}
}

// The message offers only what can work for this caller.
func TestRegister_SealedFilePartHints(t *testing.T) {
	const auto, off = `use model "0g/auto"`, HeaderEncryptedTransit + ": off"
	for _, tc := range []struct {
		name         string
		opts         []Option
		callerHeader string
		autoRouted   bool
		want, not    []string
	}{
		{"gateway, no header", []Option{cleartextOpt, WithAutoRouting()}, "", false,
			[]string{auto, off, "unless your account or API key requires encryption"}, nil},
		{"gateway, preferred", []Option{cleartextOpt, WithAutoRouting()}, core.TransitPreferred, false,
			[]string{auto, off}, nil},
		// The caller just asked for encryption: do not suggest giving it up.
		{"gateway, caller required", []Option{cleartextOpt, WithAutoRouting()}, core.TransitRequired, false,
			[]string{auto}, []string{off}},
		// It came through "0g/auto": suggesting it again goes in a circle.
		{"gateway, auto-routed", []Option{cleartextOpt, WithAutoRouting()}, "", true,
			[]string{off}, []string{auto}},
		// A gateway sealing every model does not route "0g/auto".
		{"seal-all gateway", []Option{cleartextOpt}, "", false,
			[]string{off}, []string{auto}},
		// The sidecar has neither a cleartext path nor auto routing.
		{"sidecar", nil, "", false,
			nil, []string{auto, off, HeaderEncryptedTransit}},
	} {
		res := &transitResolver{transit: core.TransitRequired}
		rec, _ := serveFile(t, endpoint.Chat, res, tc.opts, tc.callerHeader, pdfChat, tc.autoRouted)
		msg := fileRefusal(t, tc.name, rec)
		for _, w := range tc.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: message %q lacks %q", tc.name, msg, w)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(msg, n) {
				t.Errorf("%s: message %q offers %q, which cannot work here", tc.name, msg, n)
			}
		}
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
