package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/clientip"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// fakeAutoRouter answers the three calls an auto request makes — precheck
// preview, decisions, model-choice preview — and records them, plus the chat
// request that follows when the chosen model is not sealed.
type fakeAutoRouter struct {
	mu sync.Mutex

	precheckStatus int    // 0 = 200
	precheckBody   string // used when precheckStatus != 0
	transit        string
	decisionStatus int // 0 = 200
	decisionBody   string
	task           string // the classifier's answer
	decisionDelay  time.Duration
	chosen         string // auto.model on the model-choice preview

	prechecks, decisions, selects int
	decisionHeaders               http.Header
	decisionReq                   map[string]any
	selectReq                     map[string]any
	chatBodies                    []string
}

func (f *fakeAutoRouter) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/routing/preview":
			var body map[string]any
			_ = json.Unmarshal(b, &body)
			auto, _ := body["auto"].(map[string]any)
			if auto["precheck"] == true {
				f.prechecks++
				if f.precheckStatus != 0 {
					w.WriteHeader(f.precheckStatus)
					_, _ = io.WriteString(w, f.precheckBody)
					return
				}
				_, _ = io.WriteString(w, `{"providers":[],"auto":{"enabled":true},"encrypted_transit":"`+f.transit+`"}`)
				return
			}
			f.selects++
			f.selectReq = body
			_, _ = io.WriteString(w, `{"providers":[{"address":"0xp"}],"auto":{"enabled":true,"task":"x","model":"`+f.chosen+`"}}`)
		case "/v1/decisions":
			f.decisions++
			if d := f.decisionDelay; d > 0 {
				f.mu.Unlock()
				time.Sleep(d)
				f.mu.Lock()
			}
			f.decisionHeaders = r.Header.Clone()
			_ = json.Unmarshal(b, &f.decisionReq)
			if f.decisionStatus != 0 {
				w.WriteHeader(f.decisionStatus)
				_, _ = io.WriteString(w, f.decisionBody)
				return
			}
			_, _ = io.WriteString(w, `{"answers":{"task":{"choice":"`+f.task+`","confidence":0.9}}}`)
		case endpoint.Chat.Path:
			f.chatBodies = append(f.chatBodies, string(b))
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeAutoRouter) counts() (prechecks, decisions, selects int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.prechecks, f.decisions, f.selects
}

// autoGateway is a gateway sealing "glm-5" in front of f.
func autoGateway(t *testing.T, f *fakeAutoRouter) *httptest.Server {
	return catalogGateway(t, f.server(t), entryPolicy{sealModels: mustSealModels(t, sealedModel)})
}

// postAuto posts body to the gateway. Unless headers say otherwise, the caller
// sends X-0G-Encrypted-Transit: preferred, which lets a classifier outside
// -seal-models (autoGateway's) classify in the clear.
func postAuto(t *testing.T, gwURL, body string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, gwURL+endpoint.Chat.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	req.Header.Set(openaiproxy.HeaderEncryptedTransit, "preferred")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(got)
}

const autoBody = `{"model":"0g/auto","messages":[{"role":"system","content":"You are a Go expert."},{"role":"user","content":"why does this panic?"}],"temperature":0.2}`

// The whole flow: classified once, model chosen, body rewritten and sent as
// that model; the next turn of the same conversation uses the cached task.
func TestAutoClassifiesOnceAndRewritesModel(t *testing.T) {
	f := &fakeAutoRouter{task: "code:debugging", chosen: "deepseek-v4-pro"}
	gw := autoGateway(t, f)

	resp, _ := postAuto(t, gw.URL, autoBody, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for h, want := range map[string]string{
		openaiproxy.HeaderAutoTask: "code:debugging", openaiproxy.HeaderAutoModel: "deepseek-v4-pro",
		openaiproxy.HeaderAutoClassifierE2EE: "none", openaiproxy.HeaderE2EE: openaiproxy.E2EEValueNone,
	} {
		if got := resp.Header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	if p, d, s := f.counts(); p != 1 || d != 1 || s != 1 {
		t.Fatalf("prechecks/decisions/selects = %d/%d/%d, want 1/1/1", p, d, s)
	}
	if len(f.chatBodies) != 1 {
		t.Fatalf("router got %d chat requests, want 1", len(f.chatBodies))
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(f.chatBodies[0]), &sent)
	if sent["model"] != "deepseek-v4-pro" || sent["temperature"] != 0.2 {
		t.Errorf("forwarded body = %s, want model rewritten and the rest kept", f.chatBodies[0])
	}
	state, _ := f.decisionReq["state"].(string)
	if !strings.Contains(state, "<system_prompt>\nYou are a Go expert.\n</system_prompt>") ||
		!strings.Contains(state, "<user_message>\nwhy does this panic?\n</user_message>") {
		t.Errorf("classifier state = %q", state)
	}
	if f.decisionHeaders.Get("Authorization") != "Bearer sk-user-key" {
		t.Errorf("classification must carry the caller's credential")
	}
	auto, _ := f.selectReq["auto"].(map[string]any)
	if auto["task"] != "code:debugging" || auto["sealing"] != "any" || f.selectReq["api_format"] != "openai" {
		t.Errorf("model-choice preview = %v", f.selectReq)
	}
	if _, leaked := f.selectReq["messages"]; leaked {
		t.Errorf("the model-choice preview must not carry messages")
	}

	// Second turn: same opening, more history.
	next := strings.Replace(autoBody, `"temperature"`, `"x":1,"temperature"`, 1)
	resp, _ = postAuto(t, gw.URL, next, nil)
	if p, d, s := f.counts(); p != 1 || d != 1 || s != 2 {
		t.Errorf("after a cached turn prechecks/decisions/selects = %d/%d/%d, want 1/1/2", p, d, s)
	}
	if resp.Header.Get(openaiproxy.HeaderAutoClassifierE2EE) != "none" {
		t.Errorf("a cached task still means the opening went out in the clear")
	}
}

// A sealable chosen model goes down the sealed path, not to the router.
func TestAutoChosenSealedModelIsSealed(t *testing.T) {
	f := &fakeAutoRouter{task: "math", chosen: sealedModel}
	gw := autoGateway(t, f)
	resp, _ := postAuto(t, gw.URL, autoBody, nil)
	if resp.Header.Get(openaiproxy.HeaderAutoModel) != sealedModel {
		t.Fatalf("auto model = %q", resp.Header.Get(openaiproxy.HeaderAutoModel))
	}
	if len(f.chatBodies) != 0 {
		t.Errorf("a sealed model's request reached the router's chat path in the clear")
	}
	sealable, _ := f.selectReq["auto"].(map[string]any)["sealable_models"].([]any)
	if len(sealable) != 1 || sealable[0] != sealedModel {
		t.Errorf("sealable_models = %v", sealable)
	}
}

// A refused precheck is answered as the router gave it and nothing is sent to
// be classified.
func TestAutoPrecheckRefusalStopsBeforeClassifying(t *testing.T) {
	f := &fakeAutoRouter{precheckStatus: http.StatusBadRequest,
		precheckBody: `{"error":{"code":"auto_routing_disabled","message":"off"}}`}
	gw := autoGateway(t, f)
	resp, body := postAuto(t, gw.URL, autoBody, nil)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "auto_routing_disabled") {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
	if _, d, _ := f.counts(); d != 0 {
		t.Errorf("classified %d times after a refused precheck", d)
	}
	if resp.Header.Get(openaiproxy.HeaderAutoClassifierE2EE) != "" {
		t.Errorf("nothing went out in the clear, so no disclosure header")
	}
}

// The precheck carries the body's provider object, so a trust mode written
// there is checked before the opening is sent anywhere.
func TestAutoPrecheckCarriesProviderObject(t *testing.T) {
	f := &fakeAutoRouter{task: "math", chosen: "x"}
	srv := f.server(t)
	var got map[string]any
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/routing/preview" && got == nil {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &got)
			r.Body = io.NopCloser(strings.NewReader(string(b)))
		}
		inner.ServeHTTP(w, r)
	})
	gw := catalogGateway(t, srv, entryPolicy{sealModels: mustSealModels(t, sealedModel)})
	postAuto(t, gw.URL, strings.Replace(autoBody, `"temperature":0.2`, `"provider":{"trust_mode":"private"}`, 1), nil)
	p, _ := got["provider"].(map[string]any)
	if p["trust_mode"] != "private" {
		t.Errorf("precheck body = %v, want the provider object", got)
	}
	if _, leaked := got["messages"]; leaked {
		t.Errorf("the precheck must not carry messages")
	}
}

// encrypted_transit=required: the opening is never sent; the task is general.
func TestAutoRequiredTransitDoesNotClassify(t *testing.T) {
	f := &fakeAutoRouter{transit: "required", chosen: sealedModel}
	gw := autoGateway(t, f)
	resp, _ := postAuto(t, gw.URL, autoBody, nil)
	if _, d, s := f.counts(); d != 0 || s != 1 {
		t.Fatalf("decisions/selects = %d/%d, want 0/1", d, s)
	}
	if resp.Header.Get(openaiproxy.HeaderAutoTask) != autoGeneral || resp.Header.Get(openaiproxy.HeaderAutoClassifierE2EE) != "" {
		t.Errorf("headers = %v", resp.Header)
	}
	// Not cached: the next turn asks again.
	postAuto(t, gw.URL, autoBody, nil)
	if p, _, _ := f.counts(); p != 2 {
		t.Errorf("prechecks = %d, want 2", p)
	}
}

// A classifier outside -seal-models is used only when the caller's own header
// allows cleartext: without one, nothing is sent (no precheck either) and the
// task is general.
func TestAutoCleartextClassifierNeedsCallerConsent(t *testing.T) {
	f := &fakeAutoRouter{task: "math", chosen: sealedModel}
	gw := autoGateway(t, f)
	resp, _ := postAuto(t, gw.URL, autoBody, map[string]string{openaiproxy.HeaderEncryptedTransit: ""})
	if p, d, s := f.counts(); p != 0 || d != 0 || s != 1 {
		t.Fatalf("prechecks/decisions/selects = %d/%d/%d, want 0/0/1", p, d, s)
	}
	if resp.Header.Get(openaiproxy.HeaderAutoTask) != autoGeneral || resp.Header.Get(openaiproxy.HeaderAutoClassifierE2EE) != "" {
		t.Errorf("headers = %v", resp.Header)
	}
	// "off" consents.
	resp, _ = postAuto(t, gw.URL, autoBody, map[string]string{openaiproxy.HeaderEncryptedTransit: "off"})
	if _, d, _ := f.counts(); d != 1 || resp.Header.Get(openaiproxy.HeaderAutoClassifierE2EE) != openaiproxy.E2EEValueNone {
		t.Errorf("with off: decisions = %d, classifier header %q", d, resp.Header.Get(openaiproxy.HeaderAutoClassifierE2EE))
	}
}

// The auto layer's own preview calls carry the signed client address, like
// every other router-bound request.
func TestAutoPreviewsCarryTheSignedClientIP(t *testing.T) {
	f := &fakeAutoRouter{task: "math", chosen: "x"}
	router := f.server(t)
	var mu sync.Mutex
	var previews []http.Header
	inner := router.Config.Handler
	router.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/routing/preview" {
			mu.Lock()
			previews = append(previews, r.Header.Clone())
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})
	signer, err := clientip.NewSigner(testClientIPKey, mustURL(t, router.URL))
	if err != nil {
		t.Fatal(err)
	}
	h := withClientIP(signer, newHandler(allSealedClients(), mustURL(t, router.URL), testOrigins(), "", "",
		noInFlightCap, nil, nil, nil, discardLogger(), withEntryPolicy(entryPolicy{sealModels: mustSealModels(t, sealedModel)})))
	req := httptest.NewRequest(http.MethodPost, endpoint.Chat.Path, strings.NewReader(autoBody))
	req.RemoteAddr = "203.0.113.7:51000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	req.Header.Set(openaiproxy.HeaderEncryptedTransit, "preferred")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(previews) != 2 {
		t.Fatalf("router got %d previews, want the precheck and the model choice", len(previews))
	}
	key, _ := hex.DecodeString(testClientIPKey)
	for i, got := range previews {
		ts, _ := strconv.ParseInt(got.Get(clientip.HeaderTs), 10, 64)
		if got.Get(clientip.HeaderIP) != "203.0.113.7" || got.Get(clientip.HeaderSig) != clientip.Sign(key, "203.0.113.7", ts) {
			t.Errorf("preview %d: client IP headers %q / %q", i, got.Get(clientip.HeaderIP), got.Get(clientip.HeaderSig))
		}
	}
}

// The caller's own X-0G-Encrypted-Transit: required keeps the opening from
// going out in the clear, even when the router's precheck does not report it.
func TestAutoCallerRequiredDoesNotClassifyInClear(t *testing.T) {
	f := &fakeAutoRouter{chosen: sealedModel}
	gw := autoGateway(t, f)
	resp, _ := postAuto(t, gw.URL, autoBody, map[string]string{"X-0G-Encrypted-Transit": "Required"})
	if _, d, _ := f.counts(); d != 0 {
		t.Fatalf("classified %d times in the clear despite required", d)
	}
	if resp.Header.Get(openaiproxy.HeaderAutoTask) != autoGeneral {
		t.Errorf("task = %q, want general", resp.Header.Get(openaiproxy.HeaderAutoTask))
	}
}

// A refusal of the account is the caller's answer and is not cached; any
// other classification failure is "general", cached.
func TestAutoClassificationFailures(t *testing.T) {
	f := &fakeAutoRouter{decisionStatus: http.StatusPaymentRequired,
		decisionBody: `{"error":{"code":"insufficient_balance","message":"no money"}}`, chosen: "x"}
	gw := autoGateway(t, f)
	resp, body := postAuto(t, gw.URL, autoBody, nil)
	if resp.StatusCode != http.StatusPaymentRequired || !strings.Contains(body, "insufficient_balance") {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get(openaiproxy.HeaderE2EE) != openaiproxy.E2EEValueNone {
		t.Errorf("the opening went out in the clear; %s must say none", openaiproxy.HeaderE2EE)
	}
	if resp.Header.Get(openaiproxy.HeaderEncryptedTransitStatus) != openaiproxy.TransitStatusPlaintext {
		t.Errorf("%s must agree with %s", openaiproxy.HeaderEncryptedTransitStatus, openaiproxy.HeaderE2EE)
	}

	f.mu.Lock()
	f.decisionStatus, f.decisionBody = http.StatusServiceUnavailable, `{"error":{"code":"model_disabled"}}`
	f.mu.Unlock()
	resp, _ = postAuto(t, gw.URL, autoBody, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(openaiproxy.HeaderAutoTask) != autoGeneral {
		t.Fatalf("a classifier failure must route as general: %d %v", resp.StatusCode, resp.Header)
	}
	postAuto(t, gw.URL, autoBody, nil)
	if _, d, _ := f.counts(); d != 2 {
		t.Errorf("decisions = %d, want 2 (the 402 is not cached, the 503 is)", d)
	}
}

// A caller that gives up during classification does not leave its
// conversation stuck on "general": the next turn is classified again.
func TestAutoCancelledClassificationIsNotCached(t *testing.T) {
	f := &fakeAutoRouter{task: "math", chosen: "x", decisionDelay: time.Second}
	gw := autoGateway(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, gw.URL+endpoint.Chat.Path, strings.NewReader(autoBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	req.Header.Set(openaiproxy.HeaderEncryptedTransit, "preferred")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	time.Sleep(1200 * time.Millisecond) // let the abandoned classification finish

	f.mu.Lock()
	f.decisionDelay = 0
	f.mu.Unlock()
	resp, _ := postAuto(t, gw.URL, autoBody, nil)
	if _, d, _ := f.counts(); d != 2 || resp.Header.Get(openaiproxy.HeaderAutoTask) != "math" {
		t.Errorf("decisions = %d, task = %q; want a second classification giving math", d, resp.Header.Get(openaiproxy.HeaderAutoTask))
	}
}

// A pinned provider is for the main model: nothing is classified.
func TestAutoPinnedProviderIsNotClassified(t *testing.T) {
	f := &fakeAutoRouter{chosen: "x"}
	gw := autoGateway(t, f)
	postAuto(t, gw.URL, autoBody, map[string]string{"X-0G-Provider-Address": "0xabc"})
	if p, d, s := f.counts(); p != 0 || d != 0 || s != 1 {
		t.Errorf("prechecks/decisions/selects = %d/%d/%d, want 0/0/1", p, d, s)
	}
}

// The classification carries the caller's restrictions, not its preferences.
func TestAutoClassificationForwardsRestrictions(t *testing.T) {
	f := &fakeAutoRouter{task: "math", chosen: "x"}
	gw := autoGateway(t, f)
	body := strings.Replace(autoBody, `"temperature":0.2`, `"provider":{"trust_mode":"private"}`, 1)
	postAuto(t, gw.URL, body, map[string]string{
		"X-0G-Provider-Block": "0xbad", "X-0G-Provider-Sort": "latency",
	})
	if f.decisionHeaders.Get("X-0G-Provider-Block") != "0xbad" || f.decisionHeaders.Get("X-0G-Provider-Trust-Mode") != "private" {
		t.Errorf("restrictions not forwarded: %v", f.decisionHeaders)
	}
	if f.decisionHeaders.Get("X-0G-Provider-Sort") != "" {
		t.Errorf("a preference was forwarded to the classification")
	}
}

// With the classifier in -seal-models, the classification goes down the sealed
// path: nothing reaches the router's /v1/decisions in the clear, and the
// response says the classification was sealed.
func TestAutoSealedClassifierNeverReachesRouterInClear(t *testing.T) {
	f := &fakeAutoRouter{task: "math", chosen: "x"}
	gw := catalogGateway(t, f.server(t), entryPolicy{sealModels: mustSealModels(t, sealedModel+","+defaultAutoClassifierModel)})
	resp, _ := postAuto(t, gw.URL, autoBody, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if _, d, _ := f.counts(); d != 0 {
		t.Errorf("the router got %d cleartext classifications, want 0", d)
	}
	if got := resp.Header.Get(openaiproxy.HeaderAutoClassifierE2EE); got != openaiproxy.E2EEValueSealed {
		t.Errorf("%s = %q, want sealed", openaiproxy.HeaderAutoClassifierE2EE, got)
	}
}

// Even with the classifier sealed, a caller whose X-0G-Encrypted-Transit says
// off has the sealed path forward the classification in the clear; the
// response must say so, on this turn and on the cached next one.
func TestAutoSealedClassifierTransitOffIsDisclosed(t *testing.T) {
	f := &fakeAutoRouter{task: "math", chosen: "x"}
	gw := catalogGateway(t, f.server(t), entryPolicy{sealModels: mustSealModels(t, sealedModel+","+defaultAutoClassifierModel)})
	for turn := 1; turn <= 2; turn++ {
		resp, _ := postAuto(t, gw.URL, autoBody, map[string]string{"X-0G-Encrypted-Transit": "off"})
		if got := resp.Header.Get(openaiproxy.HeaderAutoClassifierE2EE); got != openaiproxy.E2EEValueNone {
			t.Errorf("turn %d: %s = %q, want none", turn, openaiproxy.HeaderAutoClassifierE2EE, got)
		}
	}
	if _, d, _ := f.counts(); d != 1 {
		t.Errorf("router got %d cleartext classifications, want 1 (then cached)", d)
	}
}

// sealedAutoHandler is the dispatch with the auto layer, in front of f for the
// previews, with stand-ins for the sealed path (which records and answers the
// classification) and the cleartext path.
func sealedAutoHandler(t *testing.T, f *fakeAutoRouter, sealedCalls *[]*http.Request) http.Handler {
	s := mustSealModels(t, sealedModel+","+defaultAutoClassifierModel)
	auto := newAutoRouter(mustURL(t, f.server(t).URL), s, "", discardLogger())
	sealed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		*sealedCalls = append(*sealedCalls, r)
		_, _ = io.WriteString(w, `{"answers":{"task":{"choice":"math","confidence":0.9}}}`)
	})
	cleartext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(openaiproxy.HeaderE2EE, openaiproxy.E2EEValueNone)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	return s.dispatchAuto(sealed, cleartext, auto)
}

// The sealed classification is a /v1/decisions request for the classifier on
// the caller's credential and restrictions; and since the opening does not
// leave in the clear, encrypted_transit "required" does not stop it.
func TestAutoSealedClassification(t *testing.T) {
	f := &fakeAutoRouter{transit: "required", chosen: "x"}
	var calls []*http.Request
	h := sealedAutoHandler(t, f, &calls)

	req := httptest.NewRequest(http.MethodPost, endpoint.Chat.Path, strings.NewReader(autoBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-user-key")
	req.Header.Set("X-0G-Provider-Block", "0xbad")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Header().Get(openaiproxy.HeaderAutoTask) != "math" {
		t.Fatalf("got %d, task %q", rec.Code, rec.Header().Get(openaiproxy.HeaderAutoTask))
	}
	if rec.Header().Get(openaiproxy.HeaderAutoClassifierE2EE) != openaiproxy.E2EEValueSealed {
		t.Errorf("classifier header = %q", rec.Header().Get(openaiproxy.HeaderAutoClassifierE2EE))
	}
	if len(calls) != 1 {
		t.Fatalf("sealed path got %d requests, want the classification only", len(calls))
	}
	c := calls[0]
	var body map[string]any
	b, _ := io.ReadAll(c.Body)
	_ = json.Unmarshal(b, &body)
	if c.URL.Path != endpoint.Decisions.Path || body["model"] != defaultAutoClassifierModel ||
		c.Header.Get("Authorization") != "Bearer sk-user-key" || c.Header.Get("X-0G-Provider-Block") != "0xbad" {
		t.Errorf("classification = %s %v %v", c.URL.Path, body["model"], c.Header)
	}
	if _, d, _ := f.counts(); d != 0 {
		t.Errorf("the router got a cleartext classification")
	}
}

// Requests not naming "0g/auto" are untouched.
func TestNonAutoRequestUntouched(t *testing.T) {
	f := &fakeAutoRouter{}
	gw := autoGateway(t, f)
	body := modelBody("some-other-model")
	resp, _ := postAuto(t, gw.URL, body, nil)
	if p, d, s := f.counts(); p+d+s != 0 || resp.Header.Get(openaiproxy.HeaderAutoTask) != "" {
		t.Errorf("auto layer ran for a named model")
	}
	if len(f.chatBodies) != 1 || f.chatBodies[0] != body {
		t.Errorf("router got %v, want the caller's bytes", f.chatBodies)
	}
}

func TestParseOpening(t *testing.T) {
	var req wire.Request
	_ = json.Unmarshal([]byte(`{"system":[{"type":"text","text":"sys A"},{"type":"text","text":"sys B"}],
		"messages":[{"role":"assistant","content":"hi"},
		{"role":"user","content":[{"type":"image","source":{}},{"type":"text","text":"what is this"}]},
		{"role":"user","content":"later"}]}`), &req)
	o := parseOpening(req)
	if o.system != "sys A\nsys B" || o.user != "what is this" || !slices.Equal(o.media, []string{"image"}) {
		t.Errorf("opening = %+v", o)
	}

	// Later turns do not change the opening: a system message after the first
	// user message is not read, and an image-only first message stays empty.
	req = wire.Request{}
	_ = json.Unmarshal([]byte(`{"messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"fix my bug"},
		{"role":"assistant","content":"ok"},{"role":"system","content":"tool output secret"},{"role":"user","content":"next"}]}`), &req)
	if o = parseOpening(req); o.system != "Be brief." || o.user != "fix my bug" {
		t.Errorf("opening = %+v, want only what precedes and is the first user message", o)
	}
	req = wire.Request{}
	_ = json.Unmarshal([]byte(`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{}}]},
		{"role":"user","content":"what is it"}]}`), &req)
	if o = parseOpening(req); o.user != "" || !slices.Equal(o.media, []string{"image"}) {
		t.Errorf("opening = %+v, want no user text (later messages are not the opening) and an image", o)
	}

	// A screenshot a tool read, inside a tool_result, counts; a tool call's
	// arguments do not.
	req = wire.Request{}
	_ = json.Unmarshal([]byte(`{"messages":[{"role":"user","content":"fix the css"},
		{"role":"assistant","content":[{"type":"tool_use","input":{"type":"video"}}]},
		{"role":"user","content":[{"type":"tool_result","content":[{"type":"image","source":{}}]}]}]}`), &req)
	if o = parseOpening(req); !slices.Equal(o.media, []string{"image"}) {
		t.Errorf("media = %v, want the tool_result image only", o.media)
	}

	long := strings.Repeat("界", 3000) // 3 bytes each
	req = wire.Request{}
	_ = json.Unmarshal([]byte(`{"messages":[{"role":"user","content":"`+long+`"}]}`), &req)
	o = parseOpening(req)
	if len(o.user) != 6000 || !strings.HasPrefix(long, o.user) {
		t.Errorf("user cut to %d bytes, want 6000 on a character boundary", len(o.user))
	}
	if got := truncateUTF8("ab界", 4); got != "ab" {
		t.Errorf("truncateUTF8 = %q", got)
	}
}

func TestSealingFor(t *testing.T) {
	for body, want := range map[string]string{
		`{}`:                                          "any",
		`{"tools":[{"type":"function"}]}`:             "any",
		`{"plugins":[{"id":"web"}]}`:                  "avoid",
		`{"attachments":[{"file_id":"f1"}]}`:          "avoid",
		`{"tools":[{"type":"0g:web_search"}]}`:        "avoid",
		`{"tools":[{"type":"openrouter:web_fetch"}]}`: "avoid",
	} {
		var req wire.Request
		_ = json.Unmarshal([]byte(body), &req)
		if got := sealingFor(req, len(body)); got != want {
			t.Errorf("sealingFor(%s) = %q, want %q", body, got, want)
		}
	}
	if sealingFor(wire.Request{}, openaiproxy.MaxRequestBytes+1) != "avoid" {
		t.Errorf("a body over the sealed cap must avoid sealed models")
	}
}

func TestAutoTaskCacheEvictsAndExpires(t *testing.T) {
	c := newAutoTaskCache(2)
	c.put("a", "math", true, autoCacheTTL)
	c.put("b", "math", false, autoCacheTTL)
	c.get("a")
	c.put("c", "math", false, autoCacheTTL) // evicts b, the least recently used
	if _, _, ok := c.get("b"); ok {
		t.Errorf("b should have been evicted")
	}
	if _, inClear, ok := c.get("a"); !ok || !inClear {
		t.Errorf("a should still be cached, in the clear")
	}
	c.put("d", "math", false, -1)
	if _, _, ok := c.get("d"); ok {
		t.Errorf("an expired entry must not be returned")
	}
}

func TestIsAccountRefusal(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   bool
	}{
		{401, `{}`, true},
		{402, `{}`, true},
		{423, `{}`, true},
		{429, `{"error":{"code":"rate_limit_exceeded"}}`, true},
		{429, `{"error":{"code":"credit_limit_exceeded"}}`, true},
		{429, `{"error":{"code":"model_quota_exceeded"}}`, false},
		{429, `{"error":{"code":"fair_share_exceeded"}}`, false},
		{403, `{"error":{"code":"pay_account_cap"}}`, true},
		{403, `{"error":{"code":"model_not_allowed"}}`, false},
		{503, `{"error":{"code":"no_available_provider"}}`, false},
	} {
		if got := isAccountRefusal(tc.status, []byte(tc.body)); got != tc.want {
			t.Errorf("isAccountRefusal(%d, %s) = %v, want %v", tc.status, tc.body, got, tc.want)
		}
	}
}
