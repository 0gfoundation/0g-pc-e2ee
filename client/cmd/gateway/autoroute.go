package main

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/0gfoundation/0g-pc-e2ee/client/clientip"
	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Model "0g/auto": the caller asks this gateway to choose the model.
//
// For a chat request (POST /v1/chat/completions or /v1/messages) naming it,
// the gateway takes the conversation's opening — the system prompt and the
// first user message — asks a classifier model which task it is, asks the
// router's route preview which model serves that task for this caller, and
// rewrites `model` to that model. From there the request is exactly one that
// named the model: dispatch seals it if the model is in -seal-models and
// forwards it in the clear otherwise. The router never sees "0g/auto" on an
// inference request.
//
// # The classification
//
// The opening (classifierSystemBytes + classifierUserBytes, truncated) goes to
// the classifier at POST /v1/decisions through this gateway's own dispatch, so
// it is sealed exactly when a caller's request naming the classifier would be:
// when the classifier is in -seal-models.
//
// The opening crosses the router in the clear only when the caller's own
// X-0G-Encrypted-Transit allows it with "off" or "preferred": a sealed
// classification falls back to the clear on those, and a classifier outside
// -seal-models is used only for such callers. For anyone else that
// classifier is not called; the task is "general" and nothing is sent. Whenever the
// opening has gone out, the response says how (X-0G-Auto-Classifier-E2EE:
// sealed or none).
//
// It is sent once per conversation — the task is cached by credential and
// opening, and later turns share the opening — and not at all when the
// request could not use auto anyway (a precheck preview runs first) or the
// caller pinned a provider.
//
// The cache keeps a conversation on one task within one gateway instance and
// one credential, for the cache TTL. A conversation can still change model:
// on another instance, after a credential change (a refreshed JWT), when its
// entry expires or is evicted (a cached failure after autoFailureTTL), when a
// turn that was not classified (pinned provider, no consent to cleartext) is
// followed by one that is, or when the router's ranking for the task changes
// (the model is chosen again every turn).
//
// The classification is a normal inference request on the caller's own
// credential: the router authenticates and bills it, applies the caller's
// rules to it, and the caller pays for it.
//
// Enabled whenever -seal-models is a list (the only configuration that has
// models to choose between sealed and not). A list that seals the chat
// surface whole (chatbot:*) sends chat requests to the sealed path before the
// auto layer sees them, so "0g/auto" does not work there; the router's
// features.auto_routing
// decides whether it does anything (the precheck answers 404 or 400 when off).

const (
	// autoModel is the model id that asks for auto routing.
	autoModel = "0g/auto"
	// autoGeneral is the task for a request that was not classified.
	autoGeneral = "general"

	// defaultAutoClassifierModel answers the classification question.
	defaultAutoClassifierModel = "vela-2.0-9b"

	// The opening sent to be classified, in bytes so the classifier's input,
	// and so its latency and cost, has a fixed bound whatever the script.
	classifierSystemBytes = 2000
	classifierUserBytes   = 6000

	// classifierTimeout bounds the classification call; on expiry the request
	// goes on as "general". Measured against staging: a cleartext call peaked
	// at 2.6 s; sealed adds about 0.25 s warm, and an instance's first sealed
	// call took 2.5-3.5 s.
	classifierTimeout = 5 * time.Second
	// autoPreviewTimeout bounds each of the two preview calls.
	autoPreviewTimeout = 10 * time.Second

	autoCacheEntries = 10000
	autoCacheTTL     = 24 * time.Hour
	// autoFailureTTL is how long a failed classification is remembered as
	// "general": long enough that a conversation does not switch model on
	// every turn while the classifier is failing, short enough to retry soon.
	// (Within one instance; see "The classification" above.)
	autoFailureTTL = time.Hour

	maxAutoControlBody = 1 << 20
)

// autoTaskCategories are the classifier's choices, each with the description
// the classifier reads (OpenRouter's task tags; the router ranks models per
// tag, pkg/autoroute).
var autoTaskCategories = []struct{ tag, desc string }{
	{"agent:workflow_execution", "Autonomously carrying out a multi-step workflow or task end to end as an agent (doing the steps, not just planning them)"},
	{"agent:multi_step_planning", "Breaking a goal into an ordered plan of steps, a roadmap or a strategy before execution"},
	{"agent:tool_dispatch", "Choosing which tool / function / API to call and with which arguments"},
	{"agent:web_search", "Looking up current or live information on the web (news, prices, recent events, 'search for')"},
	{"agent:memory_extraction", "Extracting durable facts, preferences or memories about the user from a conversation to store for later"},
	{"code:general_impl", "Writing new code: implementing a function, class, script or feature"},
	{"code:file_read_write", "Reading, creating, editing or patching specific files in a codebase"},
	{"code:debugging", "Finding and fixing the cause of an error, crash, failing test or wrong behaviour in code"},
	{"code:review_security", "Reviewing code for quality, bugs or security vulnerabilities"},
	{"code:shell_execution", "Writing or running shell / terminal commands"},
	{"code:frontend_ui", "Building or styling web / mobile user interfaces (HTML, CSS, React, components, layout)"},
	{"code:repo_scan", "Exploring or explaining an existing codebase / repository structure"},
	{"code:devops_config", "Writing infrastructure or CI/CD configuration (Dockerfile, Kubernetes YAML, Terraform, GitHub Actions)"},
	{"code:sql_database", "Writing or optimizing SQL queries, database schemas or migrations"},
	{"data:extraction", "Pulling structured fields or entities out of unstructured text or documents"},
	{"data:transformation", "Converting, reformatting, cleaning or reshaping data between formats"},
	{"classification_tagging", "Assigning labels, categories, sentiment or tags to given items"},
	{"content_writing", "Writing articles, blog posts, marketing copy, emails or other prose"},
	{"roleplay_fiction", "Role-play, interactive fiction, storytelling or creative fiction writing"},
	{"qa_knowledge", "Answering a factual or explanatory knowledge question"},
	{"conversational_reply", "Casual chit-chat, greetings or small talk"},
	{"research_report", "Producing an in-depth research report or analysis on a topic"},
	{"customer_support", "Handling a customer's service issue, complaint, order or account problem"},
	{"summarization", "Condensing a given text into a shorter summary"},
	{"security_audit", "Assessing systems, infrastructure or configurations for security risks (not a code review)"},
	{"math", "Solving mathematical problems, proofs or calculations"},
	{"finance_trading", "Investing, trading, markets, portfolio or financial analysis"},
	{"translation", "Translating text from one language to another"},
	{"devops", "Operating and troubleshooting running systems: servers, deployments, monitoring, incidents"},
}

const classifierInstructions = "Which task category best describes what the user is asking the assistant to do? The state holds the assistant's system prompt (if any) and the user's first message."

// classifierRestrictionHeaders are the caller's headers that RESTRICT where a
// request may go; the classification carries them so a provider the caller
// excluded never sees the opening. Preferences (sort, fallbacks, pins) are
// not forwarded: they are about the main model.
var classifierRestrictionHeaders = []string{
	"X-0G-Provider-Trust-Mode", "X-0G-Provider-Allow", "X-0G-Provider-Block",
	"X-0G-Provider-Max-Price-Usd-Prompt", "X-0G-Provider-Max-Price-Usd-Completion", "X-0G-Provider-Max-Price-Usd-Image",
	"X-0G-Encrypted-Transit",
}

type autoRouter struct {
	previewURL string
	client     *http.Client
	classifier string
	// classifierSealed: the classification is dispatched to the sealed path
	// (the classifier is in -seal-models). That path can still forward it in
	// the clear at the caller's own request; see classify.
	classifierSealed bool
	// decide serves the classification: the gateway's model dispatch, which
	// seals it or forwards it in the clear as it would a caller's request.
	// Set by dispatchAuto.
	decide   http.Handler
	sealable []string
	cache    *autoTaskCache
	logger   *slog.Logger
}

// newAutoRouter returns nil — auto off — unless s is a model list.
func newAutoRouter(routerTarget *url.URL, s sealModels, classifier string, logger *slog.Logger) *autoRouter {
	if routerTarget == nil || s.off || s.all() {
		return nil
	}
	if classifier == "" {
		classifier = defaultAutoClassifierModel
	}
	sealable := make([]string, 0, len(s.allow))
	for m := range s.allow {
		sealable = append(sealable, m)
	}
	base := strings.TrimRight(routerTarget.String(), "/")
	return &autoRouter{
		previewURL:       base + "/v1/routing/preview",
		client:           &http.Client{Transport: core.NewPooledTransport()},
		classifier:       classifier,
		classifierSealed: s.seals(classifier) || s.surfaces[endpoint.Decisions.Path] != "",
		sealable:         sealable,
		cache:            newAutoTaskCache(autoCacheEntries),
		logger:           logger,
	}
}

// isAutoRequest reports whether r is a chat request naming "0g/auto".
func isAutoRequest(r *http.Request, model string) bool {
	return r.Method == http.MethodPost &&
		(r.URL.Path == endpoint.Chat.Path || r.URL.Path == endpoint.Anthropic.Path) &&
		strings.EqualFold(strings.TrimSpace(model), autoModel)
}

// resolve chooses the model for an auto request and returns body with `model`
// rewritten to it. On ok=false the response has been written.
func (a *autoRouter) resolve(w http.ResponseWriter, r *http.Request, body []byte) (out []byte, model string, ok bool) {
	ep := endpoint.Chat
	if r.URL.Path == endpoint.Anthropic.Path {
		ep = endpoint.Anthropic
	}
	var req wire.Request
	if err := json.Unmarshal(body, &req); err != nil {
		openaiproxy.WriteError(w, http.StatusBadRequest, "gateway", "request body is not a JSON object")
		return nil, "", false
	}
	opening := parseOpening(req)
	cred := openaiproxy.Credential(r)
	// classified: this conversation's opening has gone to the classifier,
	// this turn or an earlier one (a cached task); inClear: it went to the
	// router in the clear.
	task, classified, inClear := autoGeneral, false, false

	switch {
	case opening.user == "":
		// Nothing to classify.
	case pinsProvider(r.Header, req):
		// The pin is for the main model; the classifier cannot be sent there,
		// and sending the opening anywhere else goes against the pin.
	case !a.classifierSealed && !callerAllowsClear(r):
		// The classification would cross the router in the clear, and only
		// the caller's own header may allow that.
	default:
		key := a.cacheKey(cred, opening.input())
		if t, clear, hit := a.cache.get(key); hit {
			task, classified, inClear = t, true, clear
			break
		}
		// The body's provider object (routing preferences, no content) rides
		// along, so a trust mode in it is checked before anything goes out.
		var preReq wire.Request
		if p, ok := req["provider"]; ok {
			preReq = wire.Request{"provider": p}
		}
		pre, status, rbody, rh, err := a.preview(r, cred, ep, map[string]any{"precheck": true}, preReq)
		if err != nil {
			openaiproxy.WriteError(w, http.StatusBadGateway, "gateway", "route preview failed")
			return nil, "", false
		}
		if status != http.StatusOK {
			relayRouterError(w, status, rbody, rh)
			return nil, "", false
		}
		if strings.EqualFold(pre.EncryptedTransit, "required") && !a.classifierSealed {
			// The opening may not leave in the clear at all.
			break
		}
		classified = true
		t, clear, accountRefusal, ttl := a.classify(r, cred, req, opening.input())
		inClear = clear
		if accountRefusal != nil {
			markClassified(w, inClear)
			relayRouterError(w, accountRefusal.status, accountRefusal.body, accountRefusal.header)
			return nil, "", false
		}
		task = t
		// A caller that went away cut the classification short; that says
		// nothing about this conversation, so it is not remembered.
		if r.Context().Err() == nil {
			a.cache.put(key, task, inClear, ttl)
		}
	}

	w.Header().Set(openaiproxy.HeaderAutoTask, task)
	if classified {
		w.Header().Set(openaiproxy.HeaderAutoClassifierE2EE, classifierE2EE(inClear))
	}
	// Errors written from here on are this layer's own, not a sealed exchange.
	fail := func() {
		if classified && inClear {
			markPlaintext(w)
		}
	}

	auto := map[string]any{
		"task":            task,
		"sealable_models": a.sealable,
		"sealing":         sealingFor(req, len(body)),
	}
	if len(opening.media) > 0 {
		auto["input_modalities"] = opening.media
	}
	sel, status, rbody, rh, err := a.preview(r, cred, ep, auto, req)
	if err != nil {
		fail()
		openaiproxy.WriteError(w, http.StatusBadGateway, "gateway", "route preview failed")
		return nil, "", false
	}
	if status != http.StatusOK || sel.Auto.Model == "" {
		fail()
		if status == http.StatusOK {
			openaiproxy.WriteError(w, http.StatusBadGateway, "gateway", "route preview chose no model")
			return nil, "", false
		}
		relayRouterError(w, status, rbody, rh)
		return nil, "", false
	}
	model = sel.Auto.Model
	out, err = setModel(body, model)
	if err != nil {
		fail()
		openaiproxy.WriteError(w, http.StatusBadRequest, "gateway", "request body is not a JSON object")
		return nil, "", false
	}
	w.Header().Set(openaiproxy.HeaderAutoModel, model)
	a.logger.Debug("auto routing", "task", task, "model", model, "classified", classified, "classified_in_clear", inClear)
	return out, model, true
}

// callerAllowsClear reports whether the caller's own X-0G-Encrypted-Transit
// allows a cleartext request: off or preferred.
func callerAllowsClear(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get(openaiproxy.HeaderEncryptedTransit))) {
	case "off", "preferred":
		return true
	}
	return false
}

// classifierE2EE is X-0G-Auto-Classifier-E2EE for a classified conversation.
func classifierE2EE(inClear bool) string {
	if inClear {
		return openaiproxy.E2EEValueNone
	}
	return openaiproxy.E2EEValueSealed
}

// markClassified labels a response this layer writes after classifying: the
// disclosure header, and X-0G-E2EE none when the opening went out in the clear.
func markClassified(w http.ResponseWriter, inClear bool) {
	w.Header().Set(openaiproxy.HeaderAutoClassifierE2EE, classifierE2EE(inClear))
	if inClear {
		markPlaintext(w)
	}
}

// markPlaintext overrides the sealed gate's channel markers on a response this
// layer writes after the opening went out in the clear — both names, which
// MarkE2EE keeps in agreement.
func markPlaintext(w http.ResponseWriter) {
	w.Header().Set(openaiproxy.HeaderE2EE, openaiproxy.E2EEValueNone)
	w.Header().Set(openaiproxy.HeaderEncryptedTransitStatus, openaiproxy.TransitStatusPlaintext)
}

// opening is the part of a conversation the classifier reads.
type opening struct {
	system, user string
	// media are the non-text input modalities anywhere in the conversation
	// ("image", "video"), which narrow the models that can serve it.
	media []string
}

func (o opening) input() string {
	var b strings.Builder
	if o.system != "" {
		b.WriteString("<system_prompt>\n" + o.system + "\n</system_prompt>\n")
	}
	b.WriteString("<user_message>\n" + o.user + "\n</user_message>")
	return b.String()
}

// parseOpening reads the system prompt and the first user message's text, for
// either surface: OpenAI puts the system prompt in role system / developer
// messages, Anthropic in top-level `system`. Non-text parts are not read, only
// noted when they are images.
func parseOpening(req wire.Request) opening {
	var o opening
	var sys []string
	if raw, ok := req["system"]; ok {
		if t := contentText(raw); t != "" {
			sys = append(sys, t)
		}
	}
	var msgs []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	_ = json.Unmarshal(req["messages"], &msgs)
	o.media = mediaIn(req["messages"])
	// The opening ends at the first user message: what comes later is not
	// read (it changes every turn, and the opening must not).
	opened := false
	for _, m := range msgs {
		t := contentText(m.Content)
		if opened {
			continue
		}
		switch m.Role {
		case "system", "developer":
			if t != "" {
				sys = append(sys, t)
			}
		case "user":
			o.user, opened = t, true
		}
	}
	o.system = truncateUTF8(strings.Join(sys, "\n"), classifierSystemBytes)
	o.user = truncateUTF8(o.user, classifierUserBytes)
	return o
}

// contentText returns a message content's text: a string, or the text parts
// of an array.
func contentText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var texts []string
	for _, p := range parts {
		if (p.Type == "text" || p.Type == "input_text") && p.Text != "" {
			texts = append(texts, p.Text)
		}
	}
	return strings.Join(texts, "\n")
}

// mediaPartModality maps a content part type to the modality the router
// routes on, as the router's own detector does (pkg/inference DetectInputMedia).
var mediaPartModality = map[string]string{
	"image_url": "image", "image": "image", "input_image": "image",
	"video_url": "video", "video": "video",
}

// mediaIn lists the modalities of the media parts in messages, looking into
// nested content (an Anthropic tool_result carries a screenshot a tool read)
// but not into a tool call's arguments, like the router's detector, so the
// model chosen can take what the request carries.
func mediaIn(raw json.RawMessage) []string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var out []string
	var scan func(any)
	scan = func(v any) {
		switch t := v.(type) {
		case []any:
			for _, e := range t {
				scan(e)
			}
		case map[string]any:
			typ, _ := t["type"].(string)
			if m, ok := mediaPartModality[typ]; ok {
				if !slices.Contains(out, m) {
					out = append(out, m)
				}
				return
			}
			scan(t["content"])
		}
	}
	scan(v)
	return out
}

// truncateUTF8 cuts s to at most n bytes on a character boundary.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// pinsProvider reports whether the caller pinned a provider.
func pinsProvider(h http.Header, req wire.Request) bool {
	if h.Get("X-0G-Provider-Address") != "" || h.Get("X-0G-Provider-Identity") != "" {
		return true
	}
	var p struct {
		Address string `json:"address"`
	}
	_ = json.Unmarshal(req["provider"], &p)
	return p.Address != ""
}

// sealingFor is "avoid" when the request could not be sent sealed: it uses a
// feature the router refuses on a sealed request (router
// SealedPromptInjectionConflict: features that work by inserting into the
// prompt), or it is over the sealed path's size cap.
func sealingFor(req wire.Request, size int) string {
	if size > openaiproxy.MaxRequestBytes {
		return "avoid"
	}
	var plugins []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(req["plugins"], &plugins)
	for _, p := range plugins {
		if p.ID == "web" {
			return "avoid"
		}
	}
	var attachments []struct {
		FileID string `json:"file_id"`
	}
	_ = json.Unmarshal(req["attachments"], &attachments)
	for _, at := range attachments {
		if at.FileID != "" {
			return "avoid"
		}
	}
	var tools []struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(req["tools"], &tools)
	for _, t := range tools {
		switch t.Type {
		case "0g:web_search", "0g:web_fetch", "openrouter:web_fetch":
			return "avoid"
		}
	}
	return "any"
}

type autoPreviewResponse struct {
	EncryptedTransit string `json:"encrypted_transit"`
	Auto             struct {
		Model string `json:"model"`
	} `json:"auto"`
}

// preview calls the router's route preview for "0g/auto" with req stripped as
// the sealed path strips it (the whole request for the model choice, only its
// provider object for the precheck). A non-200 answer is returned, not an
// error.
func (a *autoRouter) preview(r *http.Request, cred string, ep endpoint.Endpoint, auto map[string]any, req wire.Request) (
	pr autoPreviewResponse, status int, body []byte, header http.Header, err error) {
	payload := map[string]any{}
	if req != nil {
		for k, v := range route.PreviewPayload(ep, req) {
			payload[k] = v
		}
	}
	payload["model"] = autoModel
	payload["service_type"] = ep.ServiceType
	// Name the surface for chat too: an omitted api_format previews either
	// one, and a model that serves only /v1/messages must not be chosen for
	// /v1/chat/completions.
	payload["api_format"] = "openai"
	if ep.APIFormat != "" {
		payload["api_format"] = ep.APIFormat
	}
	payload["auto"] = auto
	b, err := json.Marshal(payload)
	if err != nil {
		return pr, 0, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), autoPreviewTimeout)
	defer cancel()
	status, body, header, err = a.post(ctx, a.previewURL, cred, openaiproxy.RoutingHeaders(r.Header), b)
	if err != nil || status != http.StatusOK {
		return pr, status, body, header, err
	}
	if err := json.Unmarshal(body, &pr); err != nil {
		return pr, 0, nil, nil, fmt.Errorf("decode route preview: %w", err)
	}
	return pr, status, body, header, nil
}

type routerRefusal struct {
	status int
	body   []byte
	header http.Header
}

// classify asks the classifier for the opening's task. A refusal of the
// account itself (no credential, no money, rate or credit limit) is returned
// for the caller: the main request would be refused the same way. Anything
// else — a timeout, the classifier unavailable or excluded by the caller's
// rules, an answer outside the categories — is "general", remembered for
// autoFailureTTL.
//
// inClear reports whether the opening went to the router in the clear. Even
// with the classifier in -seal-models it can: the sealed path forwards in the
// clear when the caller's X-0G-Encrypted-Transit (forwarded with the other
// restrictions) says off, or says preferred and no provider can be sealed to.
// It is read from what the dispatch did — the cleartext path marks X-0G-E2EE
// none — and, when no answer came back, assumed whenever it was possible.
func (a *autoRouter) classify(r *http.Request, cred string, req wire.Request, input string) (task string, inClear bool, refusal *routerRefusal, ttl time.Duration) {
	criteria := make(map[string]string, len(autoTaskCategories))
	for _, c := range autoTaskCategories {
		criteria[c.tag] = c.desc
	}
	b, err := json.Marshal(map[string]any{
		"model": a.classifier,
		"state": input,
		"questions": map[string]any{"task": map[string]any{
			"type": "choice", "instructions": classifierInstructions, "criteria": criteria,
		}},
	})
	if err != nil {
		return autoGeneral, false, nil, autoFailureTTL
	}
	h := http.Header{}
	for _, name := range classifierRestrictionHeaders {
		if v := r.Header.Values(name); len(v) > 0 {
			h[http.CanonicalHeaderKey(name)] = v
		}
	}
	// A trust mode in the body applies to the classification too.
	if h.Get("X-0G-Provider-Trust-Mode") == "" {
		var p struct {
			TrustMode string `json:"trust_mode"`
		}
		if json.Unmarshal(req["provider"], &p) == nil && p.TrustMode != "" {
			h.Set("X-0G-Provider-Trust-Mode", p.TrustMode)
		}
	}
	// Bounded by its own budget: past it the request goes on as "general".
	ctx, cancel := context.WithTimeout(r.Context(), classifierTimeout)
	defer cancel()
	status, body, header, err := a.decideOnce(ctx, cred, h, b)
	if err != nil {
		a.logger.Info("auto classification failed", "err", err)
		t := strings.ToLower(strings.TrimSpace(h.Get(openaiproxy.HeaderEncryptedTransit)))
		return autoGeneral, !a.classifierSealed || t == "off" || t == "preferred", nil, autoFailureTTL
	}
	inClear = !a.classifierSealed || header.Get(openaiproxy.HeaderE2EE) == openaiproxy.E2EEValueNone
	if status != http.StatusOK {
		if isAccountRefusal(status, body) {
			return "", inClear, &routerRefusal{status, body, header}, 0
		}
		a.logger.Info("auto classification refused", "status", status, "code", routerErrorCode(body))
		return autoGeneral, inClear, nil, autoFailureTTL
	}
	var resp struct {
		Answers struct {
			Task struct {
				Choice string `json:"choice"`
			} `json:"task"`
		} `json:"answers"`
	}
	if json.Unmarshal(body, &resp) != nil || !isAutoTaskCategory(resp.Answers.Task.Choice) {
		a.logger.Info("auto classification gave no category")
		return autoGeneral, inClear, nil, autoFailureTTL
	}
	return resp.Answers.Task.Choice, inClear, nil, autoCacheTTL
}

func isAutoTaskCategory(t string) bool {
	for _, c := range autoTaskCategories {
		if c.tag == t {
			return true
		}
	}
	return false
}

// isAccountRefusal reports whether the router refused the account rather
// than the classifier: by error code where the status alone does not say.
func isAccountRefusal(status int, body []byte) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusLocked:
		return true
	}
	code := routerErrorCode(body)
	switch code {
	case "rate_limit_exceeded", "credit_limit_exceeded", "usd_billing_frozen", "vault_unavailable":
		return true
	}
	// 0G Pay's balance gate (pay_no_balance, pay_account_cap, …).
	return strings.HasPrefix(code, "pay_")
}

func routerErrorCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

// decideOnce serves one classification through a.decide, in process. The
// request carries ctx, so it keeps what the caller's request context holds
// (its client address) and is cut off at the classifier's budget.
func (a *autoRouter) decideOnce(ctx context.Context, cred string, h http.Header, body []byte) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.Decisions.Path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vs := range h {
		req.Header[k] = vs
	}
	req.Header.Set("Content-Type", "application/json")
	if cred != "" {
		req.Header.Set("Authorization", cred)
	}
	rec := httptest.NewRecorder()
	a.decide.ServeHTTP(rec, req)
	if err := ctx.Err(); err != nil {
		return 0, nil, nil, err
	}
	b := rec.Body.Bytes()
	if len(b) > maxAutoControlBody {
		return 0, nil, nil, fmt.Errorf("classification answer over %d bytes", maxAutoControlBody)
	}
	return rec.Code, b, rec.Header(), nil
}

func (a *autoRouter) post(ctx context.Context, url, cred string, h http.Header, body []byte) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vs := range h {
		req.Header[k] = vs
	}
	req.Header.Set("Content-Type", "application/json")
	if cred != "" {
		req.Header.Set("Authorization", cred)
	}
	clientip.Stamp(req) // router-bound: sign the client address
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAutoControlBody))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, b, resp.Header, nil
}

// relayRouterError writes a router error as the router gave it: status and
// body, and of its headers only the ones the sealed path surfaces (never its
// CORS headers, which would duplicate this gateway's own).
func relayRouterError(w http.ResponseWriter, status int, body []byte, h http.Header) {
	openaiproxy.CopyPassthroughHeaders(w, h)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// setModel rewrites the body's `model`, leaving every other field's bytes as
// they were.
func setModel(body []byte, model string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("body is not a JSON object")
	}
	v, _ := json.Marshal(model)
	m["model"] = v
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// cacheKey keys a task by credential and opening, so one caller's cache entry
// is not another's: a hit's speed must not tell anyone that some other caller
// sent this opening.
func (a *autoRouter) cacheKey(cred, input string) string {
	c := sha256.Sum256([]byte(cred))
	k := sha256.Sum256(append(c[:], input...))
	return hex.EncodeToString(k[:])
}

// autoTaskCache is a small LRU with per-entry expiry.
type autoTaskCache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List
	items map[string]*list.Element
	now   func() time.Time
}

type autoTaskEntry struct {
	key, task string
	inClear   bool // the opening went to the router in the clear
	expires   time.Time
}

func newAutoTaskCache(max int) *autoTaskCache {
	return &autoTaskCache{max: max, ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

func (c *autoTaskCache) get(key string) (task string, inClear, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return "", false, false
	}
	e := el.Value.(*autoTaskEntry)
	if c.now().After(e.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return "", false, false
	}
	c.ll.MoveToFront(el)
	return e.task, e.inClear, true
}

func (c *autoTaskCache) put(key, task string, inClear bool, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
	}
	c.items[key] = c.ll.PushFront(&autoTaskEntry{key: key, task: task, inClear: inClear, expires: c.now().Add(ttl)})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*autoTaskEntry).key)
	}
}
