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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
// # The exception to "content does not cross the router in the clear"
//
// The classifier (Vela, POST /v1/decisions) has no end-to-end encryption yet,
// so the opening is sent to it through the router IN THE CLEAR — the one
// content-bearing request this gateway sends that way on purpose (see
// newRouterProxy). It is bounded and disclosed:
//
//   - Only the opening, truncated (classifierSystemBytes + classifierUserBytes),
//     and only once per conversation: the task is cached by credential and
//     opening, so later turns, whose opening is the same, send nothing.
//   - A response whose conversation opening has gone out says so:
//     X-0G-Auto-Classifier-E2EE: none.
//   - Nothing is sent when the request could not use auto anyway (a precheck
//     preview runs first), when the caller pinned a provider, or when the
//     effective encrypted_transit is "required" — those requests are routed
//     for task "general".
//
// The classification is a normal inference request on the caller's own
// credential: the router authenticates and bills it, applies the caller's
// rules to it, and the caller pays for it.
//
// Enabled whenever -seal-models is a list (the only configuration that has
// models to choose between sealed and not); the router's features.auto_routing
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
	// goes on as "general". The slowest classification measured was 2.6 s.
	classifierTimeout = 3 * time.Second
	// autoPreviewTimeout bounds each of the two preview calls.
	autoPreviewTimeout = 10 * time.Second

	autoCacheEntries = 10000
	autoCacheTTL     = 24 * time.Hour
	// autoFailureTTL is how long a failed classification is remembered as
	// "general": long enough that a conversation does not switch model
	// mid-way when the classifier comes back, short enough to retry soon.
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
	previewURL, decisionsURL string
	client                   *http.Client
	classifier               string
	sealable                 []string
	cache                    *autoTaskCache
	logger                   *slog.Logger
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
		previewURL:   base + "/v1/routing/preview",
		decisionsURL: base + "/v1/decisions",
		client:       &http.Client{Transport: core.NewPooledTransport()},
		classifier:   classifier,
		sealable:     sealable,
		cache:        newAutoTaskCache(autoCacheEntries),
		logger:       logger,
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
	// sentInClear: this conversation's opening has gone to the router in the
	// clear, this turn or an earlier one (a cached task).
	task, sentInClear := autoGeneral, false

	switch {
	case opening.user == "":
		// Nothing to classify.
	case pinsProvider(r.Header, req):
		// The pin is for the main model; the classifier cannot be sent there,
		// and sending the opening anywhere else goes against the pin.
	default:
		key := a.cacheKey(cred, opening.input())
		if t, hit := a.cache.get(key); hit {
			task, sentInClear = t, true
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
		if pre.EncryptedTransit == "required" {
			// The opening may not leave in the clear at all.
			break
		}
		sentInClear = true
		t, accountRefusal, ttl := a.classify(r, cred, req, opening.input())
		if accountRefusal != nil {
			w.Header().Set(openaiproxy.HeaderE2EE, openaiproxy.E2EEValueNone)
			w.Header().Set(openaiproxy.HeaderAutoClassifierE2EE, "none")
			relayRouterError(w, accountRefusal.status, accountRefusal.body, accountRefusal.header)
			return nil, "", false
		}
		task = t
		// A caller that went away cut the classification short; that says
		// nothing about this conversation, so it is not remembered.
		if r.Context().Err() == nil {
			a.cache.put(key, task, ttl)
		}
	}

	w.Header().Set(openaiproxy.HeaderAutoTask, task)
	if sentInClear {
		w.Header().Set(openaiproxy.HeaderAutoClassifierE2EE, "none")
	}
	// Errors written from here on are this layer's own, not a sealed exchange.
	fail := func() {
		if sentInClear {
			w.Header().Set(openaiproxy.HeaderE2EE, openaiproxy.E2EEValueNone)
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
	a.logger.Debug("auto routing", "task", task, "model", model, "classified_in_clear", sentInClear)
	return out, model, true
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
func (a *autoRouter) classify(r *http.Request, cred string, req wire.Request, input string) (task string, refusal *routerRefusal, ttl time.Duration) {
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
		return autoGeneral, nil, autoFailureTTL
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
	status, body, header, err := a.post(ctx, a.decisionsURL, cred, h, b)
	if err != nil {
		a.logger.Info("auto classification failed", "err", err)
		return autoGeneral, nil, autoFailureTTL
	}
	if status != http.StatusOK {
		if isAccountRefusal(status, body) {
			return "", &routerRefusal{status, body, header}, 0
		}
		a.logger.Info("auto classification refused", "status", status, "code", routerErrorCode(body))
		return autoGeneral, nil, autoFailureTTL
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
		return autoGeneral, nil, autoFailureTTL
	}
	return resp.Answers.Task.Choice, nil, autoCacheTTL
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
	expires   time.Time
}

func newAutoTaskCache(max int) *autoTaskCache {
	return &autoTaskCache{max: max, ll: list.New(), items: map[string]*list.Element{}, now: time.Now}
}

func (c *autoTaskCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return "", false
	}
	e := el.Value.(*autoTaskEntry)
	if c.now().After(e.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return "", false
	}
	c.ll.MoveToFront(el)
	return e.task, true
}

func (c *autoTaskCache) put(key, task string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
	}
	c.items[key] = c.ll.PushFront(&autoTaskEntry{key: key, task: task, expires: c.now().Add(ttl)})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*autoTaskEntry).key)
	}
}
