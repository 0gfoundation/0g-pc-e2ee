package openaiproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Async image E2EE (SPEC §7.5) through the gateway's HTTP layer, against a fake
// router+enclave that opens the submit for real and seals the result for real.
// What the router would do wrong is a knob on the fake (tamper), so each
// refusal in §7.5.4 is driven by an actual frame, not a mock of the opener.

const (
	asyncPinnedAddr = "0xC0FFEE0000000000000000000000000000000001"
	asyncSigner     = "0x000000000000000000000000000000000000dEaD"
	asyncSecret     = "an async secret prompt"
	asyncImage      = "aW1hZ2VieXRlcw=="
)

type asyncJob struct {
	ephPub crypto.PublicKey
	bind   []byte
}

// asyncRouter is the router and the enclave behind it, as one fake.
type asyncRouter struct {
	t       *testing.T
	encPriv crypto.PrivateKey

	mu   sync.Mutex
	jobs map[string]asyncJob
	next int
	// seen records what reached the router, so a test can assert the prompt did
	// not and the pin did.
	seenBody   []byte
	seenHeader http.Header
	seenPoll   string

	// Knobs.
	status        string // poll answer status; "" → completed
	acceptAddr    string // 202 provider_address; "" → the pin
	submitExtra   map[string]any
	tamper        func(jobID string, frame wire.Response) wire.Response
	pollStatus    int
	pollErrorBody string
}

func newAsyncRouter(t *testing.T) (*asyncRouter, crypto.PublicKey) {
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	return &asyncRouter{t: t, encPriv: encPriv, jobs: map[string]asyncJob{}}, encPub
}

func (a *asyncRouter) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/async/images/generations", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.seenBody, a.seenHeader = body, r.Header.Clone()
		a.mu.Unlock()
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		opened, err := wire.OpenRequestFor(wire.ProfileAsyncImage, a.encPriv, env)
		if err != nil {
			http.Error(w, "open: "+err.Error(), http.StatusBadRequest)
			return
		}
		bind, _, err := wire.TakeAsyncBind(opened)
		if err != nil {
			http.Error(w, "bind: "+err.Error(), http.StatusBadRequest)
			return
		}
		meta, _ := env.E2EE()
		ephPub, _ := base64.RawURLEncoding.DecodeString(meta.ClientEphPub)
		a.mu.Lock()
		a.next++
		id := "job-" + string(rune('a'+a.next))
		a.jobs[id] = asyncJob{ephPub: ephPub, bind: bind}
		a.mu.Unlock()
		addr := a.acceptAddr
		if addr == "" {
			addr = r.Header.Get("X-0G-Provider-Address")
		}
		out := map[string]any{"jobId": id, "status": "pending", "provider_address": addr}
		for k, v := range a.submitExtra {
			out[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/async/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		a.mu.Lock()
		a.seenPoll = r.URL.String()
		job, ok := a.jobs[id]
		a.mu.Unlock()
		if a.pollStatus != 0 {
			w.WriteHeader(a.pollStatus)
			_, _ = io.WriteString(w, a.pollErrorBody)
			return
		}
		if !ok {
			http.Error(w, `{"error":{"code":"async_job_not_found","message":"no"}}`, http.StatusNotFound)
			return
		}
		status := a.status
		if status == "" {
			status = "completed"
		}
		var frame wire.Response
		if status == "completed" {
			result := wire.Response{
				"jobId":     mustJSON(id),
				"status":    mustJSON("completed"),
				"createdAt": mustJSON("2026-10-14T00:00:00Z"),
				"updatedAt": mustJSON("2026-10-14T00:00:09Z"),
				"usage":     json.RawMessage(`{"output_images":1}`),
				"data":      json.RawMessage(`{"created":1,"data":[{"b64_json":"` + asyncImage + `"}]}`),
			}
			sealed, err := wire.SealAsyncImageResult(job.ephPub, result, job.bind)
			if err != nil {
				a.t.Errorf("seal result: %v", err)
				return
			}
			frame = sealed
			frame["x_0g_trace"] = json.RawMessage(`{"request_id":"r"}`)
		} else {
			frame = wire.Response{
				"jobId": mustJSON(id), "status": mustJSON(status),
				"createdAt":    mustJSON("2026-10-14T00:00:00Z"),
				"updatedAt":    mustJSON("2026-10-14T00:00:01Z"),
				"errorMessage": mustJSON("upstream said: " + asyncSecret),
				"data":         mustJSON("leak"),
			}
		}
		if a.tamper != nil {
			frame = a.tamper(id, frame)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		_ = json.NewEncoder(w).Encode(frame)
	})
	return mux
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

type asyncGateway struct {
	router *asyncRouter
	srv    *httptest.Server
	mux    *http.ServeMux
	// cleartextHit records that the url-format branch reached the passthrough.
	cleartextHit bool
}

func newAsyncGateway(t *testing.T) *asyncGateway {
	t.Helper()
	router, encPub := newAsyncRouter(t)
	srv := httptest.NewServer(router.handler())
	t.Cleanup(srv.Close)
	g := &asyncGateway{router: router, srv: srv, mux: http.NewServeMux()}
	client := core.New(core.Provider{
		URL:        srv.URL + endpoint.AsyncImage.UpstreamPath,
		EncPubKey:  encPub,
		SignerAddr: asyncSigner,
		Address:    asyncPinnedAddr,
	}, core.WithEndpoint(endpoint.AsyncImage))
	cleartext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.cleartextHit = true
		w.WriteHeader(http.StatusAccepted)
	})
	Register(g.mux, endpoint.AsyncImage, client, WithCleartext(cleartext))
	base, _ := url.Parse(srv.URL)
	g.mux.Handle("GET "+AsyncJobsPrefix+"{id}", AsyncJobPoll(base, srv.Client()))
	return g
}

func (g *asyncGateway) do(t *testing.T, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func (g *asyncGateway) submit(t *testing.T) string {
	t.Helper()
	code, out, raw := g.do(t, "POST", "/v1/async/images/generations",
		`{"model":"z-image","n":1,"prompt":"`+asyncSecret+`"}`)
	if code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", code, raw)
	}
	id, _ := out["jobId"].(string)
	return id
}

func errCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func TestAsync_RoundTrip(t *testing.T) {
	g := newAsyncGateway(t)
	userJobID := g.submit(t)

	brokerID, key, ok := strings.Cut(userJobID, ".")
	if !ok || len(key) != 43 {
		t.Fatalf("submit returned %q, want <broker id>.<43-char key>", userJobID)
	}
	if bytes.Contains(g.router.seenBody, []byte(asyncSecret)) {
		t.Error("the prompt reached the router in the clear")
	}
	if got := g.router.seenHeader.Get("X-0G-Provider-Address"); got != asyncPinnedAddr {
		t.Errorf("pin = %q", got)
	}
	if got := g.router.seenHeader.Get("X-0G-Provider-Allow-Fallbacks"); got != "false" {
		t.Errorf("Allow-Fallbacks = %q", got)
	}

	// Pending: status fields only, the job id rewritten.
	g.router.status = "processing"
	code, out, raw := g.do(t, "GET", "/v1/async/jobs/"+userJobID+"?provider_address="+asyncPinnedAddr, "")
	if code != http.StatusOK || out["status"] != "processing" || out["jobId"] != userJobID {
		t.Fatalf("pending poll: %d %s", code, raw)
	}
	for _, k := range []string{"data", "errorMessage"} {
		if _, ok := out[k]; ok {
			t.Errorf("pending answer relayed %q", k)
		}
	}
	if strings.Contains(g.router.seenPoll, key) {
		t.Error("the key segment reached the router")
	}
	if !strings.Contains(g.router.seenPoll, "/v1/async/jobs/"+brokerID+"?provider_address=") {
		t.Errorf("router was polled at %q", g.router.seenPoll)
	}

	// Completed: opened, today's shape, the job id rewritten.
	g.router.status = ""
	code, out, raw = g.do(t, "GET", "/v1/async/jobs/"+userJobID+"?provider_address="+asyncPinnedAddr, "")
	if code != http.StatusOK {
		t.Fatalf("completed poll: %d %s", code, raw)
	}
	if out["jobId"] != userJobID || out["status"] != "completed" {
		t.Errorf("jobId/status = %v/%v", out["jobId"], out["status"])
	}
	if !strings.Contains(raw, asyncImage) {
		t.Errorf("images not opened: %s", raw)
	}
	for _, k := range []string{"_e2ee", "_bind"} {
		if _, ok := out[k]; ok {
			t.Errorf("opened answer carries %q", k)
		}
	}
}

// The ways a router can lie on a poll, each refused with no content.
func TestAsync_PollTamper(t *testing.T) {
	otherEphPriv, otherEphPub, _ := crypto.GenerateRecipientKey()
	_ = otherEphPriv
	for _, tc := range []struct {
		name   string
		status string
		tamper func(*asyncRouter) func(string, wire.Response) wire.Response
		want   string
	}{
		{"router's own job sealed to the victim's key (bind mismatch)", "", func(a *asyncRouter) func(string, wire.Response) wire.Response {
			return func(id string, _ wire.Response) wire.Response {
				job := a.jobs[id]
				forged, _ := wire.SealAsyncImageResult(job.ephPub, wire.Response{
					"jobId": mustJSON(id), "status": mustJSON("completed"),
					"usage": json.RawMessage(`{"output_images":1}`),
					"data":  json.RawMessage(`{"data":[{"b64_json":"Zm9yZ2Vk"}]}`),
				}, bytes.Repeat([]byte{7}, 32))
				return forged
			}
		}, "e2ee_verification_failed"},
		{"another job's frame", "", func(a *asyncRouter) func(string, wire.Response) wire.Response {
			return func(id string, f wire.Response) wire.Response {
				f["jobId"] = mustJSON("job-other")
				return f
			}
		}, "e2ee_verification_failed"},
		{"usage edited", "", func(a *asyncRouter) func(string, wire.Response) wire.Response {
			return func(_ string, f wire.Response) wire.Response {
				f["usage"] = json.RawMessage(`{"output_images":4}`)
				return f
			}
		}, "e2ee_verification_failed"},
		{"sealed to another key", "", func(a *asyncRouter) func(string, wire.Response) wire.Response {
			return func(id string, _ wire.Response) wire.Response {
				forged, _ := wire.SealAsyncImageResult(otherEphPub, wire.Response{
					"jobId": mustJSON(id), "status": mustJSON("completed"),
					"usage": json.RawMessage(`{"output_images":1}`), "data": json.RawMessage(`{}`),
				}, a.jobs[id].bind)
				return forged
			}
		}, "e2ee_verification_failed"},
		{"cleartext result for a sealed job", "", func(a *asyncRouter) func(string, wire.Response) wire.Response {
			return func(id string, _ wire.Response) wire.Response {
				return wire.Response{"jobId": mustJSON(id), "status": mustJSON("completed"),
					"data": json.RawMessage(`{"data":[{"b64_json":"Zm9yZ2Vk"}]}`)}
			}
		}, "e2ee_downgrade"},
		{"sealed frame on a pending job", "pending", func(a *asyncRouter) func(string, wire.Response) wire.Response {
			return func(_ string, f wire.Response) wire.Response {
				f["_e2ee"] = json.RawMessage(`{"v":1}`)
				return f
			}
		}, "e2ee_malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newAsyncGateway(t)
			id := g.submit(t)
			g.router.status = tc.status
			g.router.tamper = tc.tamper(g.router)
			code, out, raw := g.do(t, "GET", "/v1/async/jobs/"+id, "")
			if code != http.StatusBadGateway || errCode(out) != tc.want {
				t.Fatalf("got %d %s, want 502 %s", code, raw, tc.want)
			}
			if strings.Contains(raw, "Zm9yZ2Vk") || strings.Contains(raw, asyncImage) || strings.Contains(raw, id) {
				t.Errorf("refusal carries content or the job id: %s", raw)
			}
		})
	}
}

func TestAsync_FailedJobRelaysOnlyAKnownCode(t *testing.T) {
	for msg, want := range map[string]string{
		"upstream_error:422":           "upstream_error:422",
		"timeout":                      "timeout",
		"broker restarted":             "broker_error",
		"rejected: " + asyncSecret:     "job_failed",
		"upstream_error:422 and more ": "job_failed",
	} {
		g := newAsyncGateway(t)
		id := g.submit(t)
		g.router.status = "failed"
		g.router.tamper = func(_ string, f wire.Response) wire.Response {
			f["errorMessage"] = mustJSON(msg)
			return f
		}
		code, out, raw := g.do(t, "GET", "/v1/async/jobs/"+id, "")
		if code != http.StatusOK || out["errorMessage"] != want {
			t.Errorf("%q: got %d %s, want errorMessage %q", msg, code, raw, want)
		}
		if _, ok := out["data"]; ok || strings.Contains(raw, asyncSecret) {
			t.Errorf("%q: failed answer leaked: %s", msg, raw)
		}
	}
}

func TestAsync_NonOKPollRelaysStatusAndCodeOnly(t *testing.T) {
	for _, tc := range []struct {
		body, want string
	}{
		{`{"error":{"code":"async_job_not_found","message":"` + asyncSecret + `"}}`, "async_job_not_found"},
		{`{"error":"provider returned status 400: ` + asyncSecret + `"}`, "upstream_error"},
		{`{"error":{"code":"Not A Code ` + asyncSecret + `"}}`, "upstream_error"},
	} {
		g := newAsyncGateway(t)
		id := g.submit(t)
		g.router.pollStatus = http.StatusBadGateway
		g.router.pollErrorBody = tc.body
		code, out, raw := g.do(t, "GET", "/v1/async/jobs/"+id, "")
		if code != http.StatusBadGateway || errCode(out) != tc.want {
			t.Errorf("got %d %s, want 502 %s", code, raw, tc.want)
		}
		if strings.Contains(raw, asyncSecret) || strings.Contains(raw, id) {
			t.Errorf("error relayed router text or the job id: %s", raw)
		}
	}
}

func TestAsync_MalformedKeyIsNotEchoed(t *testing.T) {
	g := newAsyncGateway(t)
	bad := "job-a.c2VjcmV0LWtleS1tYXRlcmlhbA"
	code, out, raw := g.do(t, "GET", "/v1/async/jobs/"+bad, "")
	if code != http.StatusBadRequest || errCode(out) != "invalid_job_id" {
		t.Fatalf("got %d %s", code, raw)
	}
	if strings.Contains(raw, "c2VjcmV0") {
		t.Errorf("the key segment was echoed: %s", raw)
	}
	if g.router.seenPoll != "" {
		t.Error("a malformed id must not reach the router")
	}
}

// A 202 that names a provider other than the pin is a job no other enclave can
// open: refused, and no job id is handed back.
func TestAsync_SubmitAcceptedElsewhereIsRefused(t *testing.T) {
	g := newAsyncGateway(t)
	g.router.acceptAddr = "0xBADBADBADBADBADBADBADBADBADBADBADBADBAD0"
	code, _, raw := g.do(t, "POST", "/v1/async/images/generations", `{"model":"z-image","prompt":"p"}`)
	if code < 500 || strings.Contains(raw, "jobId") {
		t.Fatalf("got %d %s", code, raw)
	}
}

func TestAsync_SubmitResponseCarryingE2EEIsRefused(t *testing.T) {
	g := newAsyncGateway(t)
	g.router.submitExtra = map[string]any{"_e2ee": map[string]any{"v": 1}}
	code, _, raw := g.do(t, "POST", "/v1/async/images/generations", `{"model":"z-image","prompt":"p"}`)
	if code < 500 || strings.Contains(raw, "jobId") {
		t.Fatalf("got %d %s", code, raw)
	}
}

// url format goes to the cleartext handler, unsealed (a product decision still
// open; see WithCleartext). Every other value but b64_json is refused.
func TestAsync_URLFormatGoesToCleartext(t *testing.T) {
	g := newAsyncGateway(t)
	code, _, _ := g.do(t, "POST", "/v1/async/images/generations", `{"model":"z-image","prompt":"p","response_format":"url"}`)
	if code != http.StatusAccepted || !g.cleartextHit {
		t.Fatalf("url submit: %d, cleartext reached = %v", code, g.cleartextHit)
	}
	if g.router.seenBody != nil {
		t.Error("the url submit must not be sealed")
	}
	g2 := newAsyncGateway(t)
	if code, _, _ := g2.do(t, "POST", "/v1/async/images/generations", `{"model":"z-image","prompt":"p","response_format":"png"}`); code != http.StatusBadRequest {
		t.Errorf("response_format=png: %d, want 400", code)
	}
}

func TestRedactJobPath(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/async/jobs/job-a.c2VjcmV0":  "/v1/async/jobs/job-a.<redacted>",
		"/v1/async/jobs/job-a":           "/v1/async/jobs/job-a",
		"/v1/async/jobs/a.b.c2VjcmV0":    "/v1/async/jobs/a.b.<redacted>",
		"/v1/chat/completions":           "/v1/chat/completions",
		"/v1/images/generations/x.y.zzz": "/v1/images/generations/x.y.zzz",
	} {
		if got := RedactJobPath(in); got != want {
			t.Errorf("RedactJobPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A status body's fields are relayed only in their own shape.
func TestAsync_StatusBodyFieldsAreShaped(t *testing.T) {
	g := newAsyncGateway(t)
	id := g.submit(t)
	g.router.status = "processing"
	g.router.tamper = func(_ string, f wire.Response) wire.Response {
		f["status"] = mustJSON("processing: " + asyncSecret)
		f["createdAt"] = json.RawMessage(`{"leak":"` + asyncSecret + `"}`)
		return f
	}
	code, out, raw := g.do(t, "GET", "/v1/async/jobs/"+id, "")
	if code != http.StatusOK || out["status"] != "unknown" || strings.Contains(raw, asyncSecret) {
		t.Fatalf("got %d %s", code, raw)
	}
}
