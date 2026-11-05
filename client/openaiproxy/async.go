package openaiproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Async image E2EE (SPEC §7.5). The submit is sealed like the sync image
// request and answers 202 with a job id that carries the response key; the
// result is opened when that id is polled. The router sees the job id without
// its key segment and never the key.

// AsyncJobsPrefix is the poll route's prefix. Every async job, sealed or not,
// whatever its modality, is polled under it.
const AsyncJobsPrefix = "/v1/async/jobs/"

// maxPollResponseBytes bounds the read of a poll answer. A completed sealed
// image frame is ≈1.78× the raw images, and the router reads the broker's
// answer through a 32 MiB cap, so anything past this is not a poll answer.
const maxPollResponseBytes = 48 << 20

// pollTimeout bounds one poll round trip. A poll does no inference: it reads
// a stored result.
const pollTimeout = 2 * time.Minute

// WithCleartext gives a surface the handler a request it will not seal is sent
// to: the cleartext passthrough. Three kinds of request go there, and only the
// caller's own X-0G-Encrypted-Transit header (callerTransit) or a field it sent
// can put one there — never a value the router reports:
//
//   - the caller's header says off: forwarded as sent, without a preview;
//   - the caller's header says preferred, and none of the request's candidates
//     could be prepared for sealing before anything was sent
//     (core.ErrNoEncryptedProvider) — unless the router says required;
//   - an async submit asking for `response_format: "url"`, which cannot be
//     served sealed (the images would be published outside the channel, SPEC
//     §7.1). It always went out in the clear; now it is refused instead under
//     required, from the caller's header or the router (see serveUnsealable).
//
// Each is marked plaintext; the last two, which are downgrades, also carry
// HeaderEncryptedTransitReason.
func WithCleartext(h http.Handler) Option {
	return func(o *options) { o.cleartext = h }
}

// registerAsync mounts an async surface's submit. Same body handling as the
// sync surfaces (Register), then core.SubmitAsync instead of Complete.
func registerAsync(mux *http.ServeMux, ep endpoint.Endpoint, c *core.Client, o options) {
	mux.HandleFunc("POST "+ep.Path, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		if err != nil {
			readBodyError(w, err)
			return
		}
		// The caller asked for plaintext in its own header (see Register).
		if o.cleartext != nil && callerTransit(r) == core.TransitOff {
			o.forwardOff(w, r, body)
			return
		}
		var req wire.Request
		if err := json.Unmarshal(body, &req); err != nil || req == nil {
			writeGatewayError(w, http.StatusBadRequest, "request body is not a JSON object")
			return
		}
		if wantsURLFormat(req) && o.cleartext != nil {
			o.serveUnsealable(w, r, c, req, body, "response_format", "url",
				`use "response_format": "b64_json" to receive the images inside the encrypted channel`)
			return
		}
		stream, err := streamRequested(req)
		if err != nil {
			writeGatewayError(w, http.StatusBadRequest, err.Error())
			return
		}
		if stream {
			writeGatewayError(w, http.StatusBadRequest, "field \"stream\" is not supported for POST "+ep.Path+": the response is a job id")
			return
		}
		if ep.PreSeal != nil {
			if req, err = ep.PreSeal(req); err != nil {
				writeGatewayError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		ctx := core.WithCredential(r.Context(), credential(r))
		ctx = core.WithForwardedHeaders(ctx, routingHeaders(r.Header))
		meta := &core.ResponseMeta{}
		ctx = core.WithResponseMeta(ctx, meta)
		fallback := o.transitFallback(w, r, body)
		if fallback != nil {
			ctx = core.WithPlaintextPermitted(ctx)
		}
		resp, status, err := c.SubmitAsync(ctx, req)
		if fallback != nil && fallback(err) {
			return // not a completion; see Register
		}
		recordCompletion(err)
		if err != nil {
			o.writeError(w, err)
			return
		}
		out, err := json.Marshal(resp)
		if err != nil {
			writeGatewayError(w, http.StatusInternalServerError, "encode response")
			return
		}
		setPassthrough(w, meta.Header)
		setProvider(w, meta)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(out)
	})
}

// serveUnsealable handles a request this surface cannot seal because of one of
// its fields (field=value). Such a request always went to the router in the
// clear; it still does, marked with HeaderEncryptedTransitReason, unless the
// requirement is required — from the caller's own header, or from the router's
// value, which it asks for with one route-preview (the router may tighten,
// never loosen) — and then it is refused with 400
// encrypted_transit_unsupported_feature, naming the field and how to send it
// sealed (hint). A router value this build does not know reads as required
// (route.normalizeTransit; and the default arm below for a resolver that does
// not fold it).
//
// A definitive answer from the router to that preview — a 4xx, or its own 503
// no_provider_for_encrypted_transit — is relayed: the request would get it
// anyway. Anything else (a 5xx left after retries, a router that cannot be
// reached) leaves the request to go out as it did before there was a preview;
// the router refuses a plaintext request under required itself.
func (o options) serveUnsealable(w http.ResponseWriter, r *http.Request, c *core.Client, req wire.Request, body []byte, field, value, hint string) {
	reason := field + "_" + value
	policy := callerTransit(r)
	label := policy // the metric's policy; bounded by metrics.EncryptedTransitDecision
	if policy != core.TransitRequired {
		ctx := core.WithCredential(r.Context(), credential(r))
		ctx = core.WithForwardedHeaders(ctx, routingHeaders(r.Header))
		routerPolicy, err := c.EncryptedTransit(ctx, req)
		switch {
		case err == nil:
			if routerPolicy != core.TransitOff && routerPolicy != core.TransitPreferred && routerPolicy != "" {
				// required, or a value this build does not know (labelled unknown).
				policy, label = core.TransitRequired, routerPolicy
			}
		case definitivePreviewError(err):
			o.writeError(w, err)
			return
		}
	}
	if policy == core.TransitRequired {
		metrics.EncryptedTransitDecision("refused", label, reason)
		writeErrorObject(w, http.StatusBadRequest, map[string]any{
			"error": map[string]any{
				"message": fmt.Sprintf("%s %q cannot be sent end-to-end encrypted, and encrypted_transit is required: %s", field, value, hint),
				"type":    "invalid_request_error",
				"param":   field,
				"code":    "encrypted_transit_unsupported_feature",
			},
			"_0g": map[string]any{"source": "gateway"},
		})
		return
	}
	metrics.EncryptedTransitDecision("plaintext", label, reason)
	w.Header().Set(HeaderEncryptedTransitReason, field+"="+value)
	forwardCleartext(w, r, body, o.cleartext)
}

// definitivePreviewError reports whether a route-preview failure is the router
// answering for this request, and so worth relaying rather than routing
// around: a 4xx (the caller's credential, the request's shape, a header laxer
// than the key's rule), or the router's own 503 no_provider_for_encrypted_transit.
// A 5xx otherwise, or no answer at all, says nothing about the request.
func definitivePreviewError(err error) bool {
	var ce *core.Error
	if !errors.As(err, &ce) {
		return false
	}
	switch {
	case ce.Status >= 400 && ce.Status < 500:
		return true
	case ce.Status == http.StatusServiceUnavailable:
		obj, ok := parseUpstreamErrorObject(ce.Body)
		return ok && obj["code"] == "no_provider_for_encrypted_transit"
	}
	return false
}

// wantsURLFormat reports whether the request asks for `response_format: "url"`.
func wantsURLFormat(req wire.Request) bool {
	var f string
	return json.Unmarshal(req["response_format"], &f) == nil && f == "url"
}

// HasJobKey reports whether a poll path's job id carries a key segment, i.e.
// whether the poll is for a job this gateway sealed.
func HasJobKey(r *http.Request) bool {
	return wire.HasUserJobIDKey(r.PathValue("id"))
}

// RedactJobPath returns path with the key segment of a polled job id removed,
// for anything that prints a path: a full user job id is a credential (SPEC
// §7.5.3). Any path that is not a poll is returned unchanged.
//
// It matches the prefix case-insensitively and cuts at the FIRST "." after it:
// the access log sees the path as sent, before any spelling is folded, and a
// broker job id has no "." of its own, so everything from the first one on may
// be key material (a trailing slash or a sub-path after the key included).
func RedactJobPath(path string) string {
	if len(path) <= len(AsyncJobsPrefix) || !strings.EqualFold(path[:len(AsyncJobsPrefix)], AsyncJobsPrefix) {
		return path
	}
	rest := path[len(AsyncJobsPrefix):]
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		return path[:len(AsyncJobsPrefix)] + rest[:i] + ".<redacted>"
	}
	return path
}

// AsyncJobPoll serves GET /v1/async/jobs/{id} for an id carrying a key segment
// (SPEC §7.5.4): the key is cut off, the broker's id is polled on the router,
// and the answer is opened, checked and reshaped. Nothing the router returns is
// relayed verbatim — a status body is reduced to its status fields, a result
// must open under the key and carry the request's binding, and an error is
// reduced to its HTTP status and a known code.
//
// routerBase is the router's origin (and base path); hc carries the request.
func AsyncJobPoll(routerBase *url.URL, hc *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userJobID := r.PathValue("id")
		jobID, ephPriv, err := wire.ParseUserJobID(userJobID)
		if err != nil {
			// The error names what is wrong with the id and never echoes it.
			writeAsyncError(w, http.StatusBadRequest, "gateway", "invalid_job_id", "job id: "+err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), pollTimeout)
		defer cancel()
		// jobID is [A-Za-z0-9_-] (ParseUserJobID checked it), so it needs no escaping.
		target := routerBase.JoinPath(AsyncJobsPrefix, jobID)
		target.RawQuery = r.URL.RawQuery
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			writeAsyncError(w, http.StatusInternalServerError, "gateway", "internal_error", "build poll request")
			return
		}
		if cred := credential(r); cred != "" {
			req.Header.Set("Authorization", cred)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			writeAsyncError(w, http.StatusBadGateway, "upstream", "upstream_error", "upstream request failed")
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPollResponseBytes+1))
		if err != nil || len(body) > maxPollResponseBytes {
			writeAsyncError(w, http.StatusBadGateway, "upstream", "upstream_error", "poll response unreadable or too large")
			return
		}
		status, out := asyncPollAnswer(userJobID, jobID, ephPriv, resp.StatusCode, body)
		if ra := resp.Header.Get("Retry-After"); ra != "" && status == http.StatusOK {
			w.Header().Set("Retry-After", ra)
		}
		writeErrorObject(w, status, out)
	})
}

// knownCode is the shape of a router error code or a sealed job's failure
// code: a short machine token. A body that is not one is never relayed.
var knownCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// knownJobFailure is the set of fixed codes a sealed job's errorMessage may be
// (SPEC §7.5.2). Anything else is replaced, since a router or a misbehaving
// broker could put upstream text there.
var knownJobFailure = regexp.MustCompile(`^(upstream_error(:[1-5][0-9]{2})?|timeout|broker_error)$`)

// asyncPollAnswer is the poll matrix of SPEC §7.5.4 for a keyed poll, as a pure
// function of the router's answer: the HTTP status and body to return.
func asyncPollAnswer(userJobID, jobID string, ephPriv []byte, status int, body []byte) (int, map[string]any) {
	if status < 200 || status > 299 {
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		code := "upstream_error"
		if json.Unmarshal(body, &env) == nil && knownCode.MatchString(env.Error.Code) {
			code = env.Error.Code
		}
		return status, asyncErrorBody("upstream", code, "the router answered the poll with "+http.StatusText(status))
	}

	var frame wire.Response
	if err := json.Unmarshal(body, &frame); err != nil || frame == nil {
		return http.StatusBadGateway, asyncErrorBody("upstream", "invalid_poll_response", "poll response is not a JSON object")
	}
	var jobStatus string
	_ = json.Unmarshal(frame["status"], &jobStatus)
	_, sealed := frame["_e2ee"]

	switch {
	case sealed && jobStatus == wire.AsyncStatusCompleted:
		opened, err := wire.OpenAsyncImageResult(ephPriv, frame, jobID)
		if err != nil {
			// The frame was not produced by the enclave this job was sealed to, for
			// this request (or was altered on the way): no content is returned.
			return http.StatusBadGateway, asyncErrorBody("upstream", "e2ee_verification_failed", "the job result failed end-to-end verification and was refused")
		}
		out := make(map[string]any, len(opened))
		for k, v := range opened {
			out[k] = v
		}
		out["jobId"] = userJobID
		return http.StatusOK, out
	case sealed:
		return http.StatusBadGateway, asyncErrorBody("upstream", "e2ee_malformed", "a sealed frame was returned for a job that is not completed")
	case jobStatus == wire.AsyncStatusCompleted:
		// A sealed job's result is always a frame. A cleartext one is either a
		// fault or a result the router made up.
		return http.StatusBadGateway, asyncErrorBody("upstream", "e2ee_downgrade", "the job result was not end-to-end encrypted and was refused")
	}

	// Not a frame: a status body. Reduced to the fields that say where the job
	// is and nothing else — it is cleartext and unauthenticated — and those only
	// in the shape they have: a status is a short token, a timestamp a string.
	if !knownCode.MatchString(jobStatus) {
		jobStatus = "unknown"
	}
	out := map[string]any{"jobId": userJobID, "status": jobStatus}
	for _, k := range []string{"createdAt", "updatedAt"} {
		var ts string
		if json.Unmarshal(frame[k], &ts) == nil && len(ts) <= 64 {
			out[k] = ts
		}
	}
	if jobStatus == "failed" {
		var msg string
		_ = json.Unmarshal(frame["errorMessage"], &msg)
		switch {
		case knownJobFailure.MatchString(msg):
		case msg == "broker restarted":
			msg = "broker_error"
		default:
			msg = "job_failed"
		}
		out["errorMessage"] = msg
	}
	return http.StatusOK, out
}

func asyncErrorBody(source, code, msg string) map[string]any {
	return map[string]any{
		"error": map[string]any{"message": msg, "type": source + "_error", "code": code},
		"_0g":   map[string]any{"source": source},
	}
}

func writeAsyncError(w http.ResponseWriter, status int, source, code, msg string) {
	writeErrorObject(w, status, asyncErrorBody(source, code, msg))
}
