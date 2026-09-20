package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// Per-model seal routing: seal the models this deployment can actually seal, and
// proxy the rest to the router in the clear.
//
// # Why per MODEL and not per path
//
// -seal-policy is all-or-nothing, and neither end of it is where the network is.
// Only a couple of chat models have E2EE support today, so `always` fails every
// request for the rest — a model with no sealable provider gets an empty
// route-preview, which the client treats as TERMINAL and does not retry — while
// `off` gives up encryption for the models that do support it. The granularity
// that matches reality is the model, which is also the natural rollout dial:
// enable one model, watch, enable the next.
//
// This is deliberately NOT a percentage. A per-request percentage would make the
// same caller's same model sealed on one request and cleartext on the next,
// which turns a privacy guarantee into a coin toss — and it is worse than a
// privacy problem: a sealed request carrying plugins or attachments is refused
// upstream, so the draw would decide whether a legitimate request works. A sticky
// per-account percentage would be coherent, and is a separate decision for
// later; per-model is a real dial that costs none of that.
//
// # The empty list is today's behaviour
//
// No list configured means seal everything, exactly as before this existed. The
// list NARROWS an already-sealing deployment; it cannot turn sealing on where
// -seal-policy has turned it off.
//
// # Only narrow on evidence
//
// A request whose model cannot be read — a body that is not JSON, a multipart
// upload, a body over the size cap — is SEALED, i.e. handled as today. That is
// the asymmetry worth stating: "cannot tell" resolves toward sealing, never
// toward the clear.
//
// It costs nothing. A body that is not JSON is refused by the sealed path with
// the same 400 it gets today, and an oversize one with the same 413 — no prompt
// reaches the router either way. The opposite default would mean a single parse
// failure is a cleartext disclosure, which is not a trade to make for tidiness.
type sealModels struct {
	// allow is the lower-cased set of models to seal. Nil/empty means "all".
	allow map[string]struct{}
}

// parseSealModels builds the set from a comma-separated list. Entries are
// trimmed and lower-cased (model ids are matched case-insensitively, the way the
// router's own canonical-id comparison does), and empty entries are dropped so a
// trailing comma is not a model named "".
func parseSealModels(csv string) sealModels {
	allow := map[string]struct{}{}
	for _, part := range strings.Split(csv, ",") {
		if m := strings.ToLower(strings.TrimSpace(part)); m != "" {
			allow[m] = struct{}{}
		}
	}
	if len(allow) == 0 {
		return sealModels{}
	}
	return sealModels{allow: allow}
}

// all reports whether every model is sealed, i.e. no list was configured.
func (s sealModels) all() bool { return len(s.allow) == 0 }

// seals reports whether this model is one the deployment seals.
func (s sealModels) seals(model string) bool {
	if s.all() {
		return true
	}
	_, ok := s.allow[strings.ToLower(model)]
	return ok
}

// label buckets a model for the decision metric: configured models by name,
// everything else as "other". See metrics.RecordSealDecision — the raw value is
// caller-supplied, so it can never be a label.
func (s sealModels) label(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return "other"
	}
	if _, ok := s.allow[m]; ok {
		return m
	}
	return "other"
}

// dispatch returns a handler that reads each request's model and sends it to
// `sealed` or `cleartext` accordingly.
//
// A no-op when every model is sealed: the dispatcher is not mounted at all, so
// the ordinary deployment keeps the exact handler chain it had, and the body is
// not buffered on its account.
//
// # The body
//
// Deciding needs the model, the model is in the body, and both destinations need
// the body afterwards — so it is buffered and rewound. The sealed path already
// read it whole (openaiproxy.Register, capped at MaxRequestBytes), so nothing
// changes there. What DOES change is the cleartext path on these surfaces: it
// used to stream, and now it is buffered up to the same cap. That is a real
// narrowing, accepted because the cap is the sealed path's own and these are
// chat-shaped bodies.
//
// Reading one byte past the cap, rather than enforcing it here, keeps the
// oversize answer where it already lives: we learn the body is too big, decide
// "sealed", and let Register's MaxBytesReader produce the 413 it produces today.
// Enforcing it here would mean a second place that writes that error, and two
// places to keep saying the same thing.
func (s sealModels) dispatch(sealed, cleartext http.Handler) http.Handler {
	if s.all() {
		return sealed
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, err := io.ReadAll(io.LimitReader(r.Body, openaiproxy.MaxRequestBytes+1))
		// Rewind before any branch returns: whichever handler runs must see the
		// body byte-for-byte as it arrived. MultiReader covers the oversize case,
		// where r.Body still holds the remainder we did not read.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))

		// Three cases, and only the last one reaches the router.
		switch model, reason := modelOf(buf, r.Header.Get("Content-Type"), err, len(buf)); {
		case reason != "":
			// Could not tell. Seal, which is what this request got yesterday.
			metrics.RecordSealDecision(s.label(model), "sealed", reason)
			sealed.ServeHTTP(w, r)
		case s.seals(model):
			metrics.RecordSealDecision(s.label(model), "sealed", "in_allowlist")
			sealed.ServeHTTP(w, r)
		default:
			// A model we positively read and positively do not seal.
			metrics.RecordSealDecision(s.label(model), "passthrough", "not_in_allowlist")
			cleartext.ServeHTTP(w, r)
		}
	})
}

// modelOf extracts the request's model, or names the reason it could not.
//
// A non-empty reason means "do not route on this" — the caller seals. The
// reasons are a small closed set because they are a metric label.
func modelOf(body []byte, contentType string, readErr error, n int) (model, reason string) {
	switch {
	case readErr != nil:
		return "", "unreadable_body"
	case n > openaiproxy.MaxRequestBytes:
		return "", "body_too_large"
	case isMultipartContentType(contentType):
		// A multipart upload (speech today) carries its model as a form field, not
		// as JSON. Decoding it here would duplicate ep.DecodeMultipart and its
		// error surface; sealing it is what happens today, and these surfaces are
		// not what the per-model rollout is about.
		return "", "multipart_body"
	}
	var probe struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", "body_not_json"
	}
	if strings.TrimSpace(probe.Model) == "" {
		return "", "no_model_field"
	}
	return probe.Model, ""
}

// isMultipartContentType is the cheap prefix test, not a full media-type parse:
// the only decision riding on it is "skip the JSON probe", and a value this
// misjudges lands on "body_not_json", which seals — the same answer.
func isMultipartContentType(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "multipart/form-data")
}
