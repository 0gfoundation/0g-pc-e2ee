package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
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
// A request whose model cannot be read — a body that is not JSON, one over the
// size cap, one that names no model — is SEALED, i.e. handled as today. That is
// the asymmetry worth stating: "cannot tell" resolves toward sealing, never
// toward the clear.
//
// What that asymmetry costs is NOT the same for every reason, and an earlier
// version of this comment flattened three different situations into one
// "it costs nothing". The three:
//
//   - A body that is already broken — not JSON, no model field, unreadable,
//     multipart this cannot parse. The sealed path refuses it with the same 400
//     it gets today, so sealing really is free: no prompt reaches the router
//     either way, and the opposite default would make a single parse failure a
//     cleartext disclosure.
//   - A body over openaiproxy.MaxRequestBytes. Sealing is NOT free here — a
//     passthrough would have streamed it, and instead the caller gets a 413.
//     It is still right, because routing needs the model and reading further to
//     find it is exactly what the cap exists to prevent (computeMaxInFlight
//     derives the memory ceiling from it). We genuinely cannot tell, so we seal.
//     Note the consequence rather than hiding it: sealed surfaces carry a 10 MiB
//     cap the router itself does not, whatever the model list says.
//   - A multipart body. This one was simply MISFILED in the first bucket. A
//     transcription request is WELL-FORMED and works today; sealing it does not
//     refuse a broken request, it breaks a working one, and unlike the oversize
//     case we CAN tell — the model is right there in a form field. So it is
//     parsed rather than bucketed as unknown; see modelOfMultipart.
//
// # A name only does something on a SEALED SURFACE
//
// The list is consulted by the dispatcher, and the dispatcher is mounted only on
// the surfaces in endpoint.All. A name for anything else — /v1/embeddings,
// /v1/completions — is a silent no-op: those paths go to the catch-all proxy,
// which never asks this type anything, so the entry sits in the set and is never
// matched. Nothing logs it and no metric moves.
//
// That ordering is not an oversight to work around by adding the name early. A
// surface gets sealed by gaining a row in endpoint.All and a seal path (see the
// note on newRouterProxy); only then does naming its models mean anything.
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
// The identity function when every model is sealed: it hands back `sealed`
// untouched, so the ordinary deployment keeps the exact handler chain it had and
// nothing is buffered on its account.
//
// # Where this must be mounted, and why it is not negotiable
//
// BEHIND the credential gate and the in-flight cap — see the chain in
// newHandler. Deciding requires reading the body, so mounting this in front of
// those guards means an unauthenticated or shed request gets buffered first and
// refused second. That breaks LimitInFlight's stated contract (a request
// "rejected on shape alone … must not consume a slot") and the memory ceiling
// computeMaxInFlight derives from it, and with no ReadTimeout on these servers
// a slow body could hold that buffer indefinitely while holding no slot.
//
// The marker rides along correctly because MarkE2EE uses Set, not Add: the
// outer layer stamps "sealed" for the whole chain and the cleartext branch,
// which carries its own marker, overwrites it to "none" on the way out.
//
// # The body
//
// Deciding needs the model, the model is in the body, and both destinations need
// the body afterwards — so it is buffered and rewound. The sealed path already
// read it whole (openaiproxy.Register, capped at MaxRequestBytes), so nothing
// changes there. What DOES change is the cleartext path on these surfaces: it
// used to stream, and now it is buffered up to the same cap. That is a real
// narrowing, accepted because the cap is the sealed path's own and these are
// chat-shaped bodies — and because being inside the cap is what keeps that
// memory inside the ceiling.
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
		return modelOfMultipart(body, contentType)
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

// modelOfMultipart reads the "model" form field out of a multipart body, which
// is how the transcription surface names its model — it is the one sealed
// surface whose caller does not speak JSON (see endpoint.Speech).
//
// This exists because bucketing multipart as "cannot tell" is not the free
// choice the other reasons are. A transcription request is well-formed and
// works; sealing it on a deployment that seals only chat models turns a working
// request into a terminal failure, since a model with no sealable provider gets
// an empty route-preview and no retry. Reading the one field it turns on costs a
// walk over bytes already in memory.
//
// It reads only the field, not the audio: every other part is skipped, and Close
// discards the remainder rather than materializing it. That is also why it is
// not endpoint.speechDecodeMultipart — that one base64s the whole file to build
// the object the profile seals, which is the sealed path's job and far more work
// than a routing decision needs.
//
// Anything it cannot parse falls back to the sealing side, so the asymmetry the
// type comment states survives for bodies that really are unreadable.
func modelOfMultipart(body []byte, contentType string) (model, reason string) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return "", "multipart_unreadable"
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			// Walked every part and none was the model.
			return "", "no_model_field"
		}
		if err != nil {
			return "", "multipart_unreadable"
		}
		// FormName is the Content-Disposition `name`, and "" for a part that is
		// not form-data at all. Matching is case-sensitive, as form field names
		// are: a part called "Model" is not found, and the request seals. Note it
		// does NOT exclude parts carrying a filename, so a file part that called
		// itself "model" would be read as one — harmless, since the audio part is
		// called "file" and a request with no "file" part fails upstream anyway.
		//
		// A repeated model part resolves to the first; the upstream may pick the
		// last, but the only caller who can arrange that is the one whose own
		// prompt is at stake, and the marker says which way it went.
		if part.FormName() != fieldModel {
			part.Close()
			continue
		}
		// One byte past the cap so an oversize value is detected rather than
		// truncated into a different model name.
		v, err := io.ReadAll(io.LimitReader(part, maxModelFieldBytes+1))
		part.Close()
		if err != nil || len(v) > maxModelFieldBytes {
			return "", "multipart_unreadable"
		}
		if m := strings.TrimSpace(string(v)); m != "" {
			return m, ""
		}
		return "", "no_model_field"
	}
}

const (
	// fieldModel is the multipart part naming the model, same spelling as the
	// JSON field.
	fieldModel = "model"
	// maxModelFieldBytes bounds what is read from that part. A model id is a
	// short token; a part this size is not one, and reading it whole would let a
	// caller decide how much the routing decision allocates.
	maxModelFieldBytes = 512
)

// isMultipartContentType is the cheap prefix test, not a full media-type parse:
// it only decides whether to try the multipart reader instead of the JSON probe.
// A value it misjudges in either direction lands on a reason that seals —
// "body_not_json" one way, "multipart_unreadable" the other — so the mistake
// costs a sealed request, never a cleartext one.
func isMultipartContentType(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "multipart/form-data")
}
