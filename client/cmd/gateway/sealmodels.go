package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
)

// Per-model seal routing: seal the models this deployment can actually seal, and
// proxy the rest to the router in the clear.
//
// # Why per MODEL and not per path
//
// All-or-nothing is not where the network is. Only a couple of chat models have
// E2EE support today, so sealing everything fails every request for the rest — a
// model with no sealable provider gets an empty route-preview, which the client
// treats as TERMINAL and does not retry — while sealing nothing gives up
// encryption for the models that do support it. The granularity
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
// # The two ends: `*` and empty
//
// `*` (the built-in default) seals every model, so a gateway that says nothing
// keeps sealing rather than silently stopping. An EMPTY value seals nothing: every sealed
// surface — its path, its subtree and its POST — is proxied to the router in the
// clear, marked X-0G-E2EE: none, and this gateway behaves as the plain router.
//
// Sealing nothing exists for the global-entry cutover. Pointing router-api.0g.ai at a gateway
// that seals unconditionally would, in one DNS change, also turn on default
// encryption for everybody: the provider pool narrows to the sealable ones, web
// search and file attachments break by construction
// (SealedPromptInjectionConflict), and every request pays a route-preview plus an
// HPKE seal. DNS cutover is a deploy; the sealing default is a release.
//
// These used to be a separate -seal-policy switch (`always` | `off`) beside this
// list, which made one dial two knobs whose combinations had to be explained.
// Empty used to mean "seal everything"; it now means the opposite, and the default
// moved to `*` so an unset variable still seals. Only a value SET to empty turns
// sealing off — which is why the compose interpolates it with `${VAR-…}`, not
// `${VAR:-…}`: the colon form would replace a deliberate empty with the default.
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
// the surfaces in endpoint.All. A name for anything else — /v1/completions,
// say — is a silent no-op: such paths go to the catch-all proxy, which never
// asks this type anything, so the entry sits in the set and is never matched.
// Nothing logs it and no metric moves.
//
// That ordering is not an oversight to work around by adding the name early. A
// surface gets sealed by gaining a row in endpoint.All and a seal path (see the
// note on newRouterProxy); only then does naming its models mean anything.
//
// # A whole service type: `<service type>:*`
//
// An entry such as `embedding:*` seals every request on the surfaces of that
// router service type, whatever the model. It is for a service type whose whole
// fleet serves the profile, so listing its models one by one would only add a
// way to forget one. The decision is made on the path, before the body is read.
//
// `*` never appears in a model id, so a model id containing `:` (`qwen3:8b`)
// is still an ordinary entry. A `:*` entry naming no row's service type is
// refused at startup rather than ignored: a typo there would leave the whole
// surface in the clear.
//
// The zero value seals every model, which is what `*` parses to.
type sealModels struct {
	// off reports that nothing is sealed (an empty -seal-models).
	off bool
	// allow is the lower-cased set of models to seal. See all() for what an
	// empty list means.
	allow map[string]struct{}
	// surfaces maps a sealed surface's path to the `<service type>:*` entry that
	// claimed it, which is also the entry's metric label.
	surfaces map[string]string
}

const (
	// sealModelsAll seals every model; the built-in default.
	sealModelsAll = "*"
	// sealModelsNone seals nothing.
	sealModelsNone = ""
)

// surfaceWildcard is the suffix that turns an entry into a whole-service-type one.
const surfaceWildcard = ":*"

// parseSealModels builds the set from -seal-models: `*`, empty, or a
// comma-separated list. Entries are trimmed and lower-cased (model ids are matched
// case-insensitively, the way the router's own canonical-id comparison does), and
// empty entries are dropped so a trailing comma is not a model named "" — which
// also means a value of nothing but separators is empty, and seals nothing.
//
// It refuses rather than guesses, because the question is "is this encrypted":
//
//   - `*` mixed with anything else, which says two things at once.
//   - A `<service type>:*` entry naming no surface, which would leave that surface
//     in the clear while reading as configured.
func parseSealModels(csv string) (sealModels, error) {
	var s sealModels
	var entries []string
	for _, part := range strings.Split(csv, ",") {
		if m := strings.ToLower(strings.TrimSpace(part)); m != "" {
			entries = append(entries, m)
		}
	}
	switch {
	case len(entries) == 0:
		s.off = true
		return s, nil
	case len(entries) > 1 && slices.Contains(entries, sealModelsAll):
		return s, fmt.Errorf("%q stands alone and cannot be combined with other entries", sealModelsAll)
	case entries[0] == sealModelsAll:
		return s, nil
	}
	var unknown []string
	for _, m := range entries {
		switch {
		case strings.HasSuffix(m, surfaceWildcard):
			serviceType := strings.TrimSuffix(m, surfaceWildcard)
			matched := false
			for _, ep := range endpoint.All {
				if ep.ServiceType == serviceType {
					if s.surfaces == nil {
						s.surfaces = map[string]string{}
					}
					s.surfaces[ep.Path] = m
					matched = true
				}
			}
			if !matched {
				unknown = append(unknown, m)
			}
		default:
			if s.allow == nil {
				s.allow = map[string]struct{}{}
			}
			s.allow[m] = struct{}{}
		}
	}
	if len(unknown) > 0 {
		var known []string
		for _, ep := range endpoint.All {
			if e := ep.ServiceType + surfaceWildcard; !slices.Contains(known, e) {
				known = append(known, e)
			}
		}
		return sealModels{}, fmt.Errorf("no sealed surface has the service type of %v; want one of %v", unknown, known)
	}
	return s, nil
}

// all reports whether every model is sealed, i.e. no list was configured. It says
// nothing about off, which is decided before dispatch is ever mounted.
func (s sealModels) all() bool {
	return len(s.allow) == 0 && len(s.surfaces) == 0
}

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

// maxPassthroughBytes caps a request body this gateway forwards to the router in
// the clear — a model it does not seal. Twice the sealed cap (MaxRequestBytes), for
// chat turns that carry a video to a model with no E2EE support; see dispatch for
// why the two branches can afford different caps. The router applies its own
// per-route cap after it (chatBodyCap), so raising this alone admits nothing the
// router would refuse.
//
// Against the derived in-flight cap (inflight.go), which prices a request at
// 3 x MaxRequestBytes = 30 MiB: a cleartext request at this cap holds the buffer
// plus io.ReadAll's growth slack, up to about 40 MiB. That is over the per-request
// price but well under what a sealed request at its own cap was measured at, so
// the sealed path, not this one, still sets the worst case.
const maxPassthroughBytes = 20 << 20 // 20 MiB

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
// computeMaxInFlight derives from it, and with only the listener's 90 s
// ReadTimeout backstop out there a slow body could hold that buffer that long
// while holding no slot.
//
// The marker rides along correctly because MarkE2EE uses Set, not Add: the
// outer layer stamps "sealed" for the whole chain and the cleartext branch,
// which carries its own marker, overwrites it to "none" on the way out.
//
// # The body
//
// Deciding needs the model, the model is in the body, and both destinations need
// the body afterwards — so it is buffered and rewound, up to maxPassthroughBytes.
// The sealed path already read it whole (openaiproxy.Register, capped at
// MaxRequestBytes), so nothing changes there. What DOES change is the cleartext
// path on these surfaces: it used to stream, and now it is buffered up to its own
// cap — inside the in-flight cap, which is what keeps that memory inside the
// ceiling.
//
// Two caps, because the two branches cost different amounts. A sealed request is
// parsed, sealed and base64'd, measured at roughly 7-13x its body
// (inflight.go), and the router sees it about a third larger again; a cleartext
// one is this one buffer, handed to the router as it is. So a body between the
// two caps is fine for a model this deployment forwards (a chat turn carrying a
// video, for a model with no E2EE support) and refused for one it seals.
//
// Reading one byte past the cleartext cap, rather than enforcing either cap here,
// keeps the oversize answer where it already lives: a body past it reads as "body
// too large", is decided "sealed", and Register's MaxBytesReader produces the 413
// it produces today; a sealed model's body past MaxRequestBytes reaches the same
// 413 by being sealed. Enforcing it here would mean a second place that writes
// that error, and two places to keep saying the same thing.
func (s sealModels) dispatch(sealed, cleartext http.Handler) http.Handler {
	if s.all() {
		return sealed
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The path is canonical here: sealedNamespaceGuard folds its spellings
		// before the mux, and the trailing-slash route rewrites to the bare path.
		if entry, ok := s.surfaces[r.URL.Path]; ok {
			metrics.RecordSealDecision(entry, "sealed", "surface_in_allowlist")
			sealed.ServeHTTP(w, r)
			return
		}
		buf, err := io.ReadAll(io.LimitReader(r.Body, maxPassthroughBytes+1))
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
	case n > maxPassthroughBytes:
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
