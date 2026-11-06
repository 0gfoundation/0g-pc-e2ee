package openaiproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// transitResolver stands in for the route resolver. transit is what the ROUTER
// says, returned as-is (not normalized, so a resolver that does not fold values
// is covered too). Resolve hands back candidates none of which can be prepared
// for sealing, carrying transit — nothing is ever sent — so a request either
// downgrades or fails visibly. previewed records the policy preview.
type transitResolver struct {
	transit   string
	err       error
	resolved  bool
	previewed bool
}

func (t *transitResolver) Resolve(context.Context, endpoint.Endpoint, wire.Request) (core.Candidates, error) {
	t.resolved = true
	return unsealableCands{t.transit}, nil
}

func (t *transitResolver) EncryptedTransit(context.Context, endpoint.Endpoint, wire.Request) (string, error) {
	t.previewed = true
	return t.transit, t.err
}

// unsealableCands: two candidates, neither with a key to seal to.
type unsealableCands struct{ transit string }

func (unsealableCands) Len() int                   { return 2 }
func (u unsealableCands) EncryptedTransit() string { return u.transit }
func (unsealableCands) Provider(context.Context, int) (core.Provider, error) {
	return core.Provider{}, errors.New("no key to seal to")
}

// cleartextRecorder is the passthrough: it records the body it was handed.
type cleartextRecorder struct {
	hit  bool
	body string
}

func (c *cleartextRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.hit = true
	b, _ := io.ReadAll(r.Body)
	c.body = string(b)
	w.WriteHeader(http.StatusAccepted)
}

// serveTransit sends body to ep's sealed handler, with the caller's
// X-0G-Encrypted-Transit header set to callerHeader ("" = absent).
func serveTransit(t *testing.T, ep endpoint.Endpoint, res *transitResolver, withCleartext bool, callerHeader, body string) (*httptest.ResponseRecorder, *cleartextRecorder) {
	t.Helper()
	mux := http.NewServeMux()
	ct := &cleartextRecorder{}
	var opts []Option
	if withCleartext {
		opts = append(opts, WithCleartext(ct))
	}
	Register(mux, ep, core.NewWithResolver(res, core.WithEndpoint(ep)), opts...)
	req := httptest.NewRequest(http.MethodPost, ep.Path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("Content-Type", "application/json")
	if callerHeader != "" {
		req.Header.Set(HeaderEncryptedTransit, callerHeader)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec, ct
}

const (
	transitChat   = `{"model":"glm-5","messages":[{"role":"user","content":"hi"}]}`
	transitStream = `{"model":"glm-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	transitAsync  = `{"model":"z-image","prompt":"p"}`
	transitURL    = `{"model":"z-image","prompt":"p","response_format":"url"}`
)

// The caller's own header saying off: forwarded as sent, at once (no preview,
// nothing sealed), and not called a downgrade.
func TestTransit_CallerOffForwards(t *testing.T) {
	for _, tc := range []struct {
		ep   endpoint.Endpoint
		body string
	}{{endpoint.Chat, transitChat}, {endpoint.Chat, transitStream}, {endpoint.AsyncImage, transitAsync}, {endpoint.AsyncImage, transitURL}} {
		res := &transitResolver{transit: core.TransitRequired}
		rec, ct := serveTransit(t, tc.ep, res, true, " Off ", tc.body)
		if !ct.hit || ct.body != tc.body || res.resolved || res.previewed {
			t.Fatalf("%s: cleartext %v body %q, resolved %v, previewed %v", tc.body, ct.hit, ct.body, res.resolved, res.previewed)
		}
		if got := rec.Header().Get(HeaderEncryptedTransitReason); got != "" {
			t.Errorf("%s: Reason = %q, want none", tc.body, got)
		}
	}
	// Without a cleartext path (the sidecar) the header is not acted on.
	res := &transitResolver{transit: core.TransitOff}
	if _, ct := serveTransit(t, endpoint.Chat, res, false, "off", transitChat); ct.hit || !res.resolved {
		t.Error("no cleartext path: the request must take the sealed path")
	}
}

// The router alone cannot make a request go out in the clear: its off or
// preferred, with no permission from the caller, leaves the sealed path's own
// error — the cleartext handler is never called.
func TestTransit_RouterAloneNeverDowngrades(t *testing.T) {
	for _, routerSays := range []string{core.TransitOff, core.TransitPreferred, ""} {
		for _, body := range []string{transitChat, transitStream} {
			rec, ct := serveTransit(t, endpoint.Chat, &transitResolver{transit: routerSays}, true, "", body)
			if ct.hit || rec.Code < 400 {
				t.Errorf("router %q, %s: cleartext %v, status %d; want the walk's error", routerSays, body, ct.hit, rec.Code)
			}
		}
		if _, ct := serveTransit(t, endpoint.AsyncImage, &transitResolver{transit: routerSays}, true, "", transitAsync); ct.hit {
			t.Errorf("router %q, async: cleartext reached", routerSays)
		}
	}
	// A malformed caller header permits nothing either.
	if _, ct := serveTransit(t, endpoint.Chat, &transitResolver{transit: core.TransitPreferred}, true, "sometimes", transitChat); ct.hit {
		t.Error("a malformed header must not permit a downgrade")
	}
}

// The caller's header saying preferred, nothing could be sealed, nothing sent:
// downgraded, body intact, marked no_encrypted_provider — unless the router
// says required, which vetoes it.
func TestTransit_CallerPreferredDowngrades(t *testing.T) {
	for _, tc := range []struct {
		ep   endpoint.Endpoint
		body string
	}{{endpoint.Chat, transitChat}, {endpoint.Chat, transitStream}, {endpoint.AsyncImage, transitAsync}} {
		for _, routerSays := range []string{core.TransitPreferred, "", core.TransitOff} {
			rec, ct := serveTransit(t, tc.ep, &transitResolver{transit: routerSays}, true, "preferred", tc.body)
			if !ct.hit || ct.body != tc.body {
				t.Fatalf("router %q, %s: cleartext %v body %q (status %d %s)", routerSays, tc.body, ct.hit, ct.body, rec.Code, rec.Body)
			}
			if got := rec.Header().Get(HeaderEncryptedTransitReason); got != "no_encrypted_provider" {
				t.Errorf("router %q, %s: Reason = %q", routerSays, tc.body, got)
			}
		}
		rec, ct := serveTransit(t, tc.ep, &transitResolver{transit: core.TransitRequired}, true, "preferred", tc.body)
		if ct.hit || rec.Code < 400 {
			t.Errorf("router required, %s: cleartext %v, status %d; want no downgrade", tc.body, ct.hit, rec.Code)
		}
	}
}

// An async submit asking for a URL went out in the clear before; it still
// does, marked, unless either side says required.
func TestTransit_UnsealableAsyncURL(t *testing.T) {
	for _, routerSays := range []string{core.TransitPreferred, "", core.TransitOff} {
		rec, ct := serveTransit(t, endpoint.AsyncImage, &transitResolver{transit: routerSays}, true, "", transitURL)
		if !ct.hit || ct.body != transitURL || rec.Header().Get(HeaderEncryptedTransitReason) != "response_format=url" {
			t.Errorf("router %q: cleartext %v, Reason %q", routerSays, ct.hit, rec.Header().Get(HeaderEncryptedTransitReason))
		}
	}

	refused := func(rec *httptest.ResponseRecorder, ct *cleartextRecorder) bool {
		var out map[string]map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code == http.StatusBadRequest && !ct.hit &&
			out["error"]["code"] == "encrypted_transit_unsupported_feature" && out["error"]["param"] == "response_format" &&
			strings.Contains(rec.Body.String(), "b64_json")
	}
	if rec, ct := serveTransit(t, endpoint.AsyncImage, &transitResolver{transit: core.TransitRequired}, true, "", transitURL); !refused(rec, ct) {
		t.Errorf("router required: status %d %s", rec.Code, rec.Body)
	}
	res := &transitResolver{transit: core.TransitOff}
	if rec, ct := serveTransit(t, endpoint.AsyncImage, res, true, "required", transitURL); !refused(rec, ct) || res.previewed {
		t.Errorf("caller required: status %d, previewed %v", rec.Code, res.previewed)
	}
}

// A value this build does not know, from a resolver that did not fold it, is
// refused like required — never downgraded — and labelled unknown.
func TestTransit_UnknownPolicyIsNotADowngrade(t *testing.T) {
	const series = `zg_gateway_encrypted_transit_decisions_total{outcome="refused",policy="unknown",reason="response_format_url"}`
	before := scrapeMetric(t, series)
	rec, ct := serveTransit(t, endpoint.AsyncImage, &transitResolver{transit: "strict"}, true, "", transitURL)
	if rec.Code != http.StatusBadRequest || ct.hit {
		t.Errorf("status %d, cleartext reached = %v; want the required refusal", rec.Code, ct.hit)
	}
	if d := scrapeMetric(t, series) - before; d != 1 {
		t.Errorf("refused/unknown delta = %v, want 1", d)
	}
}

// Only a definitive preview answer is relayed (a 4xx, the router's 503
// no_provider_for_encrypted_transit). A 5xx otherwise, or no answer at all,
// leaves the url submit to go out as it did before there was a preview.
func TestTransit_UnsealablePolicyErrors(t *testing.T) {
	upstream := func(status int, body string) *core.Error {
		return &core.Error{Stage: core.StageUpstream, Status: status, Err: errors.New("route preview failed"), Body: body}
	}
	for name, tc := range map[string]struct {
		err     error
		relayed int
	}{
		"401":                     {upstream(401, `{"error":{"message":"bad key","code":"invalid_api_key"}}`), 401},
		"503 no encrypted supply": {upstream(503, `{"error":{"message":"none","code":"no_provider_for_encrypted_transit"}}`), 503},
		"502 after retries":       {upstream(502, `bad gateway`), 0},
		"503 other":               {upstream(503, `{"error":{"message":"busy","code":"no_available_provider"}}`), 0},
		"unreachable":             {upstream(0, ``), 0},
	} {
		rec, ct := serveTransit(t, endpoint.AsyncImage, &transitResolver{err: tc.err}, true, "", transitURL)
		switch {
		case tc.relayed != 0 && (rec.Code != tc.relayed || ct.hit):
			t.Errorf("%s: status %d, cleartext %v; want %d relayed", name, rec.Code, ct.hit, tc.relayed)
		case tc.relayed == 0 && (!ct.hit || rec.Header().Get(HeaderEncryptedTransitReason) != "response_format=url"):
			t.Errorf("%s: cleartext %v (status %d); want it forwarded as before", name, ct.hit, rec.Code)
		}
	}
}

// MarkE2EE stamps the new header alongside the old one, and they agree.
func TestMarkE2EE_TransitStatus(t *testing.T) {
	for value, want := range map[string]string{E2EEValueSealed: TransitStatusEncrypted, E2EEValueNone: TransitStatusPlaintext} {
		rec := httptest.NewRecorder()
		MarkE2EE(value, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Header().Get(HeaderE2EE) != value || rec.Header().Get(HeaderEncryptedTransitStatus) != want {
			t.Errorf("%s: X-0G-E2EE %q, Status %q, want %q", value, rec.Header().Get(HeaderE2EE), rec.Header().Get(HeaderEncryptedTransitStatus), want)
		}
	}
	h := http.Header{}
	h.Set(HeaderE2EE, "sealed")
	h.Set(HeaderEncryptedTransitStatus, "encrypted")
	h.Set(HeaderEncryptedTransitReason, "x")
	StripTransitHeaders(h)
	if len(h) != 0 {
		t.Errorf("StripTransitHeaders left %v", h)
	}
}

// scrapeMetric reads one series from the process registry (0 when absent).
// Counters are process-global, so tests read a delta.
func scrapeMetric(t *testing.T, series string) float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if v, ok := strings.CutPrefix(line, series+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				t.Fatalf("parsing %q: %v", line, err)
			}
			return f
		}
	}
	return 0
}
