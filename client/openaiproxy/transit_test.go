package openaiproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// transitResolver stands in for the route resolver: it answers the request's
// encrypted_transit, and for off (with a cleartext path) refuses to resolve the
// way route.Router does. Any other answer is a provider that cannot be reached,
// so a request that would have been sealed fails visibly.
type transitResolver struct {
	transit  string
	err      error
	resolved bool
}

func (t *transitResolver) Resolve(ctx context.Context, _ endpoint.Endpoint, _ wire.Request) (core.Candidates, error) {
	t.resolved = true
	if t.transit == core.TransitOff && core.CleartextFallbackFrom(ctx) {
		return nil, core.ErrEncryptedTransitOff
	}
	return nil, errors.New("sealed path reached")
}

func (t *transitResolver) EncryptedTransit(context.Context, endpoint.Endpoint, wire.Request) (string, error) {
	return t.transit, t.err
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

func serveTransit(t *testing.T, ep endpoint.Endpoint, res *transitResolver, withCleartext bool, body string) (*httptest.ResponseRecorder, *cleartextRecorder) {
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
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec, ct
}

// encrypted_transit=off: the request goes to the cleartext path, body intact,
// streaming or not, and is not a downgrade (no Reason header).
func TestTransitOff_ForwardsInTheClear(t *testing.T) {
	for _, body := range []string{
		`{"model":"glm-5","messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"glm-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`,
	} {
		rec, ct := serveTransit(t, endpoint.Chat, &transitResolver{transit: core.TransitOff}, true, body)
		if !ct.hit || rec.Code != http.StatusAccepted {
			t.Fatalf("%s: cleartext reached = %v, status %d (%s)", body, ct.hit, rec.Code, rec.Body)
		}
		if ct.body != body {
			t.Errorf("forwarded body = %q, want it exactly as sent", ct.body)
		}
		if got := rec.Header().Get(HeaderEncryptedTransitReason); got != "" {
			t.Errorf("Reason = %q on cleartext the caller asked for, want none", got)
		}
	}
}

// Without a cleartext path (the sidecar) off is sealed anyway: it permits
// plaintext, it does not demand it.
func TestTransitOff_NoCleartextPathSeals(t *testing.T) {
	res := &transitResolver{transit: core.TransitOff}
	rec, _ := serveTransit(t, endpoint.Chat, res, false, `{"model":"glm-5","messages":[{"role":"user","content":"hi"}]}`)
	if !res.resolved || rec.Code == http.StatusAccepted {
		t.Fatalf("status %d: want the sealed path's answer", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "encrypted_transit is off") {
		t.Errorf("the off sentinel leaked to the caller: %s", rec.Body)
	}
}

// An async submit asking for a URL cannot be sealed: required refuses it with
// the documented code, preferred (or a router that sends no value) downgrades
// it and says why, off forwards it without calling it a downgrade.
func TestTransit_UnsealableAsyncURL(t *testing.T) {
	const body = `{"model":"z-image","prompt":"p","response_format":"url"}`

	rec, ct := serveTransit(t, endpoint.AsyncImage, &transitResolver{transit: core.TransitRequired}, true, body)
	if rec.Code != http.StatusBadRequest || ct.hit {
		t.Fatalf("required: status %d, cleartext reached = %v", rec.Code, ct.hit)
	}
	var out map[string]map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"]["code"] != "encrypted_transit_unsupported_feature" || out["error"]["param"] != "response_format" {
		t.Errorf("required: error = %v", out["error"])
	}
	if !strings.Contains(rec.Body.String(), "b64_json") {
		t.Errorf("required: the error should say how to send it sealed: %s", rec.Body)
	}

	for _, policy := range []string{core.TransitPreferred, ""} {
		rec, ct = serveTransit(t, endpoint.AsyncImage, &transitResolver{transit: policy}, true, body)
		if !ct.hit || ct.body != body {
			t.Fatalf("%q: cleartext reached = %v, body %q", policy, ct.hit, ct.body)
		}
		if got := rec.Header().Get(HeaderEncryptedTransitReason); got != "response_format=url" {
			t.Errorf("%q: Reason = %q, want response_format=url", policy, got)
		}
	}

	rec, ct = serveTransit(t, endpoint.AsyncImage, &transitResolver{transit: core.TransitOff}, true, body)
	if !ct.hit || rec.Header().Get(HeaderEncryptedTransitReason) != "" {
		t.Errorf("off: cleartext reached = %v, Reason = %q", ct.hit, rec.Header().Get(HeaderEncryptedTransitReason))
	}
}

// The router answering the policy preview with an error is relayed (the
// request would get it anyway); a router that cannot be reached leaves the
// request to go out as before, where the router enforces required itself.
func TestTransit_UnsealablePolicyErrors(t *testing.T) {
	const body = `{"model":"z-image","prompt":"p","response_format":"url"}`
	answered := &core.Error{Stage: core.StageUpstream, Status: http.StatusServiceUnavailable,
		Err:  errors.New("route preview returned 503"),
		Body: `{"error":{"message":"none","code":"no_provider_for_encrypted_transit"}}`}
	rec, ct := serveTransit(t, endpoint.AsyncImage, &transitResolver{err: answered}, true, body)
	if rec.Code != http.StatusServiceUnavailable || ct.hit || !strings.Contains(rec.Body.String(), "no_provider_for_encrypted_transit") {
		t.Errorf("router answered: status %d, cleartext %v, body %s", rec.Code, ct.hit, rec.Body)
	}

	unreachable := &core.Error{Stage: core.StageUpstream, Err: errors.New("dial: refused")}
	rec, ct = serveTransit(t, endpoint.AsyncImage, &transitResolver{err: unreachable}, true, body)
	if !ct.hit || rec.Header().Get(HeaderEncryptedTransitReason) != "response_format=url" {
		t.Errorf("router unreachable: cleartext %v, Reason %q", ct.hit, rec.Header().Get(HeaderEncryptedTransitReason))
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
