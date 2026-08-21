package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// staticProviderURL reads back the URL of the static provider New wrapped, so
// the default-URL assertions do not depend on the resolver's internals.
func staticProviderURL(t *testing.T, c *Client) string {
	t.Helper()
	sr, ok := c.resolver.(staticResolver)
	if !ok {
		t.Fatalf("New should install a staticResolver, got %T", c.resolver)
	}
	return sr.provider.URL
}

func TestNewDefaultsProviderURL(t *testing.T) {
	if got := staticProviderURL(t, New(Provider{})); got != DefaultProviderURL {
		t.Fatalf("empty URL: got %q, want default %q", got, DefaultProviderURL)
	}
	custom := "https://example.test/v1/chat/completions"
	if got := staticProviderURL(t, New(Provider{URL: custom})); got != custom {
		t.Fatalf("explicit URL was overridden: got %q", got)
	}
}

func TestNewDefaultsSealFields(t *testing.T) {
	if got := New(Provider{}).sealFields; !reflect.DeepEqual(got, wire.DefaultSealedFields()) {
		t.Fatalf("default seal fields = %v, want %v", got, wire.DefaultSealedFields())
	}
}

func TestNewDefaultsUnboundFields(t *testing.T) {
	if got := New(Provider{}).unboundFields; !reflect.DeepEqual(got, wire.DefaultUnboundFields()) {
		t.Fatalf("default unbound fields = %v, want %v", got, wire.DefaultUnboundFields())
	}
}

func TestWithUnboundFieldsOverrides(t *testing.T) {
	c := New(Provider{}, WithUnboundFields([]string{"x_0g_trace"}))
	if got := c.unboundFields; !reflect.DeepEqual(got, []string{"x_0g_trace"}) {
		t.Fatalf("unbound fields = %v, want [x_0g_trace]", got)
	}
}

func TestResolveErr(t *testing.T) {
	// A plain (non-*Error) resolver failure is wrapped as an upstream error.
	plain := resolveErr(errors.New("dns boom"))
	var e *Error
	if !errors.As(plain, &e) {
		t.Fatalf("resolveErr did not produce *Error: %v", plain)
	}
	if e.Stage != StageUpstream {
		t.Errorf("stage = %q, want %q", e.Stage, StageUpstream)
	}

	// An already-staged *Error passes through verbatim (same pointer).
	staged := &Error{Stage: StageRequest, Err: errors.New("no model")}
	if got := resolveErr(staged); got != staged {
		t.Errorf("staged error not passed through: got %v", got)
	}
}

func TestWithStreamUsage(t *testing.T) {
	cases := []struct {
		name string
		req  wire.Request
		want string // expected stream_options JSON, "" = field must be absent
	}{
		{
			name: "no stream field",
			req:  wire.Request{"messages": json.RawMessage(`[]`)},
			want: "",
		},
		{
			name: "stream false",
			req:  wire.Request{"stream": json.RawMessage(`false`)},
			want: "",
		},
		{
			name: "non-boolean stream left alone",
			req:  wire.Request{"stream": json.RawMessage(`"yes"`)},
			want: "",
		},
		{
			name: "stream true adds options",
			req:  wire.Request{"stream": json.RawMessage(`true`)},
			want: `{"include_usage":true}`,
		},
		{
			name: "existing options preserved, include_usage forced",
			req: wire.Request{
				"stream":         json.RawMessage(`true`),
				"stream_options": json.RawMessage(`{"include_usage":false,"foo":1}`),
			},
			want: `{"foo":1,"include_usage":true}`, // map marshal sorts keys
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := withStreamUsage(tc.req)
			got, present := out["stream_options"]
			if tc.want == "" {
				if present {
					t.Fatalf("stream_options should be absent, got %s", got)
				}
				return
			}
			if !present {
				t.Fatalf("stream_options missing, want %s", tc.want)
			}
			if string(got) != tc.want {
				t.Fatalf("stream_options = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestWithStreamUsageDoesNotMutateCaller(t *testing.T) {
	req := wire.Request{"stream": json.RawMessage(`true`)}
	_ = withStreamUsage(req)
	if _, present := req["stream_options"]; present {
		t.Fatal("withStreamUsage mutated the caller's request")
	}
}

func TestLogOpenFailureDiagnosticAndRedacted(t *testing.T) {
	_, pub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// A frame whose sealed choices hold a secret the log must never carry.
	resp := wire.Response{
		"id":      json.RawMessage(`"chatcmpl-1"`),
		"model":   json.RawMessage(`"gpt-4o"`),
		"choices": json.RawMessage(`[{"index":0,"message":{"role":"assistant","content":"the secret answer"}}]`),
	}
	sealed, err := wire.SealResponse(pub, resp, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	var buf bytes.Buffer
	c := New(Provider{}, WithDebugLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	c.logOpenFailure(3, sealed, errors.New("chacha20poly1305: message authentication failed"))

	out := buf.String()
	// The frame ordinal (first vs later frame) and the underlying cause must be
	// present — that ordinal is what separates a setup/key/AAD failure from a
	// dropped or reordered later frame. Fields are now slog attributes, so a
	// value containing spaces (the key list) is rendered quoted.
	for _, want := range []string{"frame=3", `cleartext_keys="[id model]"`, "sealed_fields=[choices]", "message authentication failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("debug log missing %q, got: %s", want, out)
		}
	}
	// Redaction: never the sealed plaintext.
	if strings.Contains(out, "secret answer") {
		t.Fatalf("debug log leaked sealed plaintext: %s", out)
	}
}

func TestLogOpenFailureNilLoggerIsNoop(t *testing.T) {
	// No debug logger configured: must not panic, even on a malformed frame.
	New(Provider{}).logOpenFailure(0, wire.Response{}, errors.New("boom"))
}

// countingHook is a MetricsHook that records how many open failures it saw, plus
// verification failures by reason, data-plane attempts by "kind/outcome",
// candidate fallbacks by reason, and stream first-frame observations.
type countingHook struct {
	n         int
	verify    map[string]int
	attempts  map[string]int
	fallbacks map[string]int
	ttff      int
}

func (h *countingHook) ResponseOpenFailure() { h.n++ }
func (h *countingHook) ResponseVerificationFailure(reason string) {
	if h.verify == nil {
		h.verify = map[string]int{}
	}
	h.verify[reason]++
}

func (h *countingHook) UpstreamAttempt(kind, outcome string, _ time.Duration) {
	if h.attempts == nil {
		h.attempts = map[string]int{}
	}
	h.attempts[kind+"/"+outcome]++
}

func (h *countingHook) StreamFirstFrame(time.Duration) { h.ttff++ }

func (h *countingHook) CandidateFallback(reason string) {
	if h.fallbacks == nil {
		h.fallbacks = map[string]int{}
	}
	h.fallbacks[reason]++
}

// The metrics hook must fire on every open failure and, critically, independently
// of the debug logger — the counter is a security signal the gateway alerts on,
// so it must not be gated on the (optional) debug diagnostics being enabled.
func TestLogOpenFailureFiresMetricsWithoutDebugLogger(t *testing.T) {
	h := &countingHook{}
	c := New(Provider{}, WithMetrics(h)) // no WithDebugLogger
	c.logOpenFailure(0, wire.Response{}, errors.New("boom"))
	c.logOpenFailure(1, wire.Response{}, errors.New("boom"))
	if h.n != 2 {
		t.Fatalf("metrics hook fired %d times, want 2", h.n)
	}
}

// stubFetcher is a SignatureFetcher that should never be reached in the
// missing-header path below (fetchSig fails before calling it).
type stubFetcher struct{}

func (stubFetcher) FetchSignature(ctx context.Context, p Provider, chatKey string) (proof.ChatSignature, error) {
	return proof.ChatSignature{}, errors.New("should not be called")
}

// A verification that cannot even fetch its proof (here: no ZG-Res-Key handle on
// the response) must count as reason "fetch" — the operational bucket, distinct
// from a signature that was fetched but did not verify.
func TestVerifyNonStreamMetersFetchFailure(t *testing.T) {
	h := &countingHook{}
	c := New(Provider{},
		WithMetrics(h),
		WithResponseVerification(stubFetcher{}, func(text string, sig []byte) (string, error) { return "", nil }),
	)
	_, err := c.verifyNonStream(context.Background(), Provider{}, http.Header{}, wire.Request{}, wire.Response{})
	if err == nil {
		t.Fatal("verifyNonStream with no ZG-Res-Key header should fail closed")
	}
	if h.verify["fetch"] != 1 || h.verify["signature"] != 0 {
		t.Fatalf("verify metrics = %v, want fetch=1 signature=0", h.verify)
	}
}

func TestSealedFieldsForFiltersByPresence(t *testing.T) {
	c := New(Provider{}, WithSealFields([]string{"messages", "tools", "metadata"}))
	req := wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[]`),
		"metadata": json.RawMessage(`{}`),
		// no "tools"
	}
	got := c.sealedFieldsFor(req)
	want := []string{"messages", "metadata"} // configured order, present only
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sealedFieldsFor = %v, want %v", got, want)
	}
}

// slowCandidates is a candidate chain whose materialization blocks until its
// context ends, recording how many candidates were reached. It stands in for a
// chain of unreachable providers — the case resolveBudget exists to bound.
type slowCandidates struct {
	n       int
	reached int
}

func (s *slowCandidates) Len() int { return s.n }

func (s *slowCandidates) Provider(ctx context.Context, i int) (Provider, error) {
	s.reached++
	<-ctx.Done()
	return Provider{}, ctx.Err()
}

// The first candidate always gets the whole budget, so the walk can never refuse
// to try anybody — a cold start with one slow provider must still reach it.
func TestCandidateWalkAlwaysTriesTheFirstCandidate(t *testing.T) {
	w := candidateWalk{budget: 50 * time.Millisecond}
	cands := &slowCandidates{n: 3}

	if _, err := w.provider(context.Background(), cands, 0); err == nil {
		t.Fatal("a materialization that ran out of budget should error")
	}
	if cands.reached != 1 {
		t.Fatalf("candidates reached = %d, want 1", cands.reached)
	}
	if !w.exhausted() {
		t.Fatal("the budget should be exhausted after a materialization that consumed it")
	}
}

// Once the budget is gone the walk reports it WITHOUT touching the resolver: every
// remaining candidate would fail the same way, and the caller is better served by
// the failure already in hand.
func TestCandidateWalkStopsWithoutCallingTheResolver(t *testing.T) {
	w := candidateWalk{budget: time.Second, spent: time.Second}
	cands := &slowCandidates{n: 5}

	_, err := w.provider(context.Background(), cands, 2)
	if err == nil {
		t.Fatal("want an error once the budget is spent, got nil")
	}
	if cands.reached != 0 {
		t.Fatalf("the resolver was called %d time(s) with no budget left; want 0", cands.reached)
	}
	var e *Error
	if !errors.As(err, &e) || e.Stage != StageUpstream {
		t.Fatalf("want a StageUpstream *Error, got %v (%T)", err, err)
	}
	if !strings.Contains(err.Error(), "budget") {
		t.Errorf("error should name the budget, got %q", err.Error())
	}
}

// The budget is shared across the chain, so a walk down several slow candidates
// costs the budget ONCE in total rather than once per candidate.
func TestCandidateWalkBudgetIsSharedAcrossCandidates(t *testing.T) {
	w := candidateWalk{budget: 50 * time.Millisecond}
	cands := &slowCandidates{n: 4}

	start := time.Now()
	for i := 0; i < cands.n; i++ {
		if _, err := w.provider(context.Background(), cands, i); err != nil && w.exhausted() {
			break
		}
	}
	elapsed := time.Since(start)

	if cands.reached != 1 {
		t.Fatalf("candidates reached = %d, want 1 (the first exhausts the shared budget)", cands.reached)
	}
	// Generous bound: the point is that the remaining candidates cost nothing, not
	// the precise timing of the one that ran.
	if elapsed > 5*time.Second {
		t.Fatalf("the walk took %s; the budget is not being shared across candidates", elapsed)
	}
}

// Time spent on an ATTEMPT is not charged to the budget — only materialization is
// — so a long, legitimate inference on the head candidate cannot starve a later
// fallback of the budget it needs to materialize.
func TestCandidateWalkChargesOnlyMaterialization(t *testing.T) {
	var w candidateWalk
	cands := staticCandidates{Provider{URL: "https://example.test"}, Provider{URL: "https://example.test"}}

	if _, err := w.provider(context.Background(), cands, 0); err != nil {
		t.Fatalf("materialize candidate 0: %v", err)
	}
	// Stand in for a long attempt against the materialized provider.
	time.Sleep(20 * time.Millisecond)
	if _, err := w.provider(context.Background(), cands, 1); err != nil {
		t.Fatalf("materialize candidate 1 after a long attempt: %v", err)
	}
	if w.exhausted() {
		t.Fatal("two instant materializations should not exhaust the budget")
	}
	if w.spent > time.Second {
		t.Errorf("spent = %s; the attempt's own duration was charged to the budget", w.spent)
	}
}

func TestUpstreamStatusOutcome(t *testing.T) {
	for status, want := range map[int]string{
		http.StatusTooManyRequests:     "http_429",
		http.StatusBadRequest:          "http_4xx",
		http.StatusUnauthorized:        "http_4xx",
		http.StatusNotFound:            "http_4xx",
		http.StatusInternalServerError: "http_5xx",
		http.StatusBadGateway:          "http_5xx",
		http.StatusServiceUnavailable:  "http_5xx",
		http.StatusMovedPermanently:    "http_other",
	} {
		if got := upstreamStatusOutcome(status); got != want {
			t.Errorf("upstreamStatusOutcome(%d) = %q, want %q", status, got, want)
		}
	}
	// 429 must never be folded into the 4xx bucket: it says "this provider is
	// saturated", not "this request was wrong", and it is the one the fallback logic
	// treats as transient.
	if upstreamStatusOutcome(http.StatusTooManyRequests) == upstreamStatusOutcome(http.StatusBadRequest) {
		t.Error("429 and 400 must not share a bucket")
	}
}

// A failure on the LAST candidate is not a fallback — there was nothing to fall
// back to. Without this the series would count every transient failure on a
// single-candidate deployment, which is the common shape.
func TestMetricFallbackOnlyWhenANextCandidateExists(t *testing.T) {
	h := &countingHook{}
	c := New(Provider{}, WithMetrics(h))

	c.metricFallback(FallbackUpstream, 0, 2) // candidate 0 of 2 — a real fallback
	c.metricFallback(FallbackUpstream, 1, 2) // the last one — not a fallback
	c.metricFallback(FallbackMaterialize, 0, 1)

	if got := h.fallbacks[FallbackUpstream]; got != 1 {
		t.Errorf("upstream fallbacks = %d, want 1", got)
	}
	if got := h.fallbacks[FallbackMaterialize]; got != 0 {
		t.Errorf("materialize fallbacks = %d, want 0 (a single-candidate chain cannot fall back)", got)
	}
}

// A nil hook is the default, and every metric call must stay a no-op under it —
// core's metering is optional and must never panic a caller that left it off.
func TestMetricCallsAreNoOpWithoutAHook(t *testing.T) {
	c := New(Provider{})
	c.metricUpstreamAttempt(UpstreamBuffered, UpstreamOK, time.Second)
	c.metricFallback(FallbackUpstream, 0, 2)
	c.metricStreamFirstFrame(time.Second)
}

// mixedCandidates materializes candidate 0 fine and blocks forever on every later
// one — the shape that exhausts the materialization budget after an attempt has
// already produced a real upstream failure.
type mixedCandidates struct {
	n int
	p Provider
}

func (m mixedCandidates) Len() int { return m.n }

func (m mixedCandidates) Provider(ctx context.Context, i int) (Provider, error) {
	if i == 0 {
		return m.p, nil
	}
	<-ctx.Done()
	return Provider{}, ctx.Err()
}

// When the budget runs out mid-walk, the caller must still be told what the
// PROVIDER said. The materialization deadline is our own bookkeeping; a 503 with a
// Retry-After (which the proxy surfaces verbatim) is what the caller can act on, so
// it must not be overwritten on the way out.
func TestBudgetExhaustionKeepsTheUpstreamError(t *testing.T) {
	// A provider whose data-plane call returns 503, so the first candidate produces a
	// real staged upstream error before the walk stalls on the second.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "provider busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	cands := mixedCandidates{n: 3, p: Provider{
		URL: srv.URL, EncPubKey: encPub, Address: "0xC0FFEE0000000000000000000000000000000001",
		SignerAddr: "0xd45b4301940B297F76d6e622c1CeA2AE660617d4",
	}}
	c := NewWithResolver(fixedResolver{cands})
	c.resolveBudgetTO = 300 * time.Millisecond // scaled; the shipped value is a minute-plus

	_, err = c.Complete(context.Background(), wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	})
	if err == nil {
		t.Fatal("want an error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %T: %v", err, err)
	}
	// The status is the whole point: a materialization timeout carries none, so a 0
	// here means the provider's reply was thrown away.
	if e.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d — the upstream reply was overwritten by our own bookkeeping error",
			e.Status, http.StatusServiceUnavailable)
	}
	if e.Header.Get("Retry-After") != "7" {
		t.Errorf("Retry-After = %q, want \"7\"", e.Header.Get("Retry-After"))
	}
}

// fixedResolver returns a prepared Candidates, so a test can control materialization.
type fixedResolver struct{ c Candidates }

func (f fixedResolver) Resolve(context.Context, wire.Request) (Candidates, error) { return f.c, nil }

// Our own provider deadline expiring during the §8 fetch is OUR timeout, not the
// broker failing to produce a proof — and the runbook reads "unverifiable" as the
// broker's account. The transport and body sites already drew this three-way split;
// the verification site did not, so it filed our timeout as somebody else's.
func TestVerifyOutcomeSeparatesOurTimeoutFromAnUnfetchableProof(t *testing.T) {
	parent := context.Background()

	expired, cancelExpired := context.WithCancel(parent)
	cancelExpired() // stands in for our attempt deadline having fired

	goneParent, cancelParent := context.WithCancel(context.Background())
	cancelParent()

	live := context.Background()

	for _, tc := range []struct {
		name            string
		parent, attempt context.Context
		concluded, want string
	}{
		{"our deadline fired", parent, expired, UpstreamUnverifiable, UpstreamTimeout},
		{"broker could not produce it", parent, live, UpstreamUnverifiable, UpstreamUnverifiable},
		{"caller went away", goneParent, expired, UpstreamUnverifiable, UpstreamCanceled},
		// An integrity finding is never re-attributed, whatever the contexts say:
		// letting a well-timed disconnect or our own deadline erase it would put the
		// one integrity signal here at the mercy of timing.
		{"signature did not verify, caller gone", goneParent, expired, UpstreamUnverified, UpstreamUnverified},
		{"signature did not verify, deadline fired", parent, expired, UpstreamUnverified, UpstreamUnverified},
		// Nor is a fault of OURS. All three cells, because only the quiet one used to
		// be covered: a binder that will not produce its text is a local failure with
		// nothing to do with either context, and re-labelling it canceled or timeout
		// files our bug in a bucket every alert ignores — the same thing the onFrame
		// site refuses to do.
		{"our own binder broke", parent, live, UpstreamInternal, UpstreamInternal},
		{"our own binder broke, caller gone", goneParent, live, UpstreamInternal, UpstreamInternal},
		{"our own binder broke, deadline fired", parent, expired, UpstreamInternal, UpstreamInternal},
	} {
		if got := verifyOutcome(tc.parent, tc.attempt, tc.concluded); got != tc.want {
			t.Errorf("%s: verifyOutcome(%q) = %q, want %q", tc.name, tc.concluded, got, tc.want)
		}
	}
}

// exhausted() is the only judge at the budget boundary, so spent must never come
// back short of the budget the deadline just consumed. It did when the clock was
// read AFTER deriving the deadline: any scheduling delay between the two fell
// outside the measurement. This runs the boundary repeatedly, since the gap it
// guards against is a few milliseconds wide.
func TestCandidateWalkSpendIsFullyChargedAtTheBoundary(t *testing.T) {
	for i := 0; i < 200; i++ {
		w := candidateWalk{budget: 2 * time.Millisecond}
		cands := &slowCandidates{n: 2}
		if _, err := w.provider(context.Background(), cands, 0); err == nil {
			t.Fatal("a blocking materialization under a spent budget should error")
		}
		if !w.exhausted() {
			t.Fatalf("iteration %d: spent %s against a %s budget — the deadline ended the "+
				"materialization but exhausted() disagrees, so the walk would try another candidate",
				i, w.spent, w.limit())
		}
	}
}
