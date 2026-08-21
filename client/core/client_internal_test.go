package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
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
	budgetCut int
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

func (h *countingHook) WalkBudgetExhausted() { h.budgetCut++ }

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

// A FAILED attempt is charged to the walk. This test used to assert the opposite —
// that attempts are never charged — which was the reasoning that left the walk
// unbounded: with materialization cached and free, exhausted() never tripped and the
// loop ran to the router's candidate count, N x providerTimeout of the caller's time.
// See resolveBudget for why "a long inference must not starve a later fallback" was
// the wrong way round.
func TestCandidateWalkChargesFailedAttempts(t *testing.T) {
	w := candidateWalk{budget: 50 * time.Millisecond}
	cands := staticCandidates{Provider{URL: "https://example.test"}, Provider{URL: "https://example.test"}}

	// Materialization is instant here (a static candidate), so without charging the
	// attempt nothing would ever be spent.
	if _, err := w.provider(context.Background(), cands, 0); err != nil {
		t.Fatalf("materialize candidate 0: %v", err)
	}
	if w.exhausted() {
		t.Fatal("an instant materialization should not exhaust the budget")
	}
	w.charge(60 * time.Millisecond) // stands in for an attempt that failed slowly
	if !w.exhausted() {
		t.Fatalf("spent %s against a %s budget: a failed attempt must count", w.spent, w.limit())
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

// slowFailCandidates materializes instantly (so only attempt time can be charged)
// and every attempt against it fails after a fixed delay — the shape of a provider
// that returns 200 headers and then withholds the body until the deadline.
type slowFailCandidates struct {
	n       int
	p       Provider
	reached int
}

func (c *slowFailCandidates) Len() int { return c.n }

func (c *slowFailCandidates) Provider(_ context.Context, i int) (Provider, error) {
	c.reached++
	return c.p, nil
}

// End to end, and the reproduction that showed the walk was unbounded: N candidates
// whose attempts each burn wall clock. Before failed attempts were charged, all N
// ran. Now the budget stops the walk, and the ceiling is budget + one attempt rather
// than N x it — with N itself capped by route.maxPreviewCandidates.
func TestWalkStopsOnceFailedAttemptsSpendTheBudget(t *testing.T) {
	const attemptCost = 120 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 headers, then withhold the body until the client's deadline — the
		// io.ReadAll stall that returns retry=true.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(attemptCost):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	// A real enc key: without one the seal fails before any attempt is made and this
	// test would pass while exercising nothing (it did, at first — "1/8 in 0s").
	cands := &slowFailCandidates{n: 8, p: Provider{
		URL: srv.URL, EncPubKey: encPub,
		Address:    "0xC0FFEE0000000000000000000000000000000001",
		SignerAddr: "0xd45b4301940B297F76d6e622c1CeA2AE660617d4",
	}}
	c := NewWithResolver(fixedResolver{cands})
	c.resolveBudgetTO = 200 * time.Millisecond

	start := time.Now()
	if _, err := c.Complete(context.Background(), wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}); err == nil {
		t.Fatal("want an error from a chain that never answers")
	}
	elapsed := time.Since(start)

	if cands.reached >= cands.n {
		t.Errorf("walked all %d candidates; the budget did not bound the walk", cands.n)
	}
	if cands.reached == 0 {
		t.Fatal("no candidate was tried at all")
	}
	// Guard against the vacuous version of this test: if the seal or the request
	// failed before reaching the server, no attempt time was spent and the budget
	// was never the thing that stopped the walk.
	if elapsed < attemptCost {
		t.Fatalf("walk took only %s, less than one attempt (%s) — the attempts never ran",
			elapsed, attemptCost)
	}
	// The stated ceiling: the budget, plus the one attempt that was already running
	// when it ran out. Generous slack for scheduling; the point is that it is not
	// n x attemptCost.
	if ceiling := c.resolveBudgetTO + attemptCost; elapsed > ceiling+400*time.Millisecond {
		t.Errorf("walk took %s over %d candidates, past the budget+one-attempt ceiling of %s",
			elapsed, cands.reached, ceiling)
	}
	t.Logf("stopped after %d/%d candidates in %s (ceiling %s)",
		cands.reached, cands.n, elapsed.Truncate(time.Millisecond), c.resolveBudgetTO+attemptCost)
}

// The failure the caller is told about must be the most useful one seen. Three tiers,
// because they answer different questions — and a flat "whatever we already hold
// wins", which is what this started as, let a budget cut hide behind an early
// bookkeeping error and made a 90s ceiling undiagnosable.
func TestWalkErrTiers(t *testing.T) {
	mat1 := &Error{Stage: StageUpstream, Err: errors.New("no usable address")}
	mat2 := &Error{Stage: StageUpstream, Err: errors.New("pubkey fetch failed")}
	budget := budgetErr(90*time.Second, errors.New("context deadline exceeded"))
	attempt := &Error{Stage: StageUpstream, Status: 503, Err: errors.New("provider busy")}

	t.Run("a provider's reply outranks everything", func(t *testing.T) {
		var w walkErr
		w.record(tierAttempt, attempt)
		w.record(tierMaterialize, mat1)
		w.record(tierBudget, budget)
		if w.err != error(attempt) {
			t.Errorf("got %v, want the provider's reply", w.err)
		}
	})
	t.Run("the budget outranks bookkeeping", func(t *testing.T) {
		var w walkErr
		w.record(tierMaterialize, mat1)
		w.record(tierBudget, budget)
		if w.err != budget {
			t.Errorf("got %v, want the budget error — a 90s cut must say so", w.err)
		}
		if !strings.Contains(w.err.Error(), "budget") {
			t.Errorf("the budget error does not name the budget: %v", w.err)
		}
	})
	t.Run("within a tier the later one wins", func(t *testing.T) {
		var w walkErr
		w.record(tierMaterialize, mat1)
		w.record(tierMaterialize, mat2)
		if w.err != error(mat2) {
			t.Errorf("got %v, want the later failure — the earliest is the least informative", w.err)
		}
	})
}

// failThenUnpreparable answers candidate 0 (whose attempt will 503) and refuses to
// prepare every later one, quickly and for a reason that is not the budget.
type failThenUnpreparable struct {
	n int
	p Provider
}

func (c failThenUnpreparable) Len() int { return c.n }

func (c failThenUnpreparable) Provider(_ context.Context, i int) (Provider, error) {
	if i == 0 {
		return c.p, nil
	}
	return Provider{}, &Error{Stage: StageUpstream, Err: errors.New("pubkey fetch failed")}
}

// End to end: the caller must still receive the 503 and its Retry-After, not the
// bookkeeping error from the candidate we could not prepare afterwards.
func TestUnpreparableCandidateDoesNotDisplaceTheProvidersReply(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "provider busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	c := NewWithResolver(fixedResolver{failThenUnpreparable{n: 3, p: Provider{
		URL: srv.URL, EncPubKey: encPub,
		Address:    "0xC0FFEE0000000000000000000000000000000001",
		SignerAddr: "0xd45b4301940B297F76d6e622c1CeA2AE660617d4",
	}}})

	_, err = c.Complete(context.Background(), wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	})
	if err == nil {
		t.Fatal("want an error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %T", err)
	}
	if e.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want 503 — the provider's reply was displaced", e.Status)
	}
	if e.Header.Get("Retry-After") != "7" {
		t.Errorf("Retry-After = %q, want \"7\"", e.Header.Get("Retry-After"))
	}
}

// One fault must not split across two buckets by kind. A provider that accepts the
// connection and never answers is a timeout however it is noticed: the buffered
// path's context deadline, or the transport's ResponseHeaderTimeout, which is all
// the streaming path has since its context carries no deadline of its own.
func TestUpstreamFailureOutcomeAgreesAcrossMechanisms(t *testing.T) {
	live := context.Background()
	expired, cancelExpired := context.WithCancel(context.Background())
	cancelExpired()
	goneParent, cancelParent := context.WithCancel(context.Background())
	cancelParent()

	netTimeout := &net.OpError{Op: "read", Err: timeoutErr{}}

	for _, tc := range []struct {
		name            string
		parent, attempt context.Context
		err             error
		base, want      string
	}{
		// The buffered shape: our per-attempt context deadline noticed.
		{"context deadline", live, expired, context.DeadlineExceeded, UpstreamTransport, UpstreamTimeout},
		// The streaming shape: no context deadline exists, so only the transport can
		// notice. Same fault, and it must land in the same bucket.
		{"transport timeout, no context deadline", live, live, netTimeout, UpstreamTransport, UpstreamTimeout},
		// A genuine unreachable provider stays transport.
		{"connection refused", live, live, errors.New("connect: connection refused"), UpstreamTransport, UpstreamTransport},
		// The caller outranks both.
		{"caller gone", goneParent, expired, netTimeout, UpstreamTransport, UpstreamCanceled},
		// The same judgement serves the body-read site, with its own base.
		{"body dropped", live, live, errors.New("unexpected EOF"), UpstreamBody, UpstreamBody},
		{"body read timed out", live, live, netTimeout, UpstreamBody, UpstreamTimeout},
	} {
		if got := upstreamFailureOutcome(tc.parent, tc.attempt, tc.err, tc.base); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// timeoutErr is a net.Error that reports a timeout, the shape ResponseHeaderTimeout
// surfaces as.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// blockingCandidates never finishes materializing, so the caller's disconnect is
// what ends each one. reached counts how far the walk got.
type blockingCandidates struct {
	n       int
	reached int
}

func (c *blockingCandidates) Len() int { return c.n }

func (c *blockingCandidates) Provider(ctx context.Context, i int) (Provider, error) {
	c.reached++
	<-ctx.Done()
	return Provider{}, ctx.Err()
}

// A caller that goes away is not a fallback and says nothing about the router's
// ranking. Without a break the loop ground on through every remaining candidate,
// each failing instantly on the dead context, each counted — one disconnect booked
// seven materialize fallbacks on an eight-candidate chain, into the series
// documented as the only signal that the router ranks badly, with an alert on it.
func TestCallerDisconnectIsNotAFallback(t *testing.T) {
	h := &countingHook{}
	cands := &blockingCandidates{n: 8}
	c := NewWithResolver(fixedResolver{cands}, WithMetrics(h))

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()

	if _, err := c.Complete(ctx, wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}); err == nil {
		t.Fatal("want an error once the caller goes away")
	}

	if got := h.fallbacks[FallbackMaterialize]; got != 0 {
		t.Errorf("materialize fallbacks = %d, want 0 — a disconnect was filed as bad routing", got)
	}
	if cands.reached != 1 {
		t.Errorf("candidates reached = %d, want 1 — the walk spun through the dead chain", cands.reached)
	}
	if h.budgetCut != 0 {
		t.Errorf("budget cuts = %d, want 0 — the caller left, the ceiling did not fire", h.budgetCut)
	}
}

// A slow retryable failure on the LAST candidate is not a ceiling cut. At an
// attempt site the budget's only effect is to stop the walk from moving on — a
// running attempt is never cut short by it — so when there is nothing to move on
// to, the ceiling truncated nothing and the loop was ending regardless. Counting
// it books every request whose upstream is slower than resolveBudget (90s, against
// a 630s provider timeout) as OUR limit firing, in the one series the runbook says
// means exactly that, and tells operators to read against latency p99: the false
// correlation it would itself manufacture. Same reasoning as metricFallback's
// i+1 < n guard, added for the same single-candidate shape.
func TestSlowFailureOnTheLastCandidateIsNotABudgetCut(t *testing.T) {
	const attemptCost = 80 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(attemptCost):
		case <-r.Context().Done():
			return
		}
		http.Error(w, "provider busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	h := &countingHook{}
	cands := &slowFailCandidates{n: 1, p: Provider{
		URL: srv.URL, EncPubKey: encPub,
		Address:    "0xC0FFEE0000000000000000000000000000000001",
		SignerAddr: "0xd45b4301940B297F76d6e622c1CeA2AE660617d4",
	}}
	c := NewWithResolver(fixedResolver{cands}, WithMetrics(h))
	c.resolveBudgetTO = 20 * time.Millisecond // spent by the one attempt, and only then

	if _, err := c.Complete(context.Background(), wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}); err == nil {
		t.Fatal("want the provider's 503")
	}

	// Guard the vacuous version: without the attempt actually running and failing
	// retryably, the budget branch under test is never reached.
	if got := h.attempts[UpstreamBuffered+"/"+UpstreamHTTP5xx]; got != 1 {
		t.Fatalf("buffered/http_5xx attempts = %d, want 1 — the 503 attempt never ran", got)
	}
	if len(h.fallbacks) != 0 {
		t.Errorf("fallbacks = %v, want none — there was no next candidate", h.fallbacks)
	}
	if h.budgetCut != 0 {
		t.Errorf("budget cuts = %d, want 0 — a slow failure on the last candidate is not the ceiling firing", h.budgetCut)
	}
}

// The streaming walk makes the same call at the same place, so it needs the same
// guard: the two loops are mirrors and a rule applied to one of them is the
// recurring shape of this whole change.
func TestStreamSlowFailureOnTheLastCandidateIsNotABudgetCut(t *testing.T) {
	const attemptCost = 80 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(attemptCost):
		case <-r.Context().Done():
			return
		}
		http.Error(w, "provider busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	h := &countingHook{}
	cands := &slowFailCandidates{n: 1, p: Provider{
		URL: srv.URL, EncPubKey: encPub,
		Address:    "0xC0FFEE0000000000000000000000000000000001",
		SignerAddr: "0xd45b4301940B297F76d6e622c1CeA2AE660617d4",
	}}
	c := NewWithResolver(fixedResolver{cands}, WithMetrics(h))
	c.resolveBudgetTO = 20 * time.Millisecond

	err = c.CompleteStream(context.Background(), wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}, func(wire.Response) error { return nil })
	if err == nil {
		t.Fatal("want the provider's 503")
	}

	if got := h.attempts[UpstreamStream+"/"+UpstreamHTTP5xx]; got != 1 {
		t.Fatalf("stream/http_5xx attempts = %d, want 1 — the 503 attempt never ran", got)
	}
	if h.budgetCut != 0 {
		t.Errorf("budget cuts = %d, want 0 — a slow failure on the last candidate is not the ceiling firing", h.budgetCut)
	}
}

// quickFailThenBlock fails candidate 0 fast with the least informative error there
// is, then blocks — the combination that used to return "no usable address" for a
// request held the whole budget.
type quickFailThenBlock struct{ n int }

func (c quickFailThenBlock) Len() int { return c.n }

func (c quickFailThenBlock) Provider(ctx context.Context, i int) (Provider, error) {
	if i == 0 {
		return Provider{}, &Error{Stage: StageUpstream, Err: errors.New("no usable address")}
	}
	<-ctx.Done()
	return Provider{}, ctx.Err()
}

// A request cut at the ceiling must SAY so, and be counted. Before, an early
// bookkeeping error outranked the budget error and the cut was invisible in both the
// message and the metrics — a hard 90s limit with nothing to diagnose it by.
func TestBudgetCutIsVisibleInBothErrorAndMetric(t *testing.T) {
	h := &countingHook{}
	c := NewWithResolver(fixedResolver{quickFailThenBlock{n: 4}}, WithMetrics(h))
	c.resolveBudgetTO = 100 * time.Millisecond

	_, err := c.Complete(context.Background(), wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "budget") {
		t.Errorf("error does not mention the budget that cut the request: %v", err)
	}
	if h.budgetCut != 1 {
		t.Errorf("budget cuts = %d, want 1", h.budgetCut)
	}
}
