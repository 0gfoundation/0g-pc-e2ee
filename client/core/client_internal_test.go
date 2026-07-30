package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
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

// countingHook is a MetricsHook that records how many open failures it saw.
type countingHook struct{ n int }

func (h *countingHook) ResponseOpenFailure() { h.n++ }

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
