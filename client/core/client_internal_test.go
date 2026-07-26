package core

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

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
