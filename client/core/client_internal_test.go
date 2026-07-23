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
