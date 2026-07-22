package core

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func TestNewDefaultsProviderURL(t *testing.T) {
	if got := New(Provider{}).provider.URL; got != DefaultProviderURL {
		t.Fatalf("empty URL: got %q, want default %q", got, DefaultProviderURL)
	}
	custom := "https://example.test/v1/chat/completions"
	if got := New(Provider{URL: custom}).provider.URL; got != custom {
		t.Fatalf("explicit URL was overridden: got %q", got)
	}
}

func TestNewDefaultsSealFields(t *testing.T) {
	if got := New(Provider{}).sealFields; !reflect.DeepEqual(got, wire.DefaultSealedFields()) {
		t.Fatalf("default seal fields = %v, want %v", got, wire.DefaultSealedFields())
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
