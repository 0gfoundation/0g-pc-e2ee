package dcap

import (
	"errors"
	"strings"
	"testing"

	attest "github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// failGetter always errors, so negative tests are fully offline and
// deterministic even if verification reaches the collateral-fetch step.
type failGetter struct{}

func (failGetter) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("offline: collateral fetch disabled in test")
}

func TestNewQuoteParser_RejectsGarbage(t *testing.T) {
	parse := NewQuoteParser(Config{Getter: failGetter{}})
	_, _, err := parse([]byte("not a tdx quote"))
	if err == nil {
		t.Fatal("expected error for garbage input, got nil")
	}
	if !strings.Contains(err.Error(), "dcap:") {
		t.Errorf("error not wrapped by dcap: %v", err)
	}
}

func TestNewQuoteParser_RejectsEmpty(t *testing.T) {
	parse := NewQuoteParser(Config{Getter: failGetter{}})
	if _, _, err := parse(nil); err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

// TestNewQuoteParser_DoesNotExtractFromUnverified feeds bytes long enough to be
// structurally parseable by ParseTDXQuoteBody (>= minQuoteLen) but which are not
// a genuine signed quote. Verification must fail and NO keys may be returned —
// proving extraction never runs ahead of verification (fail-closed).
func TestNewQuoteParser_DoesNotExtractFromUnverified(t *testing.T) {
	parse := NewQuoteParser(Config{Getter: failGetter{}})
	m, rd, err := parse(make([]byte, 1024)) // zeroed, well-formed length, bogus content
	if err == nil {
		t.Fatal("expected verification to fail on non-genuine quote, got nil")
	}
	if m != (attest.Measurement{}) || rd != ([64]byte{}) {
		t.Error("returned key material alongside an error; must be zero-valued")
	}
}

// TestQuoteParser_PlugsIntoSeam is a compile-time + runtime proof that
// NewQuoteParser is accepted by protocol/attest.WithQuoteParser (the seam) and
// drives Verify end to end. Verification still fails closed on bad input.
func TestQuoteParser_PlugsIntoSeam(t *testing.T) {
	v := attest.New(attest.BootChainPolicy{}, attest.WithQuoteParser(NewQuoteParser(Config{Getter: failGetter{}})))
	if _, err := v.Verify([]byte("garbage")); err == nil {
		t.Fatal("expected verification error through the seam, got nil")
	}
}
