package attest

import (
	"strings"
	"testing"
)

func TestDecodeQuoteResponse_Valid(t *testing.T) {
	raw, err := DecodeQuoteResponse([]byte(`{"quote":"0a0b0c","extra":"ignored"}`))
	if err != nil {
		t.Fatalf("DecodeQuoteResponse: %v", err)
	}
	if want := []byte{0x0a, 0x0b, 0x0c}; string(raw) != string(want) {
		t.Errorf("raw = %x, want %x", raw, want)
	}
}

func TestDecodeQuoteResponse_Errors(t *testing.T) {
	cases := map[string]string{
		"not json":      `not json`,
		"missing quote": `{"event_log":"[]"}`,
		"empty quote":   `{"quote":""}`,
		"bad hex":       `{"quote":"xyz"}`,
	}
	for name, body := range cases {
		if _, err := DecodeQuoteResponse([]byte(body)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestDecodeQuoteResponse_IgnoresUnsignedFields documents that the trusted path
// reads only "quote"; unsigned convenience fields (tcb_info, event_log, …) are
// not decoded into the struct and cannot influence it.
func TestDecodeQuoteResponse_IgnoresUnsignedFields(t *testing.T) {
	body := `{"quote":"00","tcb_info":"{\"mrtd\":\"deadbeef\"}","event_log":"[]"}`
	raw, err := DecodeQuoteResponse([]byte(body))
	if err != nil {
		t.Fatalf("DecodeQuoteResponse: %v", err)
	}
	if len(raw) != 1 || raw[0] != 0 {
		t.Errorf("raw = %x, want 00", raw)
	}
	if strings.Contains(string(raw), "deadbeef") {
		t.Error("tcb_info leaked into decoded quote")
	}
}
