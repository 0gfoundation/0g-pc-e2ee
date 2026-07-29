package attest

import (
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

// Expected values decoded from the real dstack quote in
// testdata/dstack_quote_prefix.json — the KAT cross-checks our structural
// extraction against the provider's own tcb_info decode and the §4.2 report_data.
const (
	vecMRTD  = "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217"
	vecRTMR0 = "b2de1841af6de2472a3682135b2df9f69ef61231395ff3b7fdbf911d3bfb913c26ed93e43947e37d53316f9d3e99cfa5"
	vecRTMR1 = "b598fde9491427341bc4683b75d10d3e36770af3a36a6954d8b6b7b22aa66358f13e1f172e51b7d6e6710d99a8d8532f"
	vecRTMR2 = "c812d42bfff1c75382e91a37c867ab117b97eb5e8d6797488928ea38e5fd38b5ed2f87d9613d392507f1c3af94657c93"
	vecRTMR3 = "d9bd03da555cf06092605287e274b7e03b1786b7388e9c5cde539e87e9b98a01bd3f4498cd414824c639968bf9f5c925"

	vecEncPub = "4b2ca0d43e4c6a25ebe0995a65ead819e78c6db879a609309804f1dc4e09894d"
	vecSigner = "0xd45b4301940b297f76d6e622c1cea2ae660617d4"
)

// loadRealQuote reads the KAT fixture and returns the raw quote bytes.
func loadRealQuote(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/dstack_quote_prefix.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	raw, err := DecodeQuoteResponse(body)
	if err != nil {
		t.Fatalf("DecodeQuoteResponse: %v", err)
	}
	return raw
}

func TestParseTDXQuoteBody_RealVector(t *testing.T) {
	b, err := ParseTDXQuoteBody(loadRealQuote(t))
	if err != nil {
		t.Fatalf("ParseTDXQuoteBody: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"MRTD", b.Measurement.MRTD[:], vecMRTD},
		{"RTMR0", b.Measurement.RTMR0[:], vecRTMR0},
		{"RTMR1", b.Measurement.RTMR1[:], vecRTMR1},
		{"RTMR2", b.Measurement.RTMR2[:], vecRTMR2},
		{"RTMR3", b.Measurement.RTMR3[:], vecRTMR3},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}

	// report_data extracted structurally must decode per §4.2 to the bound keys.
	rd, err := ParseReportData(b.ReportData[:])
	if err != nil {
		t.Fatalf("ParseReportData: %v", err)
	}
	if got := hex.EncodeToString(rd.EncPub); got != vecEncPub {
		t.Errorf("EncPub = %s, want %s", got, vecEncPub)
	}
	if rd.SignerAddr != vecSigner {
		t.Errorf("SignerAddr = %s, want %s", rd.SignerAddr, vecSigner)
	}
	if rd.Version != ReportDataVersion {
		t.Errorf("Version = %d, want %d", rd.Version, ReportDataVersion)
	}
}

func TestParseTDXQuoteBody_TooShort(t *testing.T) {
	if _, err := ParseTDXQuoteBody(make([]byte, minQuoteLen-1)); err == nil {
		t.Errorf("expected error for short quote, got nil")
	}
	// Exactly minQuoteLen must be accepted (all fields present).
	if _, err := ParseTDXQuoteBody(make([]byte, minQuoteLen)); err != nil {
		t.Errorf("minQuoteLen input: unexpected error: %v", err)
	}
}

// structuralParser adapts ParseTDXQuoteBody to the quoteParser seam. It is
// TEST-ONLY: it does not verify the quote signature, so it must never be used in
// production (that is exactly why ParseTDXQuoteBody returns a QuoteBody, not this
// signature). Here it lets the KAT exercise the full Verify path on real bytes.
func structuralParser(raw []byte) (Measurement, [reportDataLen]byte, error) {
	b, err := ParseTDXQuoteBody(raw)
	return b.Measurement, b.ReportData, err
}

func TestVerify_RealVector_AllowlistMatch(t *testing.T) {
	raw := loadRealQuote(t)
	b, err := ParseTDXQuoteBody(raw)
	if err != nil {
		t.Fatalf("ParseTDXQuoteBody: %v", err)
	}

	v := New(Policy{Allowed: []Measurement{b.Measurement}}, WithQuoteParser(structuralParser))
	got, err := v.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if hex.EncodeToString(got.EncPub) != vecEncPub {
		t.Errorf("EncPub = %x", got.EncPub)
	}
	if got.SignerAddr != vecSigner {
		t.Errorf("SignerAddr = %s", got.SignerAddr)
	}
}

func TestVerify_RealVector_MeasurementNotAllowed(t *testing.T) {
	raw := loadRealQuote(t)
	// Allowlist a different measurement → the real quote's measurement misses.
	v := New(Policy{Allowed: []Measurement{mkMeasurement(0x00)}}, WithQuoteParser(structuralParser))
	if _, err := v.Verify(raw); !errors.Is(err, ErrUntrustedMeasurement) {
		t.Errorf("err = %v, want ErrUntrustedMeasurement", err)
	}
}
