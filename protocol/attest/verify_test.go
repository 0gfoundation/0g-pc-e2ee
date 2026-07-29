package attest

import (
	"bytes"
	"errors"
	"testing"
)

// fakeParser returns a quoteParser that yields fixed values, standing in for
// real TDX verification so the allowlist + binding logic can be tested in
// isolation. A nil err means "the quote is genuine and these are its contents".
func fakeParser(m Measurement, rd []byte, err error) quoteParser {
	var fixed [64]byte
	copy(fixed[:], rd)
	return func([]byte) (Measurement, [64]byte, error) {
		return m, fixed, err
	}
}

func TestVerify_Success(t *testing.T) {
	good := mkMeasurement(0xaa)
	encPub := sampleEncPub()
	rd := makeReportData(encPub, sampleSigner(), ReportDataVersion, [reservedLen]byte{})

	v := New(Policy{Allowed: []Measurement{good}}, WithQuoteParser(fakeParser(good, rd, nil)))
	got, err := v.Verify([]byte("raw-quote"))
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !bytes.Equal(got.EncPub, encPub[:]) {
		t.Errorf("EncPub = %x, want %x", got.EncPub, encPub[:])
	}
	if got.SignerAddr != "0xdeadbeef00112233445566778899aabbccddeeff" {
		t.Errorf("SignerAddr = %q", got.SignerAddr)
	}
	if got.Measurement != good {
		t.Errorf("Measurement mismatch")
	}
}

func TestVerify_NotConfiguredFailsClosed(t *testing.T) {
	// New without WithQuoteParser must reject every quote.
	v := New(Policy{Allowed: []Measurement{mkMeasurement(0xaa)}})
	if _, err := v.Verify([]byte("raw-quote")); !errors.Is(err, ErrQuoteVerifierNotConfigured) {
		t.Errorf("err = %v, want ErrQuoteVerifierNotConfigured", err)
	}
}

func TestVerify_UntrustedMeasurement(t *testing.T) {
	allowed := mkMeasurement(0xaa)
	served := mkMeasurement(0xbb) // genuine quote, but unaudited code
	rd := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, [reservedLen]byte{})

	v := New(Policy{Allowed: []Measurement{allowed}}, WithQuoteParser(fakeParser(served, rd, nil)))
	if _, err := v.Verify([]byte("raw-quote")); !errors.Is(err, ErrUntrustedMeasurement) {
		t.Errorf("err = %v, want ErrUntrustedMeasurement", err)
	}
}

func TestVerify_ParserErrorPropagates(t *testing.T) {
	sentinel := errors.New("bad TDX signature")
	v := New(Policy{Allowed: []Measurement{mkMeasurement(0xaa)}}, WithQuoteParser(fakeParser(Measurement{}, nil, sentinel)))
	_, err := v.Verify([]byte("raw-quote"))
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want it to wrap the parser error", err)
	}
}

func TestVerify_MalformedReportDataRejected(t *testing.T) {
	good := mkMeasurement(0xaa)
	// Genuine quote + trusted measurement, but the bound report_data is the
	// wrong version → must still fail closed at the binding step.
	bad := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion+1, [reservedLen]byte{})

	v := New(Policy{Allowed: []Measurement{good}}, WithQuoteParser(fakeParser(good, bad, nil)))
	if _, err := v.Verify([]byte("raw-quote")); !errors.Is(err, ErrMalformedReportData) {
		t.Errorf("err = %v, want ErrMalformedReportData", err)
	}
}

func TestVerify_EmptyQuote(t *testing.T) {
	v := New(Policy{Allowed: []Measurement{mkMeasurement(0xaa)}}, WithQuoteParser(fakeParser(mkMeasurement(0xaa), nil, nil)))
	if _, err := v.Verify(nil); err == nil {
		t.Error("Verify(nil) = nil error, want non-nil")
	}
}

// TestVerify_MeasurementCheckedBeforeBinding documents ordering: an untrusted
// measurement is rejected even when report_data is malformed, so a bad-image
// enclave never reaches (and cannot probe) the binding step.
func TestVerify_MeasurementCheckedBeforeBinding(t *testing.T) {
	served := mkMeasurement(0xbb)
	bad := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion+1, [reservedLen]byte{})
	v := New(Policy{Allowed: []Measurement{mkMeasurement(0xaa)}}, WithQuoteParser(fakeParser(served, bad, nil)))
	if _, err := v.Verify([]byte("raw-quote")); !errors.Is(err, ErrUntrustedMeasurement) {
		t.Errorf("err = %v, want ErrUntrustedMeasurement (measurement checked first)", err)
	}
}
