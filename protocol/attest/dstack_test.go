package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// The cert-binding layout: SHA-256(manifest) then zero padding, matching what
// dstack-ingress asks the quote for (evidence-lib.sh pads the hex query parameter
// with ASCII '0' to 128 chars, which decodes to zero bytes).
func TestEvidenceReportData_Layout(t *testing.T) {
	manifest := []byte("abc  acme-account.json\ndef  cert-x.pem\n")
	rd := EvidenceReportData(manifest)

	sum := sha256.Sum256(manifest)
	if got, want := rd[:sha256.Size], sum[:]; string(got) != string(want) {
		t.Errorf("leading digest = %x, want %x", got, want)
	}
	for i, b := range rd[sha256.Size:] {
		if b != 0 {
			t.Errorf("padding byte %d = 0x%02x, want zero", sha256.Size+i, b)
		}
	}
	if len(rd) != reportDataLen {
		t.Errorf("report_data length = %d, want %d", len(rd), reportDataLen)
	}
}

// The producer's own padding scheme, reproduced independently: hex-encode the
// digest, append '0' to 128 chars, decode. Locks our byte-domain construction to
// dstack-ingress's hex-domain one.
func TestEvidenceReportData_MatchesProducerHexPadding(t *testing.T) {
	manifest := []byte("whatever the bundle happens to contain\n")

	sum := sha256.Sum256(manifest)
	padded := hex.EncodeToString(sum[:])
	for len(padded) < 2*reportDataLen {
		padded += "0"
	}
	want, err := hex.DecodeString(padded)
	if err != nil {
		t.Fatalf("decode producer-style report_data: %v", err)
	}

	got := EvidenceReportData(manifest)
	if string(got[:]) != string(want) {
		t.Errorf("EvidenceReportData = %x, producer-style = %x", got[:], want)
	}
}

func TestVerifyEvidenceReportData_Accepts(t *testing.T) {
	manifest := []byte("bundle\n")
	if err := VerifyEvidenceReportData(EvidenceReportData(manifest), manifest); err != nil {
		t.Errorf("VerifyEvidenceReportData: %v", err)
	}
}

func TestVerifyEvidenceReportData_Rejects(t *testing.T) {
	manifest := []byte("bundle\n")
	good := EvidenceReportData(manifest)

	digestChanged := good
	digestChanged[0] ^= 0x01
	nonzeroPadding := good
	nonzeroPadding[reportDataLen-1] = 0x01
	// A quote for a *different* bundle: the shape is right, the commitment is not.
	otherBundle := EvidenceReportData([]byte("a different bundle\n"))

	cases := map[string][reportDataLen]byte{
		"digest tampered":  digestChanged,
		"nonzero padding":  nonzeroPadding,
		"different bundle": otherBundle,
		"all zero":         {},
	}
	for name, rd := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifyEvidenceReportData(rd, manifest)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !errors.Is(err, ErrMalformedReportData) {
				t.Errorf("error = %v, want it to wrap ErrMalformedReportData", err)
			}
		})
	}
}

// The two report_data layouts must not be interchangeable: the §4.2 parser has to
// reject a cert-binding report_data (its version field is zero), which is why
// VerifyEvidenceReportData exists as a separate entry point rather than a looser
// parse in one place.
func TestEvidenceReportData_RejectedByParseReportData(t *testing.T) {
	rd := EvidenceReportData([]byte("bundle\n"))
	if _, err := ParseReportData(rd[:]); !errors.Is(err, ErrMalformedReportData) {
		t.Errorf("ParseReportData on a cert-binding report_data: err = %v, want ErrMalformedReportData", err)
	}
}

// …and the reverse: a §4.2 provider report_data must not pass as a cert binding
// for any manifest. Its version byte lands in the padding region, so the padding
// check is what catches it even if a digest somehow collided.
func TestProviderReportData_RejectedAsEvidenceBinding(t *testing.T) {
	var providerRD [reportDataLen]byte
	providerRD[versionOff+versionLen-1] = ReportDataVersion // the §4.2 version field
	if err := VerifyEvidenceReportData(providerRD, []byte("bundle\n")); err == nil {
		t.Error("a §4.2 report_data passed as a cert binding")
	}
}
