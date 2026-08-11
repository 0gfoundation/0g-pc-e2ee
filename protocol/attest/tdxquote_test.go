package attest

import (
	"crypto/sha256"
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

	// mr_config_id of the same provider quote: dstack MRConfigV1, so the leading
	// byte is 0x01 and the next 32 bytes are the compose hash.
	vecMRConfigID  = "018779f38c1cc5d1e643fbfc7238bae2c227f7ffa4c72c049802942658acfc5bee000000000000000000000000000000"
	vecComposeHash = "8779f38c1cc5d1e643fbfc7238bae2c227f7ffa4c72c049802942658acfc5bee"
)

// Expected values for the GATEWAY cert-binding quote in
// testdata/dstack_gateway_quote_prefix.json. Its report_data and mr_config_id
// exercise the two dstack layouts the provider vector above does not.
const (
	gwMRConfigID = "0155d872aaa9c0b148228ebcf89302a52e7cd3d2529055a892a11715e863086f6a000000000000000000000000000000"
	// The value our MRCONFIGID parse must produce…
	gwComposeHash = "55d872aaa9c0b148228ebcf89302a52e7cd3d2529055a892a11715e863086f6a"
	// …and, independently, what dstack's OWN `compose-hash` / `app-id` runtime
	// events in the same quote's event log reported. Two producers, one value:
	// that is what makes this a cross-check rather than a restatement.
	gwEventLogComposeHash = "55d872aaa9c0b148228ebcf89302a52e7cd3d2529055a892a11715e863086f6a"
	gwEventLogAppID       = "55d872aaa9c0b148228ebcf89302a52e7cd3d252"
	// report_data = SHA-256(sha256sum.txt) ‖ 32 zero bytes (the cert binding).
	gwManifestDigest = "10c8750bc70ff84d6616ff8643990015aea74b3302e639fc74c3ecff90c285ca"
)

// loadRealQuote reads the KAT fixture and returns the raw quote bytes.
func loadRealQuote(t *testing.T) []byte {
	t.Helper()
	return loadQuoteFixture(t, "testdata/dstack_quote_prefix.json")
}

func loadQuoteFixture(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
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
		{"MRCONFIGID", b.MRConfigID[:], vecMRConfigID},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}

	// mr_config_id sits between MRTD and RTMR0; extracting the compose hash from it
	// is what locks that offset.
	ch, err := ComposeHashFromMRConfigID(b.MRConfigID)
	if err != nil {
		t.Fatalf("ComposeHashFromMRConfigID: %v", err)
	}
	if got := hex.EncodeToString(ch[:]); got != vecComposeHash {
		t.Errorf("compose_hash = %s, want %s", got, vecComposeHash)
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

// The gateway cert-binding vector: one real quote that exercises BOTH dstack
// layouts the provider vector does not — mr_config_id carrying a compose hash,
// and a report_data that is a bundle digest rather than SPEC §4.2 keys.
func TestParseTDXQuoteBody_GatewayCertBindingVector(t *testing.T) {
	b, err := ParseTDXQuoteBody(loadQuoteFixture(t, "testdata/dstack_gateway_quote_prefix.json"))
	if err != nil {
		t.Fatalf("ParseTDXQuoteBody: %v", err)
	}
	if got := hex.EncodeToString(b.MRConfigID[:]); got != gwMRConfigID {
		t.Fatalf("MRCONFIGID = %s, want %s", got, gwMRConfigID)
	}

	// Code identity: compose_hash out of the signed register, plus the app_id the
	// platform derives from it.
	ch, err := ComposeHashFromMRConfigID(b.MRConfigID)
	if err != nil {
		t.Fatalf("ComposeHashFromMRConfigID: %v", err)
	}
	if got := hex.EncodeToString(ch[:]); got != gwComposeHash {
		t.Errorf("compose_hash = %s, want %s", got, gwComposeHash)
	}
	// Cross-check against dstack's own RTMR3 runtime events from the same quote:
	// our register parse and the platform's event log must agree.
	if got := hex.EncodeToString(ch[:]); got != gwEventLogComposeHash {
		t.Errorf("compose_hash = %s, but the event log's compose-hash event says %s", got, gwEventLogComposeHash)
	}
	if got := AppIDFromComposeHash(ch); got != gwEventLogAppID {
		t.Errorf("app_id = %s, but the event log's app-id event says %s", got, gwEventLogAppID)
	}

	// This report_data is a cert binding, so §4.2 must reject it — and the
	// evidence-layout check must accept it for the right manifest digest.
	if _, err := ParseReportData(b.ReportData[:]); !errors.Is(err, ErrMalformedReportData) {
		t.Errorf("ParseReportData on the gateway vector: err = %v, want ErrMalformedReportData", err)
	}
	if got := hex.EncodeToString(b.ReportData[:sha256.Size]); got != gwManifestDigest {
		t.Errorf("manifest digest = %s, want %s", got, gwManifestDigest)
	}
	for i, by := range b.ReportData[sha256.Size:] {
		if by != 0 {
			t.Fatalf("cert-binding report_data padding byte %d = 0x%02x, want zero", sha256.Size+i, by)
		}
	}
	// The real sha256sum.txt is not in the fixture (it lives beside the quote in the
	// bundle, and changes on every certificate renewal), so the preimage half of the
	// binding is covered by client/evidence's end-to-end test instead. What this
	// vector locks is the layout: where the digest sits and that the tail is zero.
}
