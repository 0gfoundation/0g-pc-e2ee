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

	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(good)}}, WithQuoteParser(fakeParser(good, rd, nil)))
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
	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(mkMeasurement(0xaa))}})
	if _, err := v.Verify([]byte("raw-quote")); !errors.Is(err, ErrQuoteVerifierNotConfigured) {
		t.Errorf("err = %v, want ErrQuoteVerifierNotConfigured", err)
	}
}

func TestVerify_UntrustedMeasurement(t *testing.T) {
	allowed := mkMeasurement(0xaa)
	served := mkMeasurement(0xbb) // genuine quote, but unaudited code
	rd := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, [reservedLen]byte{})

	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(allowed)}}, WithQuoteParser(fakeParser(served, rd, nil)))
	if _, err := v.Verify([]byte("raw-quote")); !errors.Is(err, ErrUntrustedMeasurement) {
		t.Errorf("err = %v, want ErrUntrustedMeasurement", err)
	}
}

// The point of pinning the boot chain instead of the full Measurement: two replicas
// of ONE deployment differ in RTMR3 (dstack extends it with instance-id, derived from
// a per-CVM random seed at first boot) and in RTMR0 (VM shape), and both must satisfy
// the SAME allowlist entry. Under the old full-equality Policy each replica needed its
// own entry, which is why the provider allowlist could not be populated at all —
// entries would have had to be minted per CVM, after the CVM existed.
func TestVerify_OneEntryCoversEveryReplicaOfAnImage(t *testing.T) {
	audited := mkMeasurement(0xaa)
	rd := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, [reservedLen]byte{})
	v := func(served Measurement) *Verifier {
		return New(BootChainPolicy{Allowed: []BootChain{BootChainOf(audited)}},
			WithQuoteParser(fakeParser(served, rd, nil)))
	}

	replica := audited
	replica.RTMR3[0] ^= 0xff // a different instance of the same image
	replica.RTMR0[0] ^= 0xff // …on a differently-shaped VM
	got, err := v(replica).Verify([]byte("raw-quote"))
	if err != nil {
		t.Fatalf("a second replica of the audited image must verify: %v", err)
	}
	if !got.MeasurementTrusted {
		t.Error("MeasurementTrusted = false for a replica of the audited image")
	}

	// The registers that DO identify the image must still be compared: a changed
	// kernel is a different image, not a different replica.
	other := audited
	other.RTMR1[0] ^= 0x01
	if _, err := v(other).Verify([]byte("raw-quote")); !errors.Is(err, ErrUntrustedMeasurement) {
		t.Errorf("err = %v, want ErrUntrustedMeasurement for a changed RTMR1", err)
	}
}

// Enforcing against an empty allowlist rejects every provider. That is correct, but
// it is a configuration that was never finished — not a verdict on the enclave — and
// the two must not arrive as the same error, or turning enforcement on reads as
// "every provider runs unaudited code".
func TestVerify_EnforceWithEmptyAllowlistNamesTheConfigGap(t *testing.T) {
	served := mkMeasurement(0xaa)
	rd := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, [reservedLen]byte{})

	v := New(BootChainPolicy{}, WithQuoteParser(fakeParser(served, rd, nil)))
	_, err := v.Verify([]byte("raw-quote"))
	if !errors.Is(err, ErrMeasurementPolicyNotConfigured) {
		t.Errorf("err = %v, want ErrMeasurementPolicyNotConfigured", err)
	}
	// Still fail-closed: an unconfigured policy must never yield a Verified.
	if errors.Is(err, ErrUntrustedMeasurement) {
		t.Error("an empty allowlist must not be reported as an untrusted measurement")
	}

	// ModeWarn keeps proceeding, flagged — the rollout bridge, unchanged.
	warn := New(BootChainPolicy{}, WithQuoteParser(fakeParser(served, rd, nil)),
		WithMeasurementMode(ModeWarn))
	got, err := warn.Verify([]byte("raw-quote"))
	if err != nil {
		t.Fatalf("ModeWarn with an empty allowlist: %v", err)
	}
	if got.MeasurementTrusted {
		t.Error("MeasurementTrusted = true with no allowlist configured")
	}
}

// A verification reports WHICH audited image the enclave booted, not merely that it
// booted one — the value a report needs to name the entry, and the one it must never
// invent. The three cases below are the whole contract: a labelled match names the
// entry, a miss names nothing even where the policy holds labels, and a match against
// an unlabelled policy names nothing while staying trusted.
func TestVerify_ReportsTheMatchedOSImage(t *testing.T) {
	audited, other := mkMeasurement(0xaa), mkMeasurement(0xbb)
	rd := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, [reservedLen]byte{})
	labelled := BootChainPolicy{
		Allowed: []BootChain{BootChainOf(audited)},
		Names:   map[BootChain]string{BootChainOf(audited): "dstack-test-1.0"},
	}

	got, err := New(labelled, WithQuoteParser(fakeParser(audited, rd, nil))).Verify([]byte("raw-quote"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.MeasurementTrusted || got.MeasurementImage != "dstack-test-1.0" {
		t.Errorf("trusted/image = %v/%q, want true/\"dstack-test-1.0\"", got.MeasurementTrusted, got.MeasurementImage)
	}

	// Warn mode on an unlisted image: the quote is genuine and its keys are bound, but
	// nothing in the allowlist matched — so there is no image to name. Naming one here
	// would be the single worst way this field could fail, since a panel would show an
	// audited image beside a boot chain nobody audited.
	got, err = New(labelled, WithQuoteParser(fakeParser(other, rd, nil)),
		WithMeasurementMode(ModeWarn)).Verify([]byte("raw-quote"))
	if err != nil {
		t.Fatalf("Verify (warn, unlisted): %v", err)
	}
	if got.MeasurementTrusted {
		t.Fatal("MeasurementTrusted = true for an unlisted boot chain")
	}
	if got.MeasurementImage != "" {
		t.Errorf("MeasurementImage = %q for an unlisted boot chain, want \"\"", got.MeasurementImage)
	}

	// An unlabelled policy — every caller before Names existed — decides identically
	// and reports no name. MeasurementImage adds to MeasurementTrusted; it never
	// restates it.
	got, err = New(BootChainPolicy{Allowed: []BootChain{BootChainOf(audited)}},
		WithQuoteParser(fakeParser(audited, rd, nil))).Verify([]byte("raw-quote"))
	if err != nil {
		t.Fatalf("Verify (unlabelled policy): %v", err)
	}
	if !got.MeasurementTrusted || got.MeasurementImage != "" {
		t.Errorf("trusted/image = %v/%q, want true/\"\"", got.MeasurementTrusted, got.MeasurementImage)
	}
}

// A caller that REPORTS the measurement outcome, rather than only acting on it, has
// to tell "this image is not one we audited" from "we have audited none" — and under
// ModeWarn, MeasurementTrusted=false is both. This is the accessor that separates
// them, and the pairing below is the whole point: same false, different reason.
func TestMeasurementBaselineConfigured(t *testing.T) {
	served := mkMeasurement(0xaa)
	rd := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, [reservedLen]byte{})
	other := BootChainPolicy{Allowed: []BootChain{BootChainOf(mkMeasurement(0xbb))}}

	for _, tc := range []struct {
		name           string
		policy         BootChainPolicy
		wantConfigured bool
	}{
		{"no allowlist at all", BootChainPolicy{}, false},
		{"an allowlist this quote is not in", other, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(tc.policy, WithQuoteParser(fakeParser(served, rd, nil)), WithMeasurementMode(ModeWarn))
			got, err := v.Verify([]byte("raw-quote"))
			if err != nil {
				t.Fatalf("ModeWarn should proceed: %v", err)
			}
			if got.MeasurementTrusted {
				t.Fatal("MeasurementTrusted = true, want false in both cases")
			}
			if v.MeasurementBaselineConfigured() != tc.wantConfigured {
				t.Errorf("MeasurementBaselineConfigured() = %v, want %v",
					v.MeasurementBaselineConfigured(), tc.wantConfigured)
			}
		})
	}
	// And it is true for a policy the quote does match, so it reports the ALLOWLIST's
	// state and never doubles as a verdict on the quote.
	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(served)}}, WithQuoteParser(fakeParser(served, rd, nil)))
	if !v.MeasurementBaselineConfigured() {
		t.Error("MeasurementBaselineConfigured() = false for a populated allowlist")
	}
}

func TestVerify_ParserErrorPropagates(t *testing.T) {
	sentinel := errors.New("bad TDX signature")
	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(mkMeasurement(0xaa))}}, WithQuoteParser(fakeParser(Measurement{}, nil, sentinel)))
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

	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(good)}}, WithQuoteParser(fakeParser(good, bad, nil)))
	if _, err := v.Verify([]byte("raw-quote")); !errors.Is(err, ErrMalformedReportData) {
		t.Errorf("err = %v, want ErrMalformedReportData", err)
	}
}

func TestVerify_EmptyQuote(t *testing.T) {
	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(mkMeasurement(0xaa))}}, WithQuoteParser(fakeParser(mkMeasurement(0xaa), nil, nil)))
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
	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(mkMeasurement(0xaa))}}, WithQuoteParser(fakeParser(served, bad, nil)))
	if _, err := v.Verify([]byte("raw-quote")); !errors.Is(err, ErrUntrustedMeasurement) {
		t.Errorf("err = %v, want ErrUntrustedMeasurement (measurement checked first)", err)
	}
}

func TestVerify_WarnMode_AcceptsUntrustedMeasurement(t *testing.T) {
	served := mkMeasurement(0xbb) // genuine quote, unaudited code
	rd := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, [reservedLen]byte{})
	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(mkMeasurement(0xaa))}},
		WithQuoteParser(fakeParser(served, rd, nil)), WithMeasurementMode(ModeWarn))

	got, err := v.Verify([]byte("raw-quote"))
	if err != nil {
		t.Fatalf("warn mode should not error on measurement miss: %v", err)
	}
	if got.MeasurementTrusted {
		t.Error("MeasurementTrusted = true, want false (measurement not in allowlist)")
	}
	// Keys are still bound from the genuine, verified quote.
	if want := sampleEncPub(); !bytes.Equal(got.EncPub, want[:]) {
		t.Errorf("EncPub not bound in warn mode: %x", got.EncPub)
	}
}

func TestVerify_WarnMode_TrustedWhenAllowlisted(t *testing.T) {
	good := mkMeasurement(0xaa)
	rd := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion, [reservedLen]byte{})
	v := New(BootChainPolicy{Allowed: []BootChain{BootChainOf(good)}},
		WithQuoteParser(fakeParser(good, rd, nil)), WithMeasurementMode(ModeWarn))
	got, err := v.Verify([]byte("raw-quote"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.MeasurementTrusted {
		t.Error("MeasurementTrusted = false, want true (measurement allowlisted)")
	}
}

// Warn mode must NOT relax quote authenticity or report_data validity.
func TestVerify_WarnMode_StillEnforcesAuthenticityAndBinding(t *testing.T) {
	sentinel := errors.New("bad TDX signature")
	vAuth := New(BootChainPolicy{}, WithQuoteParser(fakeParser(Measurement{}, nil, sentinel)), WithMeasurementMode(ModeWarn))
	if _, err := vAuth.Verify([]byte("raw-quote")); !errors.Is(err, sentinel) {
		t.Errorf("warn mode must still fail on bad quote: %v", err)
	}

	badRD := makeReportData(sampleEncPub(), sampleSigner(), ReportDataVersion+1, [reservedLen]byte{})
	vBind := New(BootChainPolicy{}, WithQuoteParser(fakeParser(mkMeasurement(0xbb), badRD, nil)), WithMeasurementMode(ModeWarn))
	if _, err := vBind.Verify([]byte("raw-quote")); !errors.Is(err, ErrMalformedReportData) {
		t.Errorf("warn mode must still fail on malformed report_data: %v", err)
	}
}
