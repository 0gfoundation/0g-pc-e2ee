package attest

import "testing"

// mkMeasurement returns a Measurement whose every register byte is `fill`, a
// cheap way to get distinct, easily-compared fixtures.
func mkMeasurement(fill byte) Measurement {
	var reg [measurementRegLen]byte
	for i := range reg {
		reg[i] = fill
	}
	return Measurement{MRTD: reg, RTMR0: reg, RTMR1: reg, RTMR2: reg, RTMR3: reg}
}

func TestPolicyPermits(t *testing.T) {
	good := mkMeasurement(0xaa)
	other := mkMeasurement(0xbb)

	p := Policy{Allowed: []Measurement{good}}
	if !p.permits(good) {
		t.Error("permits(good) = false, want true")
	}
	if p.permits(other) {
		t.Error("permits(other) = true, want false")
	}
}

func TestPolicyPermits_EmptyAllowlistRejectsAll(t *testing.T) {
	var empty Policy
	if empty.permits(mkMeasurement(0xaa)) {
		t.Error("empty allowlist permitted a measurement; want fail-closed")
	}
	if empty.permits(Measurement{}) {
		t.Error("empty allowlist permitted the zero measurement; want fail-closed")
	}
}

func TestPolicyPermits_PartialMeasurementMismatch(t *testing.T) {
	good := mkMeasurement(0xaa)
	p := Policy{Allowed: []Measurement{good}}

	// A single differing register (RTMR3) must miss: the skeleton pins all
	// registers, so an otherwise-matching enclave with one changed measurement
	// is not trusted.
	almost := good
	almost.RTMR3[0] ^= 0x01
	if p.permits(almost) {
		t.Error("permits(almost) = true; a one-byte RTMR3 difference must not match")
	}
}
