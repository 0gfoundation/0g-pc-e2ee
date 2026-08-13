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

func mkBootChain(fill byte) BootChain {
	return BootChainOf(mkMeasurement(fill))
}

// The boot chain must ignore RTMR3: two deployments of the same OS image differ there
// (app-id, compose-hash, instance-id events) and must still be the same boot chain.
func TestBootChainOf_IgnoresRTMR3(t *testing.T) {
	a := mkMeasurement(0x11)
	b := a
	b.RTMR3 = mkMeasurement(0x22).RTMR3

	if BootChainOf(a) != BootChainOf(b) {
		t.Error("boot chains differ although only RTMR3 does")
	}
	// …but a different OS image must not collide.
	c := a
	c.RTMR1 = mkMeasurement(0x33).RTMR1
	if BootChainOf(a) == BootChainOf(c) {
		t.Error("boot chains match although RTMR1 differs")
	}
}

func TestBootChainPolicy_Permits(t *testing.T) {
	good := mkBootChain(0x11)
	p := BootChainPolicy{Allowed: []BootChain{mkBootChain(0x99), good}}

	if !p.Permits(good) {
		t.Error("an allowlisted boot chain was rejected")
	}
	if p.Permits(mkBootChain(0x44)) {
		t.Error("a boot chain outside the allowlist was permitted")
	}
	if !p.Configured() {
		t.Error("Configured() = false for a non-empty allowlist")
	}
}

// "Not configured" must not degrade into "permits everything".
func TestBootChainPolicy_EmptyPermitsNothing(t *testing.T) {
	var p BootChainPolicy
	if p.Configured() {
		t.Error("Configured() = true for an empty allowlist")
	}
	if p.Permits(mkBootChain(0x11)) {
		t.Error("an empty allowlist permitted a boot chain")
	}
}

// An all-zero observation is what an absent or unparsed measurement looks like. It
// must never match — including against an all-zero allowlist entry, which is the way
// a placeholder in a config file could otherwise silently accept anything.
func TestBootChainPolicy_ZeroNeverMatches(t *testing.T) {
	var zero BootChain
	if !zero.IsZero() {
		t.Fatal("IsZero() = false for the zero value")
	}
	if (BootChainPolicy{Allowed: []BootChain{zero}}).Permits(zero) {
		t.Error("a zero boot chain matched a zero allowlist entry")
	}
	if (BootChainPolicy{Allowed: []BootChain{mkBootChain(0x11)}}).Permits(zero) {
		t.Error("a zero boot chain matched a real allowlist entry")
	}
}
