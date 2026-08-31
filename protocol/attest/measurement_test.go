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

// Name reports the label of the entry that MATCHED, and reports one only for a boot
// chain the policy actually permits. That gate is the whole guarantee: a caller
// displaying a name ("this enclave runs the image we audited, and it is this one") is
// entitled to read a non-empty result as membership, so a stray label must not be able
// to name an image the allowlist never accepted.
func TestBootChainPolicy_Name(t *testing.T) {
	listed, other := mkBootChain(0x11), mkBootChain(0x44)
	p := BootChainPolicy{
		Allowed: []BootChain{mkBootChain(0x99), listed},
		Names: map[BootChain]string{
			listed: "dstack-test-1.0",
			// A label for a chain nobody allowlisted, which is what a mis-assembled policy
			// looks like. It must stay inert.
			other: "not-in-the-allowlist",
		},
	}
	if got := p.Name(listed); got != "dstack-test-1.0" {
		t.Errorf("Name(listed) = %q, want the entry's label", got)
	}
	if got := p.Name(other); got != "" {
		t.Errorf("Name(unlisted) = %q, want \"\": a label must never stand in for membership", got)
	}
	// An allowlisted entry with no label: still a match, just nothing to call it. The
	// caller reads the verdict from Permits, never from the name's emptiness.
	if got := p.Name(mkBootChain(0x99)); got != "" {
		t.Errorf("Name(unlabelled) = %q, want \"\"", got)
	}
	if !p.Permits(mkBootChain(0x99)) {
		t.Error("an unlabelled entry stopped being permitted")
	}
	// Labels are not a second allowlist: a policy without Names decides exactly as one
	// with them, and reports nothing.
	bare := BootChainPolicy{Allowed: []BootChain{listed}}
	if !bare.Permits(listed) || bare.Name(listed) != "" {
		t.Error("a policy with no Names must still permit, and name nothing")
	}
	if (BootChainPolicy{}).Name(listed) != "" {
		t.Error("an empty policy named a boot chain")
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
