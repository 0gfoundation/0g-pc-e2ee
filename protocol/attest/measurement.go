package attest

// measurementRegLen is the byte length of a TDX measurement register (SHA-384).
const measurementRegLen = 48

// Measurement is the set of TDX measurement registers that identify the code
// running in the enclave: MRTD (the initial VM image) plus the four RTMRs
// (runtime-extended measurements). Two enclaves with identical Measurement are
// running the same measured boot chain.
//
// Fixed-size arrays make Measurement comparable with ==, so matching is a plain
// equality check with no per-field loop.
//
// This is the full observation, NOT the thing an allowlist compares. Which registers
// identify "the audited image" is a policy question, and pinning all five is not the
// conservative answer it looks like: RTMR3 carries per-instance events, so a
// full-equality entry pins one CVM rather than one image. Verifier therefore compares
// BootChain — see that type for which registers are excluded and why. Measurement
// stays whole because a verifier still wants to report what it saw, RTMR0 and RTMR3
// included.
type Measurement struct {
	MRTD  [measurementRegLen]byte
	RTMR0 [measurementRegLen]byte
	RTMR1 [measurementRegLen]byte
	RTMR2 [measurementRegLen]byte
	RTMR3 [measurementRegLen]byte
}

// BootChain identifies the guest OS **image**: MRTD (the virtual firmware), RTMR1
// (the kernel) and RTMR2 (the kernel cmdline — which carries the rootfs dm-verity
// hash — plus the initrd). Two of the five registers are deliberately excluded, for
// different reasons.
//
// **RTMR3 is the application.** dstack extends it with per-app and per-instance
// runtime events (app-id, compose-hash, instance-id), so it differs between two
// replicas of one deployment. Pinning it would mean an expected value per CVM, and it
// would be redundant: the application is already pinned, more precisely, by the
// compose hash in mr_config_id.
//
// **RTMR0 is the virtual hardware, and it is not load-bearing here.** It records the
// VM shape — vCPU count, memory size, ACPI/device layout (dstack's own diagnose
// output annotates every RTMR0 event with the shape parameter it varies with). The
// claim this type exists to support is that the guest OS enforced the mr_config_id ↔
// app-compose binding, and every piece of code performing that enforcement is
// measured by the three registers above. Changing the vCPU count does not change that
// code. Including RTMR0 would have bought nothing and cost an expected value per
// (image, VM shape) pair rather than per image — which is why it is out.
//
// The security-relevant shape parameters are covered anyway: disabling root verity
// changes the cmdline and so RTMR2; device DMA into private memory is blocked by the
// TDX module rather than by the ACPI layout. A verifier that wants the shape pinned
// too should treat that as an additional, separate check — RTMR0 remains available on
// Measurement, and pcverify reports it.
//
// So BootChain answers "is this the OS image I audited?" while the compose hash
// answers "is this the app I published?" — two questions with two different lifetimes,
// which is why they get two mechanisms.
type BootChain struct {
	MRTD  [measurementRegLen]byte
	RTMR1 [measurementRegLen]byte
	RTMR2 [measurementRegLen]byte
}

// BootChainOf projects a full Measurement onto the image-identifying registers,
// dropping RTMR0 (VM shape) and RTMR3 (the application). See BootChain.
func BootChainOf(m Measurement) BootChain {
	return BootChain{MRTD: m.MRTD, RTMR1: m.RTMR1, RTMR2: m.RTMR2}
}

// IsZero reports whether the boot chain is entirely zero, which is what an absent or
// unparsed measurement looks like. Callers must treat it as "no information" rather
// than as a value to compare, or an all-zero allowlist entry would match an all-zero
// observation.
func (b BootChain) IsZero() bool { return b == BootChain{} }

// BootChainPolicy is the allowlist of OS-image boot chains a verifier accepts. Like
// Policy it must come from a source trusted independently of the thing being verified
// — for a dstack image, values recomputed from its reproducible build (`dstack-mr`),
// which is one entry per image because the shape-dependent register is excluded.
//
// An empty allowlist means "not configured". Unlike Policy, which fails closed on an
// empty set, that decision is left to the caller here: this check grounds a claim
// (which OS enforced the app binding) that a verifier may legitimately report as
// unavailable rather than as a failure. Callers must say which they are doing.
type BootChainPolicy struct {
	Allowed []BootChain
	// Names optionally labels entries in Allowed — the image name the allowlist entry
	// was published under (evidence.OSImage.Name, e.g. "dstack-nvidia-0.5.9"). It is
	// what lets a verifier report WHICH audited image an enclave booted rather than
	// only that it booted one, and it is why the label lives on the policy rather than
	// beside it: a name looked up from a second copy of the allowlist could disagree
	// with the entry that actually matched, which is the one thing a "this is the image
	// you audited" claim must not do.
	//
	// Optional, and never load-bearing. Matching reads Allowed and nothing else, so a
	// policy built without Names decides exactly as it did before — it can only report
	// less. A name for a boot chain that is NOT in Allowed is inert: Name refuses to
	// return one (see Name), so a label can never stand in for membership.
	Names map[BootChain]string
}

// Permits reports whether b is allowlisted. An empty allowlist permits nothing, and a
// zero b is never permitted — see BootChain.IsZero.
func (p BootChainPolicy) Permits(b BootChain) bool {
	if b.IsZero() {
		return false
	}
	for _, a := range p.Allowed {
		if a == b {
			return true
		}
	}
	return false
}

// Name returns the label of the allowlist entry b matched, or "" when b is not
// allowlisted or the entry carries no label.
//
// It is gated on Permits rather than being a plain map read, and that is the whole
// point of the method: a non-empty result therefore MEANS "this boot chain is in the
// allowlist, under this name". A reader can act on the name without re-deriving the
// verdict, and a mislabelled policy (a name for a chain nobody allowlisted) cannot
// turn into an accidental pass.
//
// The reverse implication does not hold and must not be read into it: "" is also what
// a matched chain returns when the policy carries no Names at all, so a caller
// reporting the name still has to report the verdict separately.
func (p BootChainPolicy) Name(b BootChain) string {
	if !p.Permits(b) {
		return ""
	}
	return p.Names[b]
}

// Configured reports whether the policy holds any expected value at all.
func (p BootChainPolicy) Configured() bool { return len(p.Allowed) > 0 }

// Policy was the client-held allowlist of full Measurements. Verifier no longer
// uses it, and nothing should: full equality includes RTMR3, which dstack extends
// with per-INSTANCE events, so one entry pins one CVM rather than one audited
// version. An allowlist of that shape needs a new entry per replica, cannot be
// published before a deployment exists, and would have to be regenerated on every
// scale-out — which is why the provider-side allowlist stayed empty rather than
// merely unpopulated.
//
// Deprecated: use BootChainPolicy, which pins the OS image (one entry per image,
// computable from a reproducible build) and leaves the application to the compose
// hash. The type is retained because protocol/ is the module every participant
// depends on, so removing an exported name is a breaking change for callers this
// repository cannot see.
type Policy struct {
	Allowed []Measurement
}
