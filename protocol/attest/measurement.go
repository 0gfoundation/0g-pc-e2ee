package attest

// measurementRegLen is the byte length of a TDX measurement register (SHA-384).
const measurementRegLen = 48

// Measurement is the set of TDX measurement registers that identify the code
// running in the enclave: MRTD (the initial VM image) plus the four RTMRs
// (runtime-extended measurements). Two enclaves with identical Measurement are
// running the same measured boot chain.
//
// Fixed-size arrays make Measurement comparable with ==, so allowlist matching
// is a plain equality check with no per-field loop.
//
// Which registers must match to call a provider "the audited image" is a policy
// question — a stricter policy might pin only MRTD, a looser one might ignore an
// RTMR that carries only benign runtime data. This skeleton pins ALL of them
// (full equality), the most conservative choice; relaxing it is a deliberate,
// reviewable Policy change, never a silent default.
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

// Configured reports whether the policy holds any expected value at all.
func (p BootChainPolicy) Configured() bool { return len(p.Allowed) > 0 }

// Policy is the client-held trust policy for quote verification. Allowed is the
// allowlist of acceptable measurements — the audited 0gfoundation/broker
// image(s). It MUST come from a source the client trusts independently of the
// request path (a reproducible build it can recompute, or a governance-signed /
// on-chain published value): NEVER from the router or the provider, which would
// let an attacker vouch for its own image.
//
// An empty Allowed permits nothing: with no acceptable measurement configured,
// every quote is rejected (fail-closed). This mirrors the WithQuoteParser
// default — an unconfigured Verifier trusts nothing.
type Policy struct {
	Allowed []Measurement
}

// permits reports whether m is in the allowlist. An empty allowlist permits
// nothing.
func (p Policy) permits(m Measurement) bool {
	for _, a := range p.Allowed {
		if a == m {
			return true
		}
	}
	return false
}
