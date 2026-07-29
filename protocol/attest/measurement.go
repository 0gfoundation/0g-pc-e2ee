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
