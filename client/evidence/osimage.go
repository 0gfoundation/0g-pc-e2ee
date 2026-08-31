package evidence

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// osimages.json holds the expected boot-chain measurements for the OS images the
// gateway is deployed on. It is EMBEDDED rather than read from a path so that a
// verifier needs no configuration and cannot be pointed at a friendlier allowlist by
// accident: the values ship with the binary, and reviewing them is reviewing this
// repository. See the file's own header for how an entry is derived.
//
//go:embed osimages.json
var osImagesFS embed.FS

// OSImage is one allowlisted OS image. **One entry per image, not per (image, VM
// shape)** — attest.BootChain excludes the shape-dependent register, so the same entry
// holds however many vCPUs or GPUs the CVM was given. The identity that matters is
// BootChain; the rest is provenance, carried so a report can name what matched.
type OSImage struct {
	// Name is the image as the platform labels it, e.g. "dstack-0.5.3" — dstack's
	// vm_config.image. A label for humans; matching never uses it.
	Name string
	// OSImageHash is the image's digest.txt, i.e. sha256(sha256sum.txt) over the
	// published release — dstack's vm_config.os_image_hash. This is the value that
	// identifies WHICH release an entry was computed from, and the one to check a
	// downloaded release against before running dstack-mr on it. It is NOT used for
	// matching: it reaches a verifier only through unsigned runtime data, whereas the
	// boot chain is in the signed report.
	OSImageHash string
	// BootChain is MRTD + RTMR1 + RTMR2 — the image-identifying registers, and the
	// value actually compared.
	BootChain attest.BootChain
}

// osImagesFile is the on-disk shape of osimages.json.
type osImagesFile struct {
	Images []struct {
		Name        string `json:"name"`
		OSImageHash string `json:"os_image_hash"`
		MRTD        string `json:"mrtd"`
		RTMR1       string `json:"rtmr1"`
		RTMR2       string `json:"rtmr2"`
	} `json:"images"`
}

// BuiltinOSImages returns the embedded allowlist. An error means the embedded file is
// malformed, which is a build-time mistake in this repository rather than anything
// about the deployment being verified — so callers should surface it loudly instead of
// degrading to "not configured", which would silently drop the check.
func BuiltinOSImages() ([]OSImage, error) {
	const file = "osimages.json"
	raw, err := osImagesFS.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read embedded OS-image allowlist: %w", err)
	}
	imgs, err := ParseOSImages(raw)
	if err != nil {
		// Named for the same reason BuiltinBrokerImages names its file: the parser is
		// shared, so without this the two allowlists fail identically.
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return imgs, nil
}

// ParseOSImages decodes an allowlist. Every measurement must be a full-length hex
// register and no entry may be all-zero: a placeholder left in the file would
// otherwise become an entry that matches a quote whose registers failed to parse.
func ParseOSImages(raw []byte) ([]OSImage, error) {
	var f osImagesFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("OS-image allowlist is not valid JSON: %w", err)
	}
	out := make([]OSImage, 0, len(f.Images))
	for i, e := range f.Images {
		label := e.Name
		if label == "" {
			label = fmt.Sprintf("entry %d", i+1)
		}
		if strings.TrimSpace(e.Name) == "" {
			return nil, fmt.Errorf("OS-image allowlist %s: name is required", label)
		}
		var bc attest.BootChain
		for _, reg := range []struct {
			name string
			hex  string
			dst  []byte
		}{
			{"mrtd", e.MRTD, bc.MRTD[:]},
			{"rtmr1", e.RTMR1, bc.RTMR1[:]},
			{"rtmr2", e.RTMR2, bc.RTMR2[:]},
		} {
			b, err := hex.DecodeString(strings.TrimSpace(reg.hex))
			if err != nil {
				return nil, fmt.Errorf("OS-image allowlist %s: %s is not hex: %w", label, reg.name, err)
			}
			if len(b) != len(reg.dst) {
				return nil, fmt.Errorf("OS-image allowlist %s: %s is %d bytes, want %d",
					label, reg.name, len(b), len(reg.dst))
			}
			copy(reg.dst, b)
		}
		if bc.IsZero() {
			return nil, fmt.Errorf("OS-image allowlist %s: all registers are zero; a placeholder entry would match an unparsed quote", label)
		}
		out = append(out, OSImage{
			Name: e.Name, OSImageHash: e.OSImageHash, BootChain: bc,
		})
	}
	return out, nil
}

// OSImageCheck is the result of comparing the verified quote's boot chain against the
// allowlist (see Report.OSImage).
type OSImageCheck struct {
	// Configured reports whether the allowlist held any entry. When false the check
	// did not run: the claim it grounds is unavailable, not refuted, so it does not
	// fail the report — but every summary must say so.
	Configured bool
	// Matched names the allowlist entry the quote's boot chain equals.
	Matched string
	// Err is set when the allowlist was configured and nothing matched.
	Err error
	// Observed is the boot chain the quote actually carries, so an operator adding a
	// new entry (a legitimate OS upgrade) can see what to expect — and so a mismatch
	// report is actionable rather than just "no".
	Observed attest.BootChain
}

// OK reports whether the OS image is acceptable. An unconfigured allowlist is OK: the
// check is unavailable, and Report.Note is where that is disclosed.
func (o OSImageCheck) OK() bool { return !o.Configured || o.Err == nil }

// BootChainPolicyOf projects an allowlist onto the type attest.Verifier compares
// with: the boot chains it matches on, plus each entry's NAME, which it does not.
//
// Exported for the same reason CheckOSImage is: the gateway's own OS-image check and
// the PROVIDER-side allowlist (brokerimages.json, which the sealing path enforces)
// must agree on what a list of entries means. A second projection would be a second
// answer to "which boot chains does this file accept".
//
// The names ride along so a verifier can say WHICH audited image an enclave booted
// (attest.Verified.MeasurementImage) — the one provenance field a report needs, and
// the reason os_image on the gateway's provider-identity endpoint can carry a value
// rather than a permanent null. They are inert for matching: attest.BootChainPolicy
// compares Allowed and consults Names only after a match.
//
// Two entries sharing one boot chain (different names for the same measured image, or
// a copy-paste in the file) keep the FIRST name, matching CheckOSImage's first-match
// report below. Neither is more correct than the other; what matters is that the two
// do not disagree about the same file.
func BootChainPolicyOf(allowed []OSImage) attest.BootChainPolicy {
	policy := attest.BootChainPolicy{
		Allowed: make([]attest.BootChain, 0, len(allowed)),
		Names:   make(map[attest.BootChain]string, len(allowed)),
	}
	for _, img := range allowed {
		policy.Allowed = append(policy.Allowed, img.BootChain)
		if _, named := policy.Names[img.BootChain]; !named {
			policy.Names[img.BootChain] = img.Name
		}
	}
	return policy
}

// CheckOSImage compares a quote's boot chain against the allowlist.
//
// Exported because two callers must reach the same verdict from the same
// allowlist: Check runs it as step 7 of a verification, and the gateway runs it
// over its own quote to say which OS image it is running. A second implementation
// of "is this image one we accept" would be a second answer.
//
// The caller is responsible for the quote being genuine. Check verifies first;
// the gateway's self-description does not, which is why what it publishes is a
// claim about itself rather than evidence — see cmd/gateway's identity endpoint.
func CheckOSImage(allowed []OSImage, m attest.Measurement) OSImageCheck {
	out := OSImageCheck{Configured: len(allowed) > 0, Observed: attest.BootChainOf(m)}
	if !out.Configured {
		return out
	}
	// One policy, one lookup, for both halves of the answer: attest.BootChainPolicy.Name
	// returns a name only for a chain it permits, so Matched cannot name an entry the
	// comparison did not match — and it is the same call the sealing path's verifier
	// makes, so this endpoint and that one cannot report different images for one quote.
	policy := BootChainPolicyOf(allowed)
	if matched := policy.Name(out.Observed); matched != "" {
		out.Matched = matched
		return out
	}
	if policy.Permits(out.Observed) {
		// Allowlisted but unlabelled — unreachable from ParseOSImages, which requires a
		// name on every entry, but reachable for a hand-built list. A match with no name
		// to report is still a match, and reporting it as a miss would be a false finding.
		return out
	}
	names := make([]string, 0, len(allowed))
	for _, img := range allowed {
		names = append(names, img.Name)
	}
	out.Err = fmt.Errorf("MRTD/RTMR1/RTMR2 match no allowlisted OS image (%s)", strings.Join(names, ", "))
	return out
}
