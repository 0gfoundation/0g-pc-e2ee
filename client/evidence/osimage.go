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
	raw, err := osImagesFS.ReadFile("osimages.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded OS-image allowlist: %w", err)
	}
	return ParseOSImages(raw)
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

// checkOSImage compares the verified quote's boot chain against the allowlist.
func checkOSImage(allowed []OSImage, m attest.Measurement) OSImageCheck {
	out := OSImageCheck{Configured: len(allowed) > 0, Observed: attest.BootChainOf(m)}
	if !out.Configured {
		return out
	}
	policy := attest.BootChainPolicy{Allowed: make([]attest.BootChain, 0, len(allowed))}
	for _, img := range allowed {
		policy.Allowed = append(policy.Allowed, img.BootChain)
	}
	if !policy.Permits(out.Observed) {
		names := make([]string, 0, len(allowed))
		for _, img := range allowed {
			names = append(names, img.Name)
		}
		out.Err = fmt.Errorf("MRTD/RTMR1/RTMR2 match no allowlisted OS image (%s)", strings.Join(names, ", "))
		return out
	}
	for _, img := range allowed {
		if img.BootChain == out.Observed {
			out.Matched = img.Name
			break
		}
	}
	return out
}
