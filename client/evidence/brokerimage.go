package evidence

import (
	"embed"
	"fmt"
)

// brokerimages.json holds the expected boot-chain measurements for the OS images a
// PROVIDER's broker may run — trust-chain hop 3's allowlist, the one the gateway and
// the sidecar compare a verified provider quote against before sealing to it.
//
// EMBEDDED, for the same reason osimages.json is: the values ship with the binary, so
// a verifier needs no configuration and cannot be pointed at a friendlier allowlist by
// accident. Reviewing the allowlist is reviewing this repository. It also answers what
// trust-chain.md hop 3 left open — where the expected values are published — with the
// modest answer: here, beside the gateway's own, until there is a reason to prefer
// on-chain or broker release assets.
//
//go:embed brokerimages.json
var brokerImagesFS embed.FS

// BuiltinBrokerImages returns the embedded provider-image allowlist.
//
// An error means brokerimages.json is malformed, which is a build-time mistake in this
// repository rather than anything about the provider being verified. Callers on the
// SEALING path must treat it as fatal, never as an empty allowlist: degrading to empty
// silently turns the check off in warn mode, and in enforce mode turns "our own file is
// broken" into "every provider runs unaudited code" — the exact conflation
// ErrMeasurementPolicyNotConfigured exists to prevent.
func BuiltinBrokerImages() ([]OSImage, error) {
	const file = "brokerimages.json"
	raw, err := brokerImagesFS.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read embedded broker-image allowlist: %w", err)
	}
	imgs, err := ParseOSImages(raw)
	if err != nil {
		// Named, because ParseOSImages is shared with the GATEWAY's own allowlist and
		// says only "OS-image allowlist ...". Unwrapped, a corrupt provider allowlist and
		// a corrupt gateway allowlist produce the same sentence — and pcverify can hit
		// either in one run, so the operator would not know which file to look at.
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return imgs, nil
}
