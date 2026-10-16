package provenance

// trust.go is where the Sigstore trust root a run verifies against comes from.
//
// THE CURRENT ROOT, OVER TUF. Sigstore publishes its trust root (trusted_root.json) as a
// TUF target at tuf-repo-cdn.sigstore.dev, signed under a TUF root whose initial version
// sigstore-go embeds; the TUF client walks the root forward version by version, each
// signed by its predecessor's keys, so the chain from the embedded anchor to today's
// keys is verified, not trusted. This is what cosign and gh attestation do. Fetching it
// each run is what lets Sigstore rotate a key or open a new Rekor shard without a release
// of this verifier.
//
// THE SNAPSHOT, WHEN TUF IS UNREACHABLE. The embedded trusted_root.json holds real
// Sigstore keys, so a bundle that verifies against it is genuine; but a bundle that does
// not may simply be newer than the snapshot. judge reports that case as a check that did
// not run (exit 3, a failure under -strict), never as a refusal and never as a pass.
//
// No cache is written: pcverify keeps no state between runs.

import (
	"fmt"
	"net/http"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// trust is the trust root one run verifies against.
type trust struct {
	sigstore *verify.Verifier
	// stale says why the current trust root is not in use; empty when it is.
	stale string
}

// trust resolves, once per Verifier, which trust root to verify against.
func (v *Verifier) trust() trust {
	v.trustOnce.Do(func() {
		v.trusted = trust{sigstore: v.snapshot}
		if v.fetchRoot == nil {
			return
		}
		tm, err := v.fetchRoot()
		if err == nil {
			var sv *verify.Verifier
			if sv, err = sigstoreVerifier(tm); err == nil {
				v.trusted.sigstore = sv
				return
			}
		}
		v.trusted.stale = fmt.Sprintf("the current Sigstore trust root could not be fetched (%v), so it was checked "+
			"against the snapshot embedded on %s, which may predate the key that signed it", err, snapshotDate)
	})
	return v.trusted
}

// fetchTrustedRoot fetches Sigstore's public-good trust root over TUF with client.
func fetchTrustedRoot(client *http.Client) (root.TrustedMaterial, error) {
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPClient(client)
	f.SetHTTPUserAgent("pcverify")
	opts := tuf.DefaultOptions().WithDisableLocalCache().WithFetcher(f)
	return root.FetchTrustedRootWithOptions(opts)
}
