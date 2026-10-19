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
// A LONG-RUNNING PROCESS. pcverify resolves the root once per run; the gateway and the
// sidecar hold one Verifier for days, so the root is fetched again every trustRefresh.
// A refresh that fails keeps the last root TUF did deliver — it is never older than the
// snapshot, and it is what the process was verifying against a moment ago — and is
// retried every trustRetry. Only a process that has never reached TUF verifies against the
// snapshot, and only that case carries the staleness caveat.
//
// Nothing is written to disk: TUF's local cache is disabled, so every fetch walks from the
// root sigstore-go embeds.

import (
	"fmt"
	"net/http"
	"time"

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

// How often the current root is fetched again, and how soon a failed fetch is retried.
const (
	trustRefresh = 24 * time.Hour
	trustRetry   = 10 * time.Minute
)

// trust resolves which trust root to verify against, fetching the current one when it is
// due. Calls wait for a fetch in progress rather than starting a second.
func (v *Verifier) trust() trust {
	v.trustMu.Lock()
	defer v.trustMu.Unlock()
	now := v.now()
	if v.trusted.sigstore == nil {
		v.trusted = trust{sigstore: v.snapshot}
	}
	if v.fetchRoot == nil || !v.trustNext.IsZero() && now.Before(v.trustNext) {
		return v.trusted
	}
	tm, err := v.fetchRoot()
	if err == nil {
		var sv *verify.Verifier
		if sv, err = sigstoreVerifier(tm); err == nil {
			v.trusted, v.current, v.trustNext = trust{sigstore: sv}, true, now.Add(trustRefresh)
			return v.trusted
		}
	}
	v.trustNext = now.Add(trustRetry)
	if !v.current {
		v.trusted.stale = fmt.Sprintf("the current Sigstore trust root could not be fetched (%v), so it was checked "+
			"against the snapshot embedded on %s, which may predate the key that signed it", err, snapshotDate)
	}
	return v.trusted
}

// fetchTrustedRoot fetches Sigstore's public-good trust root over TUF with client.
func fetchTrustedRoot(client *http.Client) (root.TrustedMaterial, error) {
	f := fetcher.NewDefaultFetcher()
	f.SetHTTPClient(client)
	f.SetHTTPUserAgent("0g-pc-e2ee-provenance")
	opts := tuf.DefaultOptions().WithDisableLocalCache().WithFetcher(f)
	return root.FetchTrustedRootWithOptions(opts)
}
