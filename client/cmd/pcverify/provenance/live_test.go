package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

// liveTagEnv names the broker release TestLive_BrokerRelease checks. Unset, the test is
// skipped and the suite stays offline.
const liveTagEnv = "PCVERIFY_LIVE_BROKER_TAG"

// TestLive_BrokerRelease checks one broker release exactly as `pcverify -provider` would:
// New(), the live registry, the current Sigstore trust root over TUF. The scheduled
// broker-release workflow runs it against the broker's newest release, so a release that
// stops verifying — a renamed workflow, a dropped attestation, a Sigstore change this
// verifier does not follow — shows up here, before a provider check reports it.
func TestLive_BrokerRelease(t *testing.T) {
	tag := os.Getenv(liveTagEnv)
	if tag == "" {
		t.Skip(liveTagEnv + " is not set")
	}
	if !releaseTag.MatchString(tag) {
		t.Fatalf("%s=%q is not a release tag", liveTagEnv, tag)
	}
	v, err := New(&http.Client{Timeout: 30 * time.Second}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// The digest a provider deploys is the one the tag names: the manifest build.yml
	// pushed, whose sha256 is the digest.
	host, name, _ := strings.Cut(v.Repository(), "/")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	raw, status, err := v.registry.get(ctx, host, name, "manifests/"+tag, strings.Join([]string{
		mediaIndex, mediaManifest,
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "), maxManifestBytes)
	if err != nil || status != http.StatusOK {
		t.Fatalf("%s:%s: HTTP %d, %v", v.Repository(), tag, status, err)
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	got := v.Verify(v.Repository(), digest)
	if v.trusted.stale != "" {
		t.Errorf("the current trust root was not used: %s", v.trusted.stale)
	}
	if got.Status != evidence.ReleaseAccepted || got.Release.Version != tag {
		t.Fatalf("%s:%s (%s) is not accepted: status %d: %s", v.Repository(), tag, digest, got.Status, got.Reason)
	}
	t.Logf("%s:%s = %s, release %s, commit %s", v.Repository(), tag, digest, got.Release.Version, got.Release.Commit)
}
