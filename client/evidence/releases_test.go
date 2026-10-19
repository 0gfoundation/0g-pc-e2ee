package evidence

const (
	brokerRepoName = "ghcr.io/0gfoundation/0g-serving-broker"
	// v054Digest is broker v0.5.4, the build testnet runs.
	v054Digest = "sha256:951f4c7971f87377ab077639a5a84d2aed8945460494da076ff8466ea1ee90b5"
)

// fakeReleases is a ReleaseVerifier with a fixed answer per digest. The real one checks
// signatures (client/provenance) and is tested there against real bundles;
// what this package tests is what the compose checks DO with each verdict.
type fakeReleases struct {
	repo     string
	accepted map[string]string // digest -> version
	// unavailable makes every check come back ReleaseUnavailable.
	unavailable bool
}

func (f fakeReleases) Repository() string { return f.repo }

func (f fakeReleases) Verify(repository, digest string) ReleaseVerdict {
	switch {
	case repository != f.repo:
		return ReleaseVerdict{Reason: "the build is not in the repository this verifier judges"}
	case f.unavailable:
		return ReleaseVerdict{Status: ReleaseUnavailable, Reason: "the registry did not answer"}
	}
	if v, ok := f.accepted[digest]; ok {
		return ReleaseVerdict{Status: ReleaseAccepted, Release: BrokerRelease{Version: v, Digest: digest, Commit: "c0ffee"}}
	}
	return ReleaseVerdict{Reason: "it carries no provenance from the release workflow"}
}

// fleetReleases accepts what the real verifier accepts among the builds the recorded
// deployments run: v0.5.4, and not v0.5.1 (cn-20).
var fleetReleases = fakeReleases{repo: brokerRepoName, accepted: map[string]string{v054Digest: "v0.5.4"}}
