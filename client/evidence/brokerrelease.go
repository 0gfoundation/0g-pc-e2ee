package evidence

// brokerrelease.go is how the compose checks ask which builds of 0G's broker image a
// provider may run — as an interface, deliberately, with the answer supplied by the
// caller.
//
// WHY A BOUND AT ALL. The per-service baseline (composebaseline.go) lets the three
// services that run the broker image move from one digest to another without a gateway
// release — that is the whole point of its `repository` rule. What they move TO has to be
// bounded, and "any digest in our repository" is no bound: the repository holds manual
// branch builds (the 2026-10-10 sweep found two running on mainnet, signed by the
// broker's docker-publish.yml on refs/heads/main) and every old release, including ones
// without the controller and ingress fixes the docker.sock exception rests on.
//
// WHY AN INTERFACE. The answer is now a signature check — the build's SLSA provenance,
// signed by the broker repository's release workflow on a release tag, at or above a
// minimum version (client/cmd/pcverify/provenance). That needs Sigstore's verifier and
// its dependency tree, and this package is imported by the gateway. Taking the answer
// through an interface keeps every byte of that out of the gateway binary until a
// decision to put it there is taken on purpose. It also replaced brokerreleases.json, a
// list someone had to edit on every broker release.

// BrokerRelease is one accepted build of the broker image.
type BrokerRelease struct {
	// Version is the release tag the build was made from, e.g. "v0.5.4". For reports.
	Version string
	// Digest is the image manifest digest the verdict is about.
	Digest string
	// Commit is the source commit the release was built from.
	Commit string
}

// ReleaseStatus is the outcome of checking one build.
type ReleaseStatus int

const (
	// ReleaseRejected is the zero value, so a verdict nobody filled in fails closed.
	ReleaseRejected ReleaseStatus = iota
	// ReleaseAccepted means the build is a release a provider may run.
	ReleaseAccepted
	// ReleaseUnavailable means the question could not be answered — the registry did not
	// answer, say. It is neither a pass nor a refutation, and callers report it as a
	// check that did not run.
	ReleaseUnavailable
)

// ReleaseVerdict is what a ReleaseVerifier concluded about one build.
type ReleaseVerdict struct {
	Status ReleaseStatus
	// Release is set when Status is ReleaseAccepted.
	Release BrokerRelease
	// Reason says why the build was rejected or could not be checked, in terms a reader
	// of the report can act on.
	Reason string
}

// ReleaseVerifier decides which builds of the broker image are acceptable.
type ReleaseVerifier interface {
	// Repository is the image repository whose builds it judges, as it appears in a
	// compose image reference — no tag, no digest.
	Repository() string
	// Verify judges repository@digest. A repository other than Repository() is rejected.
	Verify(repository, digest string) ReleaseVerdict
}

// verifyRelease asks rels about repository@digest, treating a missing verifier as a check
// that could not run rather than as a pass.
func verifyRelease(rels ReleaseVerifier, repository, digest string) ReleaseVerdict {
	if rels == nil {
		return ReleaseVerdict{Status: ReleaseUnavailable, Reason: "no release verifier was configured"}
	}
	return rels.Verify(repository, digest)
}
