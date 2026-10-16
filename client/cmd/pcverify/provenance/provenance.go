// Package provenance decides which builds of 0G's broker image a provider may run, by
// verifying each build's signed SLSA provenance at run time.
//
// It answers the question client/evidence asks through evidence.ReleaseVerifier: the
// per-service baseline lets the broker services move between builds, and the docker.sock
// exception rests on code that only some builds carry, so both need to know whether a
// digest is a release. The answer used to be an embedded list edited by hand on every
// broker release; it is now a signature check against a policy (policy.json) that does
// not change when the broker ships.
//
// WHAT IS CHECKED, for repository@digest:
//
//   - The registry holds a Sigstore bundle attached to the digest (an OCI referrer).
//   - The bundle verifies against Sigstore's public-good trust root (trusted_root.json):
//     the certificate chains to Fulcio, the signature covers a statement about exactly
//     this digest, and the entry is in the Rekor transparency log.
//   - The statement is SLSA v1 provenance — not merely a signature over the image.
//   - The signing certificate was issued to the broker repository's release workflow
//     (policy.workflow) running on a release tag, triggered by the tag push, on a
//     GitHub-hosted runner; and the tag is at or above policy.minimum_version.
//   - The digest is not in policy.revoked.
//
// Every field the policy is applied to comes from the verified certificate, never from
// the unverified bundle or from the registry's own annotations.
//
// WHY ITS OWN MODULE (client/cmd/pcverify). Sigstore's verifier and the dependency
// versions it requires would otherwise move the versions the gateway is built with; see
// the go.mod there.
package provenance

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

// policy.json is EMBEDDED, like every allowlist in this repository: a verifier needs no
// configuration and cannot be pointed at a friendlier policy by accident.
//
//go:embed policy.json
var policyJSON []byte

// trusted_root.json is Sigstore's public-good trust root — the Fulcio CAs, Rekor and CT
// log keys and the timestamp authority — as sigstore-go's TUF client fetched and verified
// it from tuf-repo-cdn.sigstore.dev on snapshotDate. It is the FALLBACK, not the root a
// run normally uses: each run first fetches the current trust root over TUF (trust.go),
// so a Sigstore key rotation or a new log shard needs no release here. The snapshot is
// used only when TUF cannot be reached, and then a bundle that does not verify against
// it is reported as a check that did not run rather than as a refusal — it may have been
// signed under a key the snapshot predates. TestEmbeddedPolicyAndTrustRoot pins which
// keys it holds.
//
//go:embed trusted_root.json
var trustedRootJSON []byte

// snapshotDate is when trusted_root.json was fetched, for reports.
const snapshotDate = "2026-10-16"

// slsaProvenanceV1 is the only predicate accepted. The broker's release workflow also
// signs the image with `cosign sign` (predicate https://sigstore.dev/cosign/sign/v1), and
// so does its manual workflow; the provenance is what records how the build was made.
const slsaProvenanceV1 = "https://slsa.dev/provenance/v1"

// Policy is the decoded policy.json.
type Policy struct {
	// Repository is the image repository judged, as compose references it.
	Repository string `json:"repository"`
	// SourceRepository is the GitHub repository whose workflow must have signed.
	SourceRepository string `json:"source_repository"`
	// Workflow is the workflow file, relative to the repository root.
	Workflow string `json:"workflow"`
	// Issuer is the OIDC issuer of the signing identity.
	Issuer string `json:"issuer"`
	// MinimumVersion is the oldest release accepted, vMAJOR.MINOR.PATCH.
	MinimumVersion string `json:"minimum_version"`
	// Revoked are builds refused despite a valid signature.
	Revoked []Revocation `json:"revoked"`
	// Comment is the file's own explanation; never read.
	Comment []string `json:"_comment"`
}

// Revocation is one refused build.
type Revocation struct {
	Digest string `json:"digest"`
	Reason string `json:"reason"`
}

// releaseTag is a release tag as the policy accepts it.
var releaseTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ParsePolicy decodes and validates a policy. Unknown keys are refused, so a misspelled
// field cannot silently loosen it.
func ParsePolicy(raw []byte) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("provenance policy is not valid JSON: %w", err)
	}
	if dec.More() {
		return Policy{}, errors.New("provenance policy is not valid JSON: trailing content after the first object")
	}
	switch {
	case p.Repository == "" || strings.ContainsAny(p.Repository, "@") || strings.Contains(lastSegment(p.Repository), ":"):
		return Policy{}, fmt.Errorf("provenance policy: repository %q must be a bare image repository", p.Repository)
	case !strings.HasPrefix(p.SourceRepository, "https://github.com/") || strings.Count(p.SourceRepository, "/") != 4:
		return Policy{}, fmt.Errorf("provenance policy: source_repository %q must be https://github.com/OWNER/REPO",
			p.SourceRepository)
	case !strings.HasPrefix(p.Workflow, ".github/workflows/"):
		return Policy{}, fmt.Errorf("provenance policy: workflow %q must be a file under .github/workflows/", p.Workflow)
	case p.Issuer == "":
		return Policy{}, errors.New("provenance policy: issuer is required")
	case !releaseTag.MatchString(p.MinimumVersion):
		return Policy{}, fmt.Errorf("provenance policy: minimum_version %q is not vMAJOR.MINOR.PATCH", p.MinimumVersion)
	}
	for _, r := range p.Revoked {
		if !isSHA256Digest(r.Digest) || strings.TrimSpace(r.Reason) == "" {
			return Policy{}, fmt.Errorf("provenance policy: revoked entry %q needs a sha256 digest and a reason", r.Digest)
		}
	}
	return p, nil
}

// signerPrefix is the certificate SAN of the release workflow, up to the ref.
func (p Policy) signerPrefix() string {
	return p.SourceRepository + "/" + p.Workflow + "@"
}

// Verifier is an evidence.ReleaseVerifier backed by provenance verification. Each digest
// is judged once per Verifier; a run builds one.
type Verifier struct {
	policy   Policy
	registry *registry

	// snapshot verifies against the embedded trust root. fetchRoot, when set, supplies the
	// current one; it is called at most once, on the first digest that needs it.
	snapshot  *verify.Verifier
	fetchRoot func() (root.TrustedMaterial, error)
	trustOnce sync.Once
	trusted   trust

	mu    sync.Mutex
	cache map[string]evidence.ReleaseVerdict
}

// New builds a Verifier from the embedded policy, the current Sigstore trust root (fetched
// over TUF with client, on first use) and the embedded snapshot as its fallback. timeout
// bounds the registry fetches for one digest. An error means an embedded file is
// malformed — a defect in this build, not a statement about any provider.
func New(client *http.Client, timeout time.Duration) (*Verifier, error) {
	v, err := newVerifier(policyJSON, trustedRootJSON)
	if err != nil {
		return nil, err
	}
	v.registry = newRegistry(client, timeout)
	v.fetchRoot = func() (root.TrustedMaterial, error) { return fetchTrustedRoot(client) }
	return v, nil
}

func newVerifier(policy, trustedRoot []byte) (*Verifier, error) {
	p, err := ParsePolicy(policy)
	if err != nil {
		return nil, err
	}
	tr, err := root.NewTrustedRootFromJSON(trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("embedded Sigstore trust root: %w", err)
	}
	sv, err := sigstoreVerifier(tr)
	if err != nil {
		return nil, fmt.Errorf("embedded Sigstore trust root: %w", err)
	}
	return &Verifier{policy: p, snapshot: sv, cache: map[string]evidence.ReleaseVerdict{}}, nil
}

// sigstoreVerifier verifies bundles against tm. One signed certificate timestamp, one
// transparency log entry, one observed timestamp: what every bundle Sigstore's
// public-good instance issues carries.
func sigstoreVerifier(tm root.TrustedMaterial) (*verify.Verifier, error) {
	return verify.NewVerifier(tm, verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
}

// Repository implements evidence.ReleaseVerifier.
func (v *Verifier) Repository() string { return v.policy.Repository }

// Verify implements evidence.ReleaseVerifier.
func (v *Verifier) Verify(repository, digest string) evidence.ReleaseVerdict {
	switch {
	case repository != v.policy.Repository:
		return rejected("the build is in %s; release provenance is checked for %s only", repository, v.policy.Repository)
	case !isSHA256Digest(digest):
		return rejected("%q is not a sha256 digest", digest)
	}
	v.mu.Lock()
	cached, ok := v.cache[digest]
	v.mu.Unlock()
	if ok {
		return cached
	}

	verdict := v.check(digest)
	v.mu.Lock()
	v.cache[digest] = verdict
	v.mu.Unlock()
	return verdict
}

func (v *Verifier) check(digest string) evidence.ReleaseVerdict {
	for _, r := range v.policy.Revoked {
		if r.Digest == digest {
			return rejected("the build is revoked in the provenance policy: %s", r.Reason)
		}
	}
	bundles, err := v.registry.bundles(v.policy.Repository, digest)
	var unavailable *unavailableError
	switch {
	case errors.As(err, &unavailable):
		return evidence.ReleaseVerdict{Status: evidence.ReleaseUnavailable, Reason: err.Error()}
	case err != nil:
		return rejected("%v", err)
	}
	return v.judge(digest, bundles)
}

// judge decides from bundles already fetched. Separate from the network so that what it
// decides can be tested against real bundles offline.
func (v *Verifier) judge(digest string, bundles [][]byte) evidence.ReleaseVerdict {
	if len(bundles) == 0 {
		return rejected("the registry has no Sigstore bundle attached to it, so nothing says how it was built")
	}
	want, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil {
		return rejected("%q is not a sha256 digest", digest)
	}
	// The identity sigstore-go enforces is deliberately the REPOSITORY, not yet the
	// release workflow: a build signed by the broker's manual workflow then verifies, and
	// the policy below can say exactly why it is still refused instead of reporting a
	// bare identity mismatch.
	identity, err := verify.NewShortCertificateIdentity(v.policy.Issuer, "", "",
		"^"+regexp.QuoteMeta(v.policy.SourceRepository+"/"))
	if err != nil {
		return rejected("certificate identity: %v", err)
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", want), verify.WithCertificateIdentity(identity))

	trust := v.trust()
	var reasons []string
	unverified := false
	for _, raw := range bundles {
		var b bundle.Bundle
		if err := b.UnmarshalJSON(raw); err != nil {
			reasons = append(reasons, fmt.Sprintf("an attached bundle does not parse: %v", err))
			continue
		}
		res, err := trust.sigstore.Verify(&b, policy)
		if err != nil {
			unverified = true
			reasons = append(reasons, fmt.Sprintf("an attached bundle does not verify: %v", err))
			continue
		}
		rel, why := v.release(digest, res)
		if why == "" {
			return evidence.ReleaseVerdict{Status: evidence.ReleaseAccepted, Release: rel}
		}
		reasons = append(reasons, why)
	}
	if unverified && trust.stale != "" {
		// Against the snapshot, a bundle that does not verify may only be newer than it.
		return evidence.ReleaseVerdict{Status: evidence.ReleaseUnavailable,
			Reason: strings.Join(dedupe(reasons), "; ") + "; " + trust.stale}
	}
	return rejected("%s", strings.Join(dedupe(reasons), "; "))
}

// release applies the policy to one verified bundle. The checks run in the order a reader
// needs the answer: WHO signed it (the release workflow on a release tag?), then WHICH
// release it is (old enough to lack the fixes?), then WHAT was signed (provenance, or only
// a signature over the image?). Every field read here is from the verified certificate
// or the verified statement.
func (v *Verifier) release(digest string, res *verify.VerificationResult) (evidence.BrokerRelease, string) {
	if res.Signature == nil || res.Signature.Certificate == nil {
		return evidence.BrokerRelease{}, "a bundle is not signed by a certificate"
	}
	c := res.Signature.Certificate
	prefix := v.policy.signerPrefix()
	tag := strings.TrimPrefix(c.SubjectAlternativeName, prefix+"refs/tags/")
	switch {
	case !strings.HasPrefix(c.SubjectAlternativeName, prefix+"refs/tags/") || !releaseTag.MatchString(tag):
		return evidence.BrokerRelease{}, fmt.Sprintf("it is signed by %s, not by %s on a release tag",
			c.SubjectAlternativeName, v.policy.Workflow)
	case c.SourceRepositoryURI != v.policy.SourceRepository:
		return evidence.BrokerRelease{}, fmt.Sprintf("it was built from %s, not %s",
			c.SourceRepositoryURI, v.policy.SourceRepository)
	case c.SourceRepositoryRef != "refs/tags/"+tag:
		return evidence.BrokerRelease{}, fmt.Sprintf("its certificate names source ref %s but was issued for tag %s",
			c.SourceRepositoryRef, tag)
	case c.BuildTrigger != "push":
		return evidence.BrokerRelease{}, fmt.Sprintf("its release workflow ran on %q, not on the tag push", c.BuildTrigger)
	case c.RunnerEnvironment != "github-hosted":
		return evidence.BrokerRelease{}, fmt.Sprintf("it was built on a %q runner, not a GitHub-hosted one",
			c.RunnerEnvironment)
	case versionLess(tag, v.policy.MinimumVersion):
		return evidence.BrokerRelease{}, fmt.Sprintf("it is release %s, older than the minimum %s the provenance "+
			"policy accepts", tag, v.policy.MinimumVersion)
	case res.Statement == nil || res.Statement.GetPredicateType() != slsaProvenanceV1:
		pt := "no statement"
		if res.Statement != nil {
			pt = res.Statement.GetPredicateType()
		}
		return evidence.BrokerRelease{}, fmt.Sprintf("release %s's bundle is %s, not SLSA provenance", tag, pt)
	}
	return evidence.BrokerRelease{Version: tag, Digest: digest, Commit: c.SourceRepositoryDigest}, ""
}

func rejected(format string, args ...any) evidence.ReleaseVerdict {
	return evidence.ReleaseVerdict{Status: evidence.ReleaseRejected, Reason: fmt.Sprintf(format, args...)}
}

// versionLess reports whether release tag a is older than b. Both match releaseTag.
func versionLess(a, b string) bool {
	pa, pb := releaseTag.FindStringSubmatch(a), releaseTag.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}

func isSHA256Digest(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
