package provenance

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

// The fixtures in testdata are the real bundles attached to these builds in
// ghcr.io/0gfoundation/0g-serving-broker, fetched 2026-10-16. Each file's sha256 is the
// registry blob digest it was fetched by, so its origin can be re-checked against the
// registry at any time.
const (
	digestV054 = "sha256:951f4c7971f87377ab077639a5a84d2aed8945460494da076ff8466ea1ee90b5" // v0.5.4, testnet
	digestV052 = "sha256:9d0ae9b9cfb372a6c88d5f6810cc634804f67612fae20ac4fcde2afd6cd86fa4" // v0.5.2, cn-19
	digestV051 = "sha256:ec5df8347f91c3b28a6638db4e24dba343799c0a3a7e2cdd44845a3a27f2e734" // v0.5.1, cn-20
	// A manual docker-publish.yml build from refs/heads/main, running on cn-1/4/41.
	digestMain = "sha256:c51266405244225dc77e029a842f8a3c046e5cd28512688802e414b8411b1ac5"

	commitV054 = "da18e864e79b1e26e6d14e32f6f0717669afe681"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// embedded is a Verifier over the embedded policy and trust root, without a registry.
func embedded(t *testing.T) *Verifier {
	t.Helper()
	v, err := newVerifier(policyJSON, trustedRootJSON)
	if err != nil {
		t.Fatalf("the embedded policy or trust root does not load: %v", err)
	}
	return v
}

// withPolicy is a Verifier whose policy is the embedded one with edits applied.
func withPolicy(t *testing.T, edit func(p map[string]any)) *Verifier {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(policyJSON, &p); err != nil {
		t.Fatal(err)
	}
	edit(p)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := newVerifier(raw, trustedRootJSON)
	if err != nil {
		t.Fatalf("edited policy: %v", err)
	}
	return v
}

func TestEmbeddedPolicyAndTrustRoot(t *testing.T) {
	v := embedded(t)
	if v.Repository() != "ghcr.io/0gfoundation/0g-serving-broker" || v.policy.MinimumVersion != "v0.5.4" ||
		v.policy.Workflow != ".github/workflows/build.yml" {
		t.Fatalf("policy = %+v", v.policy)
	}
	// The snapshot's keys, pinned: a refresh is a reviewed change, not a silent one.
	for _, want := range []string{"https://rekor.sigstore.dev", "https://log2025-1.rekor.sigstore.dev",
		"https://fulcio.sigstore.dev", "https://ctfe.sigstore.dev/2022", "https://timestamp.sigstore.dev/api/v1/timestamp"} {
		if !strings.Contains(string(trustedRootJSON), want) {
			t.Errorf("the embedded trust root has no %s", want)
		}
	}
}

// What judge decides about the fleet's real builds.
func TestJudge_RealBundles(t *testing.T) {
	v := embedded(t)
	for _, tc := range []struct {
		name    string
		digest  string
		bundles []string
		accept  string // version, when accepted
		says    string // reason fragment, when rejected
	}{
		{"v0.5.4's provenance", digestV054, []string{"v0.5.4.slsa.json"}, "v0.5.4", ""},
		{"v0.5.4 with both of its bundles", digestV054, []string{"v0.5.4.cosign-sign.json", "v0.5.4.slsa.json"}, "v0.5.4", ""},
		// A valid signature from the release workflow is not provenance.
		{"v0.5.4's cosign signature alone", digestV054, []string{"v0.5.4.cosign-sign.json"}, "",
			"not SLSA provenance"},
		// Built and signed exactly as v0.5.4 was, and refused for what it predates.
		{"v0.5.2, a signed release below the minimum", digestV052, []string{"v0.5.2.slsa.json"}, "",
			"older than the minimum v0.5.4"},
		// Its provenance manifest is gone from the registry; the signature that remains is
		// from the release workflow, so it is the version that refuses it.
		{"v0.5.1, signature only", digestV051, []string{"v0.5.1.cosign-sign.json"}, "", "older than the minimum v0.5.4"},
		// Signed, validly, by the manual workflow on a branch.
		{"a manual build from main", digestMain, []string{"main-c5126640.cosign-sign.json"}, "",
			"docker-publish.yml@refs/heads/main"},
		// A bundle for another build proves nothing about this one.
		{"v0.5.4's provenance offered for v0.5.1", digestV051, []string{"v0.5.4.slsa.json"}, "", "does not verify"},
		{"no bundle", digestV054, nil, "", "no Sigstore bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bundles [][]byte
			for _, b := range tc.bundles {
				bundles = append(bundles, fixture(t, b))
			}
			got := v.judge(tc.digest, bundles)
			if tc.accept != "" {
				if got.Status != evidence.ReleaseAccepted || got.Release.Version != tc.accept || got.Release.Digest != tc.digest {
					t.Fatalf("got %+v, want release %s", got, tc.accept)
				}
				if got.Release.Commit != commitV054 {
					t.Fatalf("commit = %q, want %s", got.Release.Commit, commitV054)
				}
				return
			}
			if got.Status != evidence.ReleaseRejected || !strings.Contains(got.Reason, tc.says) {
				t.Fatalf("got %+v, want a rejection mentioning %q", got, tc.says)
			}
		})
	}
}

// Altering the signed statement — here, claiming a branch ref — must break verification,
// not change what the policy reads.
func TestJudge_TamperedProvenance(t *testing.T) {
	var b map[string]any
	if err := json.Unmarshal(fixture(t, "v0.5.4.slsa.json"), &b); err != nil {
		t.Fatal(err)
	}
	env := b["dsseEnvelope"].(map[string]any)
	payload, err := base64.StdEncoding.DecodeString(env["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(string(payload), "refs/tags/v0.5.4", "refs/heads/evil", 1)
	if altered == string(payload) {
		t.Fatal("the edit did not apply")
	}
	env["payload"] = base64.StdEncoding.EncodeToString([]byte(altered))
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	got := embedded(t).judge(digestV054, [][]byte{raw})
	if got.Status != evidence.ReleaseRejected || !strings.Contains(got.Reason, "does not verify") {
		t.Fatalf("a tampered statement: %+v", got)
	}
	if got := embedded(t).judge(digestV054, [][]byte{[]byte("not a bundle")}); got.Status != evidence.ReleaseRejected ||
		!strings.Contains(got.Reason, "does not parse") {
		t.Fatalf("garbage: %+v", got)
	}
}

// Each policy field binds: change it and v0.5.4 stops being accepted, for that reason.
func TestJudge_PolicyFieldsBind(t *testing.T) {
	slsa := [][]byte{fixture(t, "v0.5.4.slsa.json")}
	for _, tc := range []struct {
		name string
		edit func(p map[string]any)
		says string
	}{
		{"a higher minimum", func(p map[string]any) { p["minimum_version"] = "v0.5.5" }, "older than the minimum v0.5.5"},
		{"another workflow", func(p map[string]any) { p["workflow"] = ".github/workflows/docker-publish.yml" },
			"not by .github/workflows/docker-publish.yml on a release tag"},
		{"another source repository", func(p map[string]any) { p["source_repository"] = "https://github.com/0gfoundation/other" },
			"does not verify"},
		{"another issuer", func(p map[string]any) { p["issuer"] = "https://accounts.google.com" }, "does not verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := withPolicy(t, tc.edit).judge(digestV054, slsa)
			if got.Status != evidence.ReleaseRejected || !strings.Contains(got.Reason, tc.says) {
				t.Fatalf("got %+v, want a rejection mentioning %q", got, tc.says)
			}
		})
	}

	// A revoked build is refused before anything is fetched.
	v := withPolicy(t, func(p map[string]any) {
		p["revoked"] = []map[string]string{{"digest": digestV054, "reason": "test revocation"}}
	})
	if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseRejected ||
		!strings.Contains(got.Reason, "revoked in the provenance policy: test revocation") {
		t.Fatalf("revoked: %+v", got)
	}
}

func TestVerify_RefusesOtherRepositoriesAndMalformedDigests(t *testing.T) {
	v := embedded(t)
	if got := v.Verify("ghcr.io/someone/0g-serving-broker", digestV054); got.Status != evidence.ReleaseRejected {
		t.Fatalf("another repository: %+v", got)
	}
	if got := v.Verify(v.Repository(), "sha256:abc"); got.Status != evidence.ReleaseRejected {
		t.Fatalf("a malformed digest: %+v", got)
	}
}

func TestParsePolicy_Refuses(t *testing.T) {
	good := func() map[string]any {
		var p map[string]any
		_ = json.Unmarshal(policyJSON, &p)
		return p
	}
	for _, tc := range []struct {
		name string
		edit func(p map[string]any)
		says string
	}{
		{"a misspelled key", func(p map[string]any) { p["minimum_verison"] = "v9.9.9" }, "unknown field"},
		{"a repository with a tag", func(p map[string]any) { p["repository"] = "ghcr.io/x/y:v1" }, "bare image repository"},
		{"a source that is not GitHub", func(p map[string]any) { p["source_repository"] = "https://gitlab.com/x/y" }, "github.com"},
		{"a workflow outside .github/workflows", func(p map[string]any) { p["workflow"] = "build.yml" }, ".github/workflows"},
		{"no issuer", func(p map[string]any) { p["issuer"] = "" }, "issuer"},
		{"a minimum that is not a release tag", func(p map[string]any) { p["minimum_version"] = "0.5.4" }, "vMAJOR"},
		{"a revocation without a reason", func(p map[string]any) {
			p["revoked"] = []map[string]string{{"digest": digestV054, "reason": ""}}
		}, "reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := good()
			tc.edit(p)
			raw, _ := json.Marshal(p)
			if _, err := ParsePolicy(raw); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.says)
			}
		})
	}
}

func TestVersionLess(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		less bool
	}{
		{"v0.5.2", "v0.5.4", true}, {"v0.5.4", "v0.5.4", false}, {"v0.5.10", "v0.5.4", false},
		{"v0.6.0", "v0.5.4", false}, {"v1.0.0", "v0.99.99", false}, {"v0.4.99", "v0.5.0", true},
	} {
		if got := versionLess(tc.a, tc.b); got != tc.less {
			t.Errorf("versionLess(%s, %s) = %v", tc.a, tc.b, got)
		}
	}
}

// The certificate checks no real bundle on the fleet exercises, one at a time: each
// result below is what sigstore-go would return for a bundle that verified, with one
// field of the signing certificate other than the release workflow's.
func TestRelease_EachCertificateFieldBinds(t *testing.T) {
	v := embedded(t)
	good := func() *verify.VerificationResult {
		return &verify.VerificationResult{
			Statement: &intoto.Statement{PredicateType: slsaProvenanceV1},
			Signature: &verify.SignatureVerificationResult{Certificate: &certificate.Summary{
				SubjectAlternativeName: "https://github.com/0gfoundation/0g-serving-broker/.github/workflows/build.yml@refs/tags/v0.5.4",
				Extensions: certificate.Extensions{
					SourceRepositoryURI:    "https://github.com/0gfoundation/0g-serving-broker",
					SourceRepositoryRef:    "refs/tags/v0.5.4",
					SourceRepositoryDigest: commitV054,
					BuildTrigger:           "push",
					RunnerEnvironment:      "github-hosted",
				},
			}},
		}
	}
	if rel, why := v.release(digestV054, good()); why != "" || rel.Version != "v0.5.4" || rel.Commit != commitV054 {
		t.Fatalf("the premise: a release-workflow result is accepted (%+v, %q)", rel, why)
	}
	for _, tc := range []struct {
		name string
		edit func(r *verify.VerificationResult)
		says string
	}{
		{"a branch build of the release workflow", func(r *verify.VerificationResult) {
			r.Signature.Certificate.SubjectAlternativeName = strings.Replace(r.Signature.Certificate.SubjectAlternativeName,
				"refs/tags/v0.5.4", "refs/heads/main", 1)
		}, "not by .github/workflows/build.yml on a release tag"},
		{"a tag that is not a release version", func(r *verify.VerificationResult) {
			r.Signature.Certificate.SubjectAlternativeName = strings.Replace(r.Signature.Certificate.SubjectAlternativeName,
				"v0.5.4", "v0.5.4-rc1", 1)
		}, "on a release tag"},
		{"built from a fork", func(r *verify.VerificationResult) {
			r.Signature.Certificate.SourceRepositoryURI = "https://github.com/someone/0g-serving-broker"
		}, "built from https://github.com/someone"},
		{"a source ref other than the tag", func(r *verify.VerificationResult) {
			r.Signature.Certificate.SourceRepositoryRef = "refs/heads/main"
		}, "names source ref refs/heads/main"},
		{"a manual run of the release workflow", func(r *verify.VerificationResult) {
			r.Signature.Certificate.BuildTrigger = "workflow_dispatch"
		}, `ran on "workflow_dispatch"`},
		{"a self-hosted runner", func(r *verify.VerificationResult) {
			r.Signature.Certificate.RunnerEnvironment = "self-hosted"
		}, `"self-hosted" runner`},
		{"no statement", func(r *verify.VerificationResult) { r.Statement = nil }, "not SLSA provenance"},
		{"no certificate", func(r *verify.VerificationResult) { r.Signature = nil }, "not signed by a certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good()
			tc.edit(r)
			if _, why := v.release(digestV054, r); !strings.Contains(why, tc.says) {
				t.Fatalf("reason %q, want it to mention %q", why, tc.says)
			}
		})
	}
}
