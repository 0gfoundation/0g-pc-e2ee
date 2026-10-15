package evidence

import (
	"strings"
	"testing"
)

const brokerRepoName = "ghcr.io/0gfoundation/0g-serving-broker"

// The embedded list is v0.5.4, resolved against the registry rather than copied.
func TestBuiltinBrokerReleases_ListsV054(t *testing.T) {
	got, err := BuiltinBrokerReleases()
	if err != nil {
		t.Fatalf("the embedded release list does not parse: %v", err)
	}
	if got.Repository != brokerRepoName {
		t.Fatalf("repository = %q", got.Repository)
	}
	rel, ok := got.Lookup(brokerRepoName, "sha256:951f4c7971f87377ab077639a5a84d2aed8945460494da076ff8466ea1ee90b5")
	if !ok || rel.Version != "v0.5.4" {
		t.Fatalf("v0.5.4 not found: %+v %v", rel, ok)
	}
}

// v0.5.1 and v0.5.2 are real, tagged releases running on mainnet today, and are left out
// ON PURPOSE: they predate the controller and ingress fixes v0.5.4 carries. Pinned here so
// adding one back is a decision someone makes with this test and the file's header in
// front of them, not an entry that slips in with a fleet sweep.
func TestBuiltinBrokerReleases_OmitsReleasesBeforeV054(t *testing.T) {
	got, err := BuiltinBrokerReleases()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct{ version, prefix string }{
		{"v0.5.1", "sha256:ec5df834"},
		{"v0.5.2", "sha256:9d0ae9b9"},
	} {
		for _, rel := range got.Releases {
			if strings.HasPrefix(rel.Digest, d.prefix) || rel.Version == d.version {
				t.Errorf("%s is listed (%s); the header says why it is not", d.version, rel.Digest)
			}
		}
	}
}

// Both halves of a reference must agree. A listed digest under another repository is a
// copy whose provenance is unknown, not our release.
func TestBrokerReleases_LookupNeedsRepositoryAndDigest(t *testing.T) {
	rels := BrokerReleases{Repository: brokerRepoName, Releases: []BrokerRelease{{"v1", "sha256:" + strings.Repeat("a", 64)}}}
	if _, ok := rels.Lookup(brokerRepoName, "sha256:"+strings.Repeat("a", 64)); !ok {
		t.Fatal("the listed release was not found")
	}
	if _, ok := rels.Lookup("evil.example/0gfoundation/0g-serving-broker", "sha256:"+strings.Repeat("a", 64)); ok {
		t.Fatal("a listed digest under another repository was accepted")
	}
	if _, ok := rels.Lookup(brokerRepoName, "sha256:"+strings.Repeat("b", 64)); ok {
		t.Fatal("an unlisted digest was accepted")
	}
}

func TestParseBrokerReleases_Refuses(t *testing.T) {
	good := `"version": "v1", "digest": "sha256:` + strings.Repeat("a", 64) + `", "verified": ["resolved"]`
	for _, tc := range []struct{ name, doc, says string }{
		{"misspelled key — would decode to an empty list", `{"repository": "r", "relases": []}`, "unknown field"},
		{"no repository", `{"releases": []}`, "names no repository"},
		{"repository with a tag", `{"repository": "ghcr.io/x/y:v1", "releases": []}`, "bare repository"},
		{"repository with a digest", `{"repository": "ghcr.io/x/y@sha256:aa", "releases": []}`, "bare repository"},
		{"no version", `{"repository": "r", "releases": [{"digest": "sha256:` + strings.Repeat("a", 64) + `", "verified": ["x"]}]}`, "version is required"},
		{"uppercase hex", `{"repository": "r", "releases": [{"version": "v1", "digest": "sha256:` + strings.Repeat("A", 64) + `", "verified": ["x"]}]}`, "64"},
		{"short digest", `{"repository": "r", "releases": [{"version": "v1", "digest": "sha256:abc", "verified": ["x"]}]}`, "64"},
		{"another algorithm", `{"repository": "r", "releases": [{"version": "v1", "digest": "sha512:` + strings.Repeat("a", 64) + `", "verified": ["x"]}]}`, "64"},
		{"no provenance", `{"repository": "r", "releases": [{"version": "v1", "digest": "sha256:` + strings.Repeat("a", 64) + `"}]}`, "no verification"},
		{"version twice", `{"repository": "r", "releases": [{` + good + `}, {"version": "v1", "digest": "sha256:` + strings.Repeat("b", 64) + `", "verified": ["x"]}]}`, "listed twice"},
		{"digest twice", `{"repository": "r", "releases": [{` + good + `}, {"version": "v2", "digest": "sha256:` + strings.Repeat("a", 64) + `", "verified": ["x"]}]}`, "same digest"},
		{"trailing object", `{"repository": "r", "releases": []}{"repository": "r"}`, "trailing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseBrokerReleases([]byte(tc.doc))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.says)
			}
		})
	}

	// A registry port is not a tag.
	if _, err := ParseBrokerReleases([]byte(`{"repository": "localhost:5000/x/y", "releases": []}`)); err != nil {
		t.Fatalf("a repository with a registry port was refused: %v", err)
	}
}
