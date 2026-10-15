package evidence

// brokerrelease.go holds the builds of 0G's broker image that a provider may run.
//
// The per-service baseline (composebaseline.go) lets the three services that run the
// broker image move from one digest to another without a gateway release — that is the
// whole point of its `repository` rule. What it moves TO has to be bounded by something,
// and "any digest in our repository" turned out to be no bound at all: the 2026-10-10
// fleet sweep found four broker digests, and on 2026-10-15 two of them were pointed at by
// no release tag, so the repository rule would have accepted builds nobody released. This
// file is the bound. A repository-rule service matches only when its digest is listed
// here.

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

// brokerreleases.json is EMBEDDED for the reason every allowlist in this package is: a
// verifier needs no configuration and cannot be pointed at a friendlier list by
// accident, and reviewing the list is reviewing this repository.
//
//go:embed brokerreleases.json
var brokerReleasesFS embed.FS

// BrokerRelease is one build of the broker image a provider may run.
type BrokerRelease struct {
	// Version is the release's name, for reports. Never compared: a tag is mutable, and
	// the point of the list is that it pins content.
	Version string
	// Digest is the image manifest digest, "sha256:" and 64 lowercase hex.
	Digest string
}

// BrokerReleases is the acceptance list for one image repository.
type BrokerReleases struct {
	// Repository is the image repository the releases belong to, as it appears in a
	// compose image reference — no tag, no digest.
	Repository string
	Releases   []BrokerRelease
}

// Lookup reports the release a reference names. Both the repository and the digest
// have to agree: a listed digest pulled from some other repository is not our release,
// it is a copy of it whose provenance we do not know.
func (r BrokerReleases) Lookup(repository, digest string) (BrokerRelease, bool) {
	if repository != r.Repository {
		return BrokerRelease{}, false
	}
	for _, rel := range r.Releases {
		if rel.Digest == digest {
			return rel, true
		}
	}
	return BrokerRelease{}, false
}

// brokerReleasesFile is the on-disk shape. Every key is declared, including the ones
// this code never reads, because the decode refuses unknown keys: a misspelled
// "relases" would otherwise decode to an empty list and refuse every provider while
// the file looked fine.
type brokerReleasesFile struct {
	Comment    []string `json:"_comment"`
	Repository string   `json:"repository"`
	Releases   []struct {
		Version string `json:"version"`
		Digest  string `json:"digest"`
		// Verified records HOW the digest was established to be this release. Never
		// read: it is the audit trail, and an entry whose trail says "copied from a
		// running provider" is worth nothing whatever the code thinks of it.
		Verified []string `json:"verified"`
	} `json:"releases"`
}

// BuiltinBrokerReleases returns the embedded release list. An error means the embedded
// file is malformed — a build-time mistake in this repository, which callers must
// surface rather than treat as an empty list.
func BuiltinBrokerReleases() (BrokerReleases, error) {
	const file = "brokerreleases.json"
	raw, err := brokerReleasesFS.ReadFile(file)
	if err != nil {
		return BrokerReleases{}, fmt.Errorf("read embedded broker release list: %w", err)
	}
	rels, err := ParseBrokerReleases(raw)
	if err != nil {
		return BrokerReleases{}, fmt.Errorf("%s: %w", file, err)
	}
	return rels, nil
}

// ParseBrokerReleases decodes a release list.
//
// Strict about the digest's SHAPE as well as its presence. Anything looser than
// "sha256:" and 64 lowercase hex would let an entry name a prefix or a different
// algorithm, and the comparison is an exact string match against the reference the
// compose carries — so a malformed entry would not fail loudly, it would simply never
// match and refuse every provider while reading as configured.
func ParseBrokerReleases(raw []byte) (BrokerReleases, error) {
	var f brokerReleasesFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return BrokerReleases{}, fmt.Errorf("broker release list is not valid JSON: %w", err)
	}
	if dec.More() {
		return BrokerReleases{}, fmt.Errorf("broker release list is not valid JSON: trailing content after the first object")
	}

	out := BrokerReleases{Repository: strings.TrimSpace(f.Repository)}
	if out.Repository == "" {
		return BrokerReleases{}, fmt.Errorf("broker release list names no repository")
	}
	if strings.ContainsAny(out.Repository, "@") || strings.Contains(lastPathSegment(out.Repository), ":") {
		return BrokerReleases{}, fmt.Errorf("broker release list repository %q carries a tag or digest; "+
			"it must be the bare repository", out.Repository)
	}

	seenDigest := map[string]string{}
	seenVersion := map[string]bool{}
	for i, e := range f.Releases {
		label := e.Version
		if label == "" {
			label = fmt.Sprintf("entry %d", i+1)
		}
		v, d := strings.TrimSpace(e.Version), strings.TrimSpace(e.Digest)
		switch {
		case v == "":
			return BrokerReleases{}, fmt.Errorf("broker release %s: version is required", label)
		case !isSHA256Digest(d):
			return BrokerReleases{}, fmt.Errorf("broker release %s: digest %q is not sha256: followed by 64 "+
				"lowercase hex", label, d)
		case seenVersion[v]:
			return BrokerReleases{}, fmt.Errorf("broker release %s is listed twice", v)
		case seenDigest[d] != "":
			return BrokerReleases{}, fmt.Errorf("broker release %s has the same digest as %s; one build cannot "+
				"be two releases", v, seenDigest[d])
		case len(e.Verified) == 0:
			// The file's value is entirely in where its digests came from, and there is no
			// way to tell a verified entry from a copied one by looking at the digest.
			return BrokerReleases{}, fmt.Errorf("broker release %s records no verification; an entry with no "+
				"provenance cannot be told apart from one copied off a running provider", v)
		}
		seenVersion[v], seenDigest[d] = true, v
		out.Releases = append(out.Releases, BrokerRelease{Version: v, Digest: d})
	}
	return out, nil
}

// isSHA256Digest reports whether s is exactly "sha256:" and 64 lowercase hex.
func isSHA256Digest(s string) bool {
	const p = "sha256:"
	if !strings.HasPrefix(s, p) || len(s) != len(p)+64 {
		return false
	}
	for _, c := range s[len(p):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// lastPathSegment returns what follows the final "/", so a registry port
// ("localhost:5000/x") is not mistaken for a tag.
func lastPathSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}
