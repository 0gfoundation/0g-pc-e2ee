package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

// defaultReleaseRepo and defaultReleaseAsset are where the digest-pinned deployment
// manifest is published (.github/workflows/release.yml). They are defaults so the
// common case is `-releases N` with nothing else.
const (
	defaultReleaseRepo  = "0gfoundation/0g-pc-e2ee"
	defaultReleaseAsset = "docker-compose.release.yml"
)

// maxAssetBytes bounds each release-asset download. The manifest is a compose file.
const maxAssetBytes = 1 << 20

// githubAPI is the API base, a variable only so tests can point it at a local
// server. Nothing configurable by a flag: aiming release lookups at an arbitrary
// host is not a knob an operator should have.
var githubAPI = "https://api.github.com"

// ghRelease is the subset of the GitHub releases API this needs.
type ghRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// fetchReleaseComposeFiles returns the deployment manifest from each of the newest
// `count` releases of repo ("owner/name"), newest first, labelled by release tag.
//
// This is the discovery form of the compose-file check: "is what is running one of
// the manifests we published, and which one?" — versus pinning a single file, which
// asks "is it exactly the one I meant to deploy". The answer "none of them" is the
// finding that matters, so a release with no such asset is skipped with a note
// rather than treated as a match-anything.
//
// GITHUB_TOKEN / GH_TOKEN is used when set. It is only needed for a private repo or
// to lift the unauthenticated rate limit; a public repo verifies with no
// credentials, which is the point — a third party must be able to run this.
//
// GitHub is a trust assumption here, and an unavoidable one: it is the publisher of
// record for what "we released". It is also not a *silent* one — the compose text
// this returns is only ever compared against a text the quote already
// authenticated, so a tampered release asset causes a mismatch, never a false pass.
func fetchReleaseComposeFiles(ctx context.Context, hc *http.Client, repo, asset string, count int, warn io.Writer) ([]evidence.ExpectedCompose, error) {
	owner, name, ok := strings.Cut(strings.TrimSpace(repo), "/")
	if !ok || owner == "" || name == "" {
		return nil, fmt.Errorf("-repo %q is not owner/name", repo)
	}
	if count <= 0 {
		return nil, fmt.Errorf("-releases must be positive, got %d", count)
	}

	// per_page returns newest first, so no client-side sorting is needed. Ask for a
	// few extra so drafts/prereleases being skipped cannot silently shrink the set
	// below what was asked for.
	perPage := min(count*2, 100)
	listURL := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=%d",
		githubAPI, url.PathEscape(owner), url.PathEscape(name), perPage)
	var releases []ghRelease
	if err := ghJSON(ctx, hc, listURL, &releases); err != nil {
		return nil, fmt.Errorf("list releases for %s/%s: %w", owner, name, err)
	}

	var out []evidence.ExpectedCompose
	for _, r := range releases {
		if len(out) == count {
			break
		}
		// A draft is not published, and a prerelease was not meant for production; a
		// deployment matching one is a finding, not a pass.
		if r.Draft || r.Prerelease {
			continue
		}
		var assetURL string
		for _, a := range r.Assets {
			if a.Name == asset {
				assetURL = a.URL
				break
			}
		}
		if assetURL == "" {
			fmt.Fprintf(warn, "  note             release %s has no %s asset; skipped\n", r.TagName, asset)
			continue
		}
		body, err := ghBytes(ctx, hc, assetURL)
		if err != nil {
			return nil, fmt.Errorf("download %s from release %s: %w", asset, r.TagName, err)
		}
		out = append(out, evidence.ExpectedCompose{Label: r.TagName, Content: body})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no published release of %s/%s carries a %s asset", owner, name, asset)
	}
	return out, nil
}

// ghJSON GETs url and decodes the JSON body into v.
func ghJSON(ctx context.Context, hc *http.Client, url string, v any) error {
	body, err := ghBytes(ctx, hc, url)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// ghBytes GETs url with the GitHub API headers and returns the body.
func ghBytes(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAssetBytes+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// Rate limiting is the most likely failure for an unauthenticated run, and the
		// fix (set a token) is not obvious from a bare 403.
		if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return nil, fmt.Errorf("%s (GitHub rate limit exhausted; set GITHUB_TOKEN to raise it)", resp.Status)
		}
		return nil, fmt.Errorf("GET %s -> %s", url, resp.Status)
	}
	if len(body) > maxAssetBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", url, maxAssetBytes)
	}
	return body, nil
}

func githubToken() string {
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// newGitHubClient is the HTTP client for the release lookups — separate from the
// evidence checker's, so -allow-untrusted-cert can never loosen TLS against GitHub.
func newGitHubClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}
