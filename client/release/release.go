// Package release reads the digest-pinned deployment manifest out of this
// repository's published GitHub releases.
//
// It answers "is what is running one of the manifests we published, and which
// one?" — the discovery form of the compose-file check, as opposed to pinning a
// single file, which asks "is it exactly the one I meant to deploy". Two callers
// need that answer and must agree on it: `pcverify -gateway`, which compares a
// published manifest against the compose text a quote authenticated, and the
// gateway's own /v1/gateway/identity endpoint, which reports which release the
// running deployment corresponds to. They share this package so a value the
// endpoint displays and a value pcverify verifies can never come from two
// slightly different lookups.
//
// GitHub is a trust assumption here, and an unavoidable one: it is the publisher
// of record for what "we released". It is also not a *silent* one — the compose
// text this returns is only ever compared against a text the quote already
// authenticated, so a tampered release asset causes a mismatch, never a false
// pass.
package release

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
)

// DefaultRepo and DefaultAsset are where the digest-pinned deployment manifest is
// published (.github/workflows/release.yml). They are defaults so the common case
// is a count and nothing else.
const (
	DefaultRepo  = "0gfoundation/0g-pc-e2ee"
	DefaultAsset = "docker-compose.release.yml"
)

// DefaultAPIBase is GitHub's API root. Config.APIBase overrides it for tests
// only: aiming release lookups at an arbitrary host is not a knob an operator
// should have, so nothing plumbs it to a flag or an env var.
const DefaultAPIBase = "https://api.github.com"

// maxAssetBytes bounds each release-asset download. The manifest is a compose file.
const maxAssetBytes = 1 << 20

// Asset is one release's deployment manifest: the bytes, plus the provenance a
// report or a UI needs to name where they came from.
type Asset struct {
	// Tag is the release tag, e.g. "release-2026.08.07.1".
	Tag string
	// URL is the release's page on GitHub — what a "which release is this?" link
	// points at. Empty if the API did not return one.
	URL string
	// Content is the asset's bytes, compared byte-for-byte against the compose text
	// the quote authenticated.
	Content []byte
}

// Config locates the releases to read.
type Config struct {
	// HTTP is the client to use. Required — callers own the timeout, and the
	// verifier deliberately keeps this client separate from the one it uses against
	// the deployment being checked, so a "relax TLS" option there can never loosen
	// TLS against GitHub.
	HTTP *http.Client
	// Repo is "owner/name"; empty means DefaultRepo.
	Repo string
	// Asset is the release-asset filename to download; empty means DefaultAsset.
	Asset string
	// APIBase overrides DefaultAPIBase. Tests only.
	APIBase string
}

func (c Config) repo() string    { return orDefault(c.Repo, DefaultRepo) }
func (c Config) asset() string   { return orDefault(c.Asset, DefaultAsset) }
func (c Config) apiBase() string { return orDefault(c.APIBase, DefaultAPIBase) }

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// FetchComposeAssets returns the deployment manifest from each of the newest
// `count` releases, newest first.
//
// The answer "matches none of them" is the finding that matters, so a release
// with no such asset is skipped with a note to warn rather than treated as a
// match-anything. warn may be nil.
//
// GITHUB_TOKEN / GH_TOKEN is used when set. It is only needed for a private repo
// or to lift the unauthenticated rate limit; a public repo verifies with no
// credentials, which is the point — a third party must be able to run this.
func FetchComposeAssets(ctx context.Context, cfg Config, count int, warn io.Writer) ([]Asset, error) {
	if cfg.HTTP == nil {
		return nil, fmt.Errorf("release: no HTTP client configured")
	}
	if warn == nil {
		warn = io.Discard
	}
	repo, asset := cfg.repo(), cfg.asset()
	owner, name, ok := strings.Cut(strings.TrimSpace(repo), "/")
	if !ok || owner == "" || name == "" {
		return nil, fmt.Errorf("release repo %q is not owner/name", repo)
	}
	if count <= 0 {
		return nil, fmt.Errorf("release count must be positive, got %d", count)
	}

	// per_page returns newest first, so no client-side sorting is needed. Ask for a
	// few extra so drafts/prereleases being skipped cannot silently shrink the set
	// below what was asked for.
	perPage := min(count*2, 100)
	listURL := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=%d",
		cfg.apiBase(), url.PathEscape(owner), url.PathEscape(name), perPage)
	var releases []ghRelease
	if err := ghJSON(ctx, cfg.HTTP, listURL, &releases); err != nil {
		return nil, fmt.Errorf("list releases for %s/%s: %w", owner, name, err)
	}

	var out []Asset
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
		body, err := ghBytes(ctx, cfg.HTTP, assetURL)
		if err != nil {
			return nil, fmt.Errorf("download %s from release %s: %w", asset, r.TagName, err)
		}
		out = append(out, Asset{Tag: r.TagName, URL: r.HTMLURL, Content: body})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no published release of %s/%s carries a %s asset", owner, name, asset)
	}
	return out, nil
}

// NewHTTPClient is the HTTP client these lookups should use: a plain client with
// a timeout and nothing else. It is a constructor rather than a default inside
// Config so a caller cannot accidentally share a client whose transport was
// relaxed for the endpoint being verified.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// ghRelease is the subset of the GitHub releases API this needs.
type ghRelease struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
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
