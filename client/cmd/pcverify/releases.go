package main

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/release"
)

// defaultReleaseRepo and defaultReleaseAsset are where the digest-pinned deployment
// manifest is published (.github/workflows/release.yml). They are defaults so the
// common case is `-releases N` with nothing else.
const (
	defaultReleaseRepo  = release.DefaultRepo
	defaultReleaseAsset = release.DefaultAsset
)

// githubAPI is the API base, a variable only so tests can point it at a local
// server. Nothing configurable by a flag: aiming release lookups at an arbitrary
// host is not a knob an operator should have.
var githubAPI = release.DefaultAPIBase

// fetchReleaseComposeFiles returns the deployment manifest from each of the newest
// `count` releases of repo ("owner/name"), newest first, labelled by release tag —
// the candidate set the compose-file check compares the deployed text against.
//
// The lookup itself lives in client/release, shared with the gateway's
// /v1/gateway/identity endpoint so the release a deployment is REPORTED as and the
// release it is VERIFIED against can never come from two different lookups. This
// wrapper only adapts the result to the checker's candidate type, which carries a
// label rather than a tag and URL.
func fetchReleaseComposeFiles(ctx context.Context, hc *http.Client, repo, asset string, count int, warn io.Writer) ([]evidence.ExpectedCompose, error) {
	assets, err := release.FetchComposeAssets(ctx, release.Config{
		HTTP: hc, Repo: repo, Asset: asset, APIBase: githubAPI,
	}, count, warn)
	if err != nil {
		return nil, err
	}
	out := make([]evidence.ExpectedCompose, 0, len(assets))
	for _, a := range assets {
		out = append(out, evidence.ExpectedCompose{Label: a.Tag, Content: a.Content})
	}
	return out, nil
}

// newGitHubClient is the HTTP client for the release lookups — separate from the
// evidence checker's, so -allow-untrusted-cert can never loosen TLS against GitHub.
func newGitHubClient(timeout time.Duration) *http.Client {
	return release.NewHTTPClient(timeout)
}
