package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ghFixture serves a GitHub releases API and the assets it advertises.
type ghFixture struct {
	srv      *httptest.Server
	releases []ghRelease // served by /repos/…; set with setReleases after construction
	assets   map[string]string
	token    string // the Authorization header last seen
}

// newGHFixture starts a stand-in GitHub releases API. The release list is set
// afterwards via setReleases, because building an asset URL needs the server's
// address, which does not exist until it is listening.
func newGHFixture(t *testing.T, assets map[string]string) *ghFixture {
	t.Helper()
	f := &ghFixture{assets: assets}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		f.token = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(f.releases)
	})
	mux.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := f.assets[strings.TrimPrefix(r.URL.Path, "/assets/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	old := githubAPI
	githubAPI = f.srv.URL
	t.Cleanup(func() { githubAPI = old })
	return f
}

// setReleases publishes the given releases, newest first (the API's own ordering).
func (f *ghFixture) setReleases(rs ...ghRelease) { f.releases = rs }

// release builds a release entry whose asset (when assetName is non-empty) points at
// this fixture's asset route.
func (f *ghFixture) release(tag, assetName string, draft, prerelease bool) ghRelease {
	r := ghRelease{TagName: tag, Draft: draft, Prerelease: prerelease}
	if assetName != "" {
		r.Assets = append(r.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}{Name: assetName, URL: f.srv.URL + "/assets/" + tag})
	}
	return r
}

func TestFetchReleaseComposeFiles(t *testing.T) {
	assets := map[string]string{
		"release-3": "services: {} # three\n",
		"release-2": "services: {} # two\n",
		"release-1": "services: {} # one\n",
	}
	f := newGHFixture(t, assets)
	f.setReleases(
		f.release("release-3", defaultReleaseAsset, false, false),
		f.release("release-2", defaultReleaseAsset, false, false),
		f.release("release-1", defaultReleaseAsset, false, false),
	)

	var warn bytes.Buffer
	got, err := fetchReleaseComposeFiles(context.Background(), newGitHubClient(10*time.Second),
		"0gfoundation/0g-pc-e2ee", defaultReleaseAsset, 2, &warn)
	if err != nil {
		t.Fatalf("fetchReleaseComposeFiles: %v", err)
	}
	// Newest first, capped at the requested count.
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2", len(got))
	}
	if got[0].Label != "release-3" || got[1].Label != "release-2" {
		t.Errorf("labels = %q, %q; want release-3, release-2 (newest first)", got[0].Label, got[1].Label)
	}
	if string(got[0].Content) != assets["release-3"] {
		t.Errorf("release-3 content = %q", got[0].Content)
	}
}

// Drafts and prereleases were never published for production, so a deployment
// matching one is a finding — they must not become candidates.
func TestFetchReleaseComposeFiles_SkipsDraftsAndPrereleases(t *testing.T) {
	assets := map[string]string{"draft": "d\n", "pre": "p\n", "real": "r\n"}
	f := newGHFixture(t, assets)
	f.setReleases(
		f.release("draft", defaultReleaseAsset, true, false),
		f.release("pre", defaultReleaseAsset, false, true),
		f.release("real", defaultReleaseAsset, false, false),
	)

	var warn bytes.Buffer
	got, err := fetchReleaseComposeFiles(context.Background(), newGitHubClient(10*time.Second),
		"o/r", defaultReleaseAsset, 3, &warn)
	if err != nil {
		t.Fatalf("fetchReleaseComposeFiles: %v", err)
	}
	if len(got) != 1 || got[0].Label != "real" {
		t.Fatalf("candidates = %+v, want only the published release", got)
	}
}

// A release without the asset is skipped with a note — never silently treated as a
// match-anything.
func TestFetchReleaseComposeFiles_MissingAssetIsNoted(t *testing.T) {
	assets := map[string]string{"has-it": "yes\n"}
	f := newGHFixture(t, assets)
	f.setReleases(
		f.release("no-asset", "", false, false),
		f.release("has-it", defaultReleaseAsset, false, false),
	)

	var warn bytes.Buffer
	got, err := fetchReleaseComposeFiles(context.Background(), newGitHubClient(10*time.Second),
		"o/r", defaultReleaseAsset, 2, &warn)
	if err != nil {
		t.Fatalf("fetchReleaseComposeFiles: %v", err)
	}
	if len(got) != 1 || got[0].Label != "has-it" {
		t.Errorf("candidates = %+v", got)
	}
	if !strings.Contains(warn.String(), "no-asset") {
		t.Errorf("the skipped release must be reported, got: %q", warn.String())
	}
}

func TestFetchReleaseComposeFiles_Errors(t *testing.T) {
	newGHFixture(t, nil)
	hc := newGitHubClient(10 * time.Second)
	var warn bytes.Buffer

	t.Run("no releases with the asset", func(t *testing.T) {
		_, err := fetchReleaseComposeFiles(context.Background(), hc, "o/r", defaultReleaseAsset, 3, &warn)
		if err == nil || !strings.Contains(err.Error(), "no published release") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("bad repo", func(t *testing.T) {
		for _, repo := range []string{"", "no-slash", "/name", "owner/"} {
			if _, err := fetchReleaseComposeFiles(context.Background(), hc, repo, defaultReleaseAsset, 1, &warn); err == nil {
				t.Errorf("repo %q: expected an error", repo)
			}
		}
	})
	t.Run("bad count", func(t *testing.T) {
		if _, err := fetchReleaseComposeFiles(context.Background(), hc, "o/r", defaultReleaseAsset, 0, &warn); err == nil {
			t.Error("expected an error for -releases 0")
		}
	})
}

// The token is sent when the environment supplies one, so a private repo and a
// rate-limited run both work — but it is never required for a public repo.
func TestGitHubTokenIsSentWhenSet(t *testing.T) {
	f := newGHFixture(t, map[string]string{"r1": "x\n"})
	f.setReleases(f.release("r1", defaultReleaseAsset, false, false))

	t.Setenv("GITHUB_TOKEN", "s3cret")
	var warn bytes.Buffer
	if _, err := fetchReleaseComposeFiles(context.Background(), newGitHubClient(10*time.Second),
		"o/r", defaultReleaseAsset, 1, &warn); err != nil {
		t.Fatalf("fetchReleaseComposeFiles: %v", err)
	}
	if want := "Bearer s3cret"; f.token != want {
		t.Errorf("Authorization = %q, want %q", f.token, want)
	}
}

func TestGitHubToken_PrefersGITHUB_TOKEN(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "fallback")
	if got := githubToken(); got != "fallback" {
		t.Errorf("githubToken() = %q, want the GH_TOKEN fallback", got)
	}
	t.Setenv("GITHUB_TOKEN", "primary")
	if got := githubToken(); got != "primary" {
		t.Errorf("githubToken() = %q, want GITHUB_TOKEN to win", got)
	}
}

// -expect-compose-file and -releases answer different questions, so passing both
// must be rejected rather than silently resolved.
func TestNewEvidenceChecker_RejectsBothExpectForms(t *testing.T) {
	path := t.TempDir() + "/compose.yml"
	if err := os.WriteFile(path, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, gatewayConfig{
		timeout:           10 * time.Second,
		expectComposePath: path,
		releases:          3,
	})
	if err == nil || !strings.Contains(err.Error(), "pass one") {
		t.Errorf("err = %v, want a complaint that both were given", err)
	}
}

func TestNewEvidenceChecker_UnreadablePathsAreErrors(t *testing.T) {
	missing := t.TempDir() + "/does-not-exist.yml"
	for name, g := range map[string]gatewayConfig{
		"app-compose":         {timeout: time.Second, appComposePath: missing},
		"expect-compose-file": {timeout: time.Second, expectComposePath: missing},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, g); err == nil {
				t.Error("a flag that was passed but cannot be read must be an error, not a skipped check")
			}
		})
	}
}
