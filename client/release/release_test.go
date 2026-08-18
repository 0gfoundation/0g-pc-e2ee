package release

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	return f
}

// config points a lookup at this fixture.
func (f *ghFixture) config() Config {
	return Config{HTTP: NewHTTPClient(10 * time.Second), Repo: "o/r", APIBase: f.srv.URL}
}

// setReleases publishes the given releases, newest first (the API's own ordering).
func (f *ghFixture) setReleases(rs ...ghRelease) { f.releases = rs }

// release builds a release entry whose asset (when assetName is non-empty) points at
// this fixture's asset route.
func (f *ghFixture) release(tag, assetName string, draft, prerelease bool) ghRelease {
	r := ghRelease{
		TagName:    tag,
		HTMLURL:    "https://github.com/o/r/releases/tag/" + tag,
		Draft:      draft,
		Prerelease: prerelease,
	}
	if assetName != "" {
		r.Assets = append(r.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}{Name: assetName, URL: f.srv.URL + "/assets/" + tag})
	}
	return r
}

func TestFetchComposeAssets(t *testing.T) {
	assets := map[string]string{
		"release-3": "services: {} # three\n",
		"release-2": "services: {} # two\n",
		"release-1": "services: {} # one\n",
	}
	f := newGHFixture(t, assets)
	f.setReleases(
		f.release("release-3", DefaultAsset, false, false),
		f.release("release-2", DefaultAsset, false, false),
		f.release("release-1", DefaultAsset, false, false),
	)

	var warn bytes.Buffer
	got, err := FetchComposeAssets(context.Background(), f.config(), 2, &warn)
	if err != nil {
		t.Fatalf("FetchComposeAssets: %v", err)
	}
	// Newest first, capped at the requested count.
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2", len(got))
	}
	if got[0].Tag != "release-3" || got[1].Tag != "release-2" {
		t.Errorf("tags = %q, %q; want release-3, release-2 (newest first)", got[0].Tag, got[1].Tag)
	}
	if string(got[0].Content) != assets["release-3"] {
		t.Errorf("release-3 content = %q", got[0].Content)
	}
	// The release page URL rides along: it is what a "which release is this?" link
	// points at, and inventing one from the tag would guess at GitHub's URL shape.
	if want := "https://github.com/o/r/releases/tag/release-3"; got[0].URL != want {
		t.Errorf("URL = %q, want %q", got[0].URL, want)
	}
}

// Drafts and prereleases were never published for production, so a deployment
// matching one is a finding — they must not become candidates.
func TestFetchComposeAssets_SkipsDraftsAndPrereleases(t *testing.T) {
	assets := map[string]string{"draft": "d\n", "pre": "p\n", "real": "r\n"}
	f := newGHFixture(t, assets)
	f.setReleases(
		f.release("draft", DefaultAsset, true, false),
		f.release("pre", DefaultAsset, false, true),
		f.release("real", DefaultAsset, false, false),
	)

	var warn bytes.Buffer
	got, err := FetchComposeAssets(context.Background(), f.config(), 3, &warn)
	if err != nil {
		t.Fatalf("FetchComposeAssets: %v", err)
	}
	if len(got) != 1 || got[0].Tag != "real" {
		t.Fatalf("candidates = %+v, want only the published release", got)
	}
}

// A release without the asset is skipped with a note — never silently treated as a
// match-anything.
func TestFetchComposeAssets_MissingAssetIsNoted(t *testing.T) {
	assets := map[string]string{"has-it": "yes\n"}
	f := newGHFixture(t, assets)
	f.setReleases(
		f.release("no-asset", "", false, false),
		f.release("has-it", DefaultAsset, false, false),
	)

	var warn bytes.Buffer
	got, err := FetchComposeAssets(context.Background(), f.config(), 2, &warn)
	if err != nil {
		t.Fatalf("FetchComposeAssets: %v", err)
	}
	if len(got) != 1 || got[0].Tag != "has-it" {
		t.Errorf("candidates = %+v", got)
	}
	if !strings.Contains(warn.String(), "no-asset") {
		t.Errorf("the skipped release must be reported, got: %q", warn.String())
	}
}

// A nil warn writer is the gateway's case: it has no report to print into, and a
// skipped release must not panic the lookup.
func TestFetchComposeAssets_NilWarnWriter(t *testing.T) {
	f := newGHFixture(t, map[string]string{"has-it": "yes\n"})
	f.setReleases(
		f.release("no-asset", "", false, false),
		f.release("has-it", DefaultAsset, false, false),
	)
	if _, err := FetchComposeAssets(context.Background(), f.config(), 2, nil); err != nil {
		t.Fatalf("FetchComposeAssets: %v", err)
	}
}

func TestFetchComposeAssets_Errors(t *testing.T) {
	f := newGHFixture(t, nil)
	var warn bytes.Buffer

	t.Run("no releases with the asset", func(t *testing.T) {
		_, err := FetchComposeAssets(context.Background(), f.config(), 3, &warn)
		if err == nil || !strings.Contains(err.Error(), "no published release") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("bad repo", func(t *testing.T) {
		for _, repo := range []string{"no-slash", "/name", "owner/"} {
			cfg := f.config()
			cfg.Repo = repo
			if _, err := FetchComposeAssets(context.Background(), cfg, 1, &warn); err == nil {
				t.Errorf("repo %q: expected an error", repo)
			}
		}
	})
	t.Run("bad count", func(t *testing.T) {
		if _, err := FetchComposeAssets(context.Background(), f.config(), 0, &warn); err == nil {
			t.Error("expected an error for a zero count")
		}
	})
	t.Run("no HTTP client", func(t *testing.T) {
		if _, err := FetchComposeAssets(context.Background(), Config{Repo: "o/r"}, 1, &warn); err == nil {
			t.Error("expected an error when no client is configured")
		}
	})
}

// The token is sent when the environment supplies one, so a private repo and a
// rate-limited run both work — but it is never required for a public repo.
func TestGitHubTokenIsSentWhenSet(t *testing.T) {
	f := newGHFixture(t, map[string]string{"r1": "x\n"})
	f.setReleases(f.release("r1", DefaultAsset, false, false))

	t.Setenv("GITHUB_TOKEN", "s3cret")
	var warn bytes.Buffer
	if _, err := FetchComposeAssets(context.Background(), f.config(), 1, &warn); err != nil {
		t.Fatalf("FetchComposeAssets: %v", err)
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

// An empty Repo/Asset means "the ones this repository publishes", so a caller that
// only wants the defaults does not have to restate them.
func TestConfigDefaults(t *testing.T) {
	var c Config
	if c.repo() != DefaultRepo || c.asset() != DefaultAsset || c.apiBase() != DefaultAPIBase {
		t.Errorf("defaults = %q %q %q", c.repo(), c.asset(), c.apiBase())
	}
}
