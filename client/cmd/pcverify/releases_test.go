package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	_, _, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, gatewayConfig{
		timeout:           10 * time.Second,
		expectComposePath: path,
		expectComposeSet:  true,
		releases:          3,
		releasesSet:       true,
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
			if _, _, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, g); err == nil {
				t.Error("a flag that was passed but cannot be read must be an error, not a skipped check")
			}
		})
	}
}

// -releases has a nonzero default, so its failure mode has to depend on whether the
// operator actually asked. A default lookup that cannot reach GitHub says nothing
// about the deployment and must not fail the run; an explicit one must.
func TestNewEvidenceChecker_ReleaseLookupFailure(t *testing.T) {
	// A server that 500s on the releases listing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	old := githubAPI
	githubAPI = srv.URL
	t.Cleanup(func() { githubAPI = old })

	base := gatewayConfig{timeout: 10 * time.Second, releases: defaultReleases,
		releaseRepo: defaultReleaseRepo, releaseAsset: defaultReleaseAsset}

	t.Run("default is advisory", func(t *testing.T) {
		g := base // releasesSet stays false
		c, expect, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, g)
		if err != nil {
			t.Fatalf("a default lookup failure must not be fatal, got: %v", err)
		}
		if c == nil {
			t.Fatal("no checker returned")
		}
		if expect.Err == nil {
			t.Error("the failure must still be recorded so the report can state it")
		}
		if !expect.Advisory {
			t.Error("Advisory = false for a lookup that was never requested")
		}
	})

	t.Run("explicit is fatal", func(t *testing.T) {
		g := base
		g.releasesSet = true
		_, _, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, g)
		if err == nil {
			t.Fatal("an explicitly requested lookup that failed must be fatal")
		}
		// Fatal as a FAILED CHECK, not as a caller mistake — see errLookupRequired.
		var required errLookupRequired
		if !errors.As(err, &required) {
			t.Errorf("err = %v (%T), want an errLookupRequired", err, err)
		}
	})

	t.Run("strict is fatal", func(t *testing.T) {
		g := base // releasesSet stays false; -strict is what demands the lookup
		g.strict = true
		_, _, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, g)
		if err == nil {
			t.Fatal("-strict must not let a failed release lookup through")
		}
		var required errLookupRequired
		if !errors.As(err, &required) {
			t.Errorf("err = %v (%T), want an errLookupRequired", err, err)
		}
	})
}

// The exit code for a demanded-but-unobtainable lookup, end to end through run().
//
// This is the scenario -strict exists for — an unreachable or rate-limited GitHub, at
// 60 requests/hour per IP on shared runners — and it must land on 1 ("a check failed"),
// never 2 ("caller mistake"). A gate that branches on the two to tell "my invocation is
// wrong" from "the deployment did not verify" would otherwise be sent the wrong way in
// exactly the case the flag was added for.
//
// It goes through run() deliberately: the bug this covers was in the mapping from
// newEvidenceChecker's error to an exit code, which no test of either half could see.
func TestRun_DemandedLookupFailureExitsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// What rate limiting actually looks like.
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	old := githubAPI
	githubAPI = srv.URL
	t.Cleanup(func() { githubAPI = old })

	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"strict", []string{"-gateway", "pc-gateway.test", "-strict"}, 1},
		{"explicit releases", []string{"-gateway", "pc-gateway.test", "-releases", "3"}, 1},
		// Still a caller mistake: these two instructions contradict each other, and the
		// run is rejected before any lookup is attempted.
		{"strict with the comparison off", []string{"-gateway", "pc-gateway.test", "-strict", "-releases", "0"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if got := run(context.Background(), &out, tc.args); got != tc.want {
				t.Errorf("exit = %d, want %d\n%s", got, tc.want, out.String())
			}
		})
	}
}

// Naming a file is the more specific instruction, so it wins over the -releases
// default without an error — only two EXPLICIT flags conflict.
func TestNewEvidenceChecker_PinnedFileBeatsDefaultReleases(t *testing.T) {
	path := t.TempDir() + "/compose.yml"
	if err := os.WriteFile(path, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No GitHub server registered: if the release lookup ran, this would fail.
	old := githubAPI
	githubAPI = "http://127.0.0.1:0"
	t.Cleanup(func() { githubAPI = old })

	_, expect, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, gatewayConfig{
		timeout:           10 * time.Second,
		expectComposePath: path,
		expectComposeSet:  true,
		releases:          defaultReleases, // the default, not passed
		releaseRepo:       defaultReleaseRepo,
		releaseAsset:      defaultReleaseAsset,
	})
	if err != nil {
		t.Fatalf("newEvidenceChecker: %v", err)
	}
	if expect.Label != path {
		t.Errorf("Label = %q, want the pinned file %q", expect.Label, path)
	}
	if expect.Err != nil {
		t.Errorf("the release lookup should not have run: %v", expect.Err)
	}
}

// -releases 0 turns the lookup off entirely.
func TestNewEvidenceChecker_ReleasesZeroDisables(t *testing.T) {
	old := githubAPI
	githubAPI = "http://127.0.0.1:0" // any lookup would fail
	t.Cleanup(func() { githubAPI = old })

	_, expect, err := newEvidenceChecker(context.Background(), &bytes.Buffer{}, gatewayConfig{
		timeout: 10 * time.Second, releases: 0, releasesSet: true,
	})
	if err != nil {
		t.Fatalf("newEvidenceChecker: %v", err)
	}
	if expect.Label != "" || expect.Err != nil {
		t.Errorf("expected no expectation source, got %+v", expect)
	}
}
