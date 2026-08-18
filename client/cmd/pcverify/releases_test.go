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

// The lookup itself is covered in client/release; what this file covers is
// pcverify's side of it — the adapter to the checker's candidate type, and the
// flag combinations that decide whether a failed lookup is fatal.

// stubReleases points githubAPI at a server publishing one release carrying
// content as its docker-compose.release.yml asset.
func stubReleases(t *testing.T, tag, content string) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name": tag,
			"html_url": "https://github.com/o/r/releases/tag/" + tag,
			"assets": []map[string]string{
				{"name": defaultReleaseAsset, "browser_download_url": srv.URL + "/asset"},
			},
		}})
	})
	mux.HandleFunc("/asset", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(content))
	})

	old := githubAPI
	githubAPI = srv.URL
	t.Cleanup(func() { githubAPI = old })
}

// The candidate the checker compares against is labelled by release tag: that
// label is what the report prints as "matches <X> byte-for-byte", so a wrong
// mapping would name the wrong release for a correct comparison.
func TestFetchReleaseComposeFiles_LabelsByTag(t *testing.T) {
	stubReleases(t, "release-2026.08.07.1", "services: {}\n")

	var warn bytes.Buffer
	got, err := fetchReleaseComposeFiles(context.Background(), newGitHubClient(10*time.Second),
		defaultReleaseRepo, defaultReleaseAsset, 1, &warn)
	if err != nil {
		t.Fatalf("fetchReleaseComposeFiles: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	if got[0].Label != "release-2026.08.07.1" {
		t.Errorf("Label = %q, want the release tag", got[0].Label)
	}
	if string(got[0].Content) != "services: {}\n" {
		t.Errorf("Content = %q", got[0].Content)
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
