package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// composeGoCase is what testdata/composego/main.go recorded for one case: docker
// compose's own reading of it (see that file for which docker compose, and why).
type composeGoCase struct {
	Documents int            `json:"documents"`
	Model     map[string]any `json:"model"`
	Error     string         `json:"error"`
}

// Every case is read by this package exactly as docker compose read it: the same
// document, or a refusal where it refused. A file with more than one document is the
// exception by design — docker compose merges them, this package refuses them.
//
// The expected readings are not written by hand. They come from running compose-go
// v2.0.2, the loader inside the docker compose dstack ships; regenerate them with
// `go run . cases` in testdata/composego after adding a case.
func TestComposeDocument_AgreesWithComposeGo(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "composego", "cases", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no cases: %v", err)
	}
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".yml")
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(strings.TrimSuffix(path, ".yml") + ".json")
			if err != nil {
				t.Fatalf("no recorded reading — run `go run . cases` in testdata/composego: %v", err)
			}
			var want composeGoCase
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}

			top, err := readComposeDocument(src)
			switch {
			case want.Documents > 1:
				if err == nil || !strings.Contains(err.Error(), "more than one YAML document") {
					t.Fatalf("a %d-document file was not refused (err = %v)", want.Documents, err)
				}
			case want.Error != "":
				if err == nil {
					t.Fatalf("docker compose refuses this file (%s), and this package read it", want.Error)
				}
			default:
				if err != nil {
					t.Fatalf("docker compose reads this file, and this package refused it: %v", err)
				}
				var decoded any
				if err := top.Decode(&decoded); err != nil {
					t.Fatal(err)
				}
				got := viaJSON(t, decoded)
				if !reflect.DeepEqual(got, viaJSON(t, want.Model)) {
					t.Fatalf("this package and docker compose read the file differently:\n ours   %s\n compose %s",
						mustJSON(t, got), mustJSON(t, want.Model))
				}
			}
		})
	}
}

// The two differences that were exploitable, end to end: what the review reports and
// what a baseline sees, not only what readComposeDocument returns.
func TestReviewCompose_ReadsWhatDockerComposeRuns(t *testing.T) {
	load := func(name string) string {
		t.Helper()
		src, err := os.ReadFile(filepath.Join("testdata", "composego", "cases", name+".yml"))
		if err != nil {
			t.Fatal(err)
		}
		return string(src)
	}

	// docker compose runs `app` privileged with SYS_ADMIN, from the anchor: the !reset
	// removes the explicit `false` before the merge is applied.
	t.Run("!reset over a merged key", func(t *testing.T) {
		r := reviewOf(t, manifest(load("reset-explicit-over-merge")))
		requireFinding(t, r, SeverityBlocking, "app", "privileged")
		if fs := find(r, "app", "cap_add"); len(fs) == 0 || !strings.Contains(fs[0].Detail, "SYS_ADMIN") {
			t.Errorf("the merged cap_add was not reported: %+v", fs)
		}
		if b := requireBlock(t, load("reset-explicit-over-merge"), "app"); strings.Contains(b.Canonical, "privileged: false") {
			t.Errorf("the canonical block describes the override docker compose discards:\n%s", b.Canonical)
		}
	})

	// docker compose merges the second document, so `app` runs privileged. Read as one
	// document, the first matched a baseline recorded from it exactly. Now nothing is
	// described, so nothing can match.
	t.Run("a second document", func(t *testing.T) {
		r := reviewOf(t, manifest(load("multi-document")))
		f := requireFinding(t, r, SeverityBlocking, "", "docker_compose_file")
		if !strings.Contains(f.Detail, "more than one YAML document") {
			t.Errorf("detail does not say why: %s", f.Detail)
		}
		if len(r.Blocks) != 0 || len(r.Services) != 0 {
			t.Fatalf("a multi-document file was described: services %+v blocks %+v", r.Services, r.Blocks)
		}
		b := parseBaseline(t, entry("app", nil, "image: app"))
		// The premise: that baseline does match the first document on its own.
		if c := check(b, reviewOf(t, manifest("services:\n  app:\n    image: app\n")).Blocks); !c.Compared() || !c.OK() {
			t.Fatalf("the baseline does not match the first document alone: %+v", c)
		}
		if c := check(b, r.Blocks); !c.Compared() || c.OK() {
			t.Fatalf("a baseline of the first document matched the file: %+v", c)
		}
	})
}

// The comparison above is only meaningful while this module decodes YAML with the same
// yaml.v3 as the docker compose the expectations came from: the decode IS the reading.
func TestComposeDocument_LinksDockerComposesYAMLDecoder(t *testing.T) {
	version := func(gomod string) string {
		t.Helper()
		raw, err := os.ReadFile(gomod)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`(?m)^\s*gopkg\.in/yaml\.v3 (v\S+)`).FindSubmatch(raw)
		if m == nil {
			t.Fatalf("%s does not require gopkg.in/yaml.v3", gomod)
		}
		return string(m[1])
	}
	ours, theirs := version(filepath.Join("..", "go.mod")), version(filepath.Join("testdata", "composego", "go.mod"))
	if ours != theirs {
		t.Fatalf("the client links yaml.v3 %s, the docker compose the cases were recorded from links %s; "+
			"check what dstack ships and regenerate before moving either", ours, theirs)
	}
}

func viaJSON(t *testing.T, v any) any {
	t.Helper()
	var out any
	if err := json.Unmarshal(mustJSON(t, v), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("not representable as JSON: %v", err)
	}
	return raw
}
