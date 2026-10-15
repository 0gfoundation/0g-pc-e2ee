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
	LoadError string         `json:"load_error"`
	// RestChangesProject is docker compose's verdict on a multi-document file it loads:
	// whether the documents after the first change the project.
	RestChangesProject *bool `json:"rest_changes_project"`
}

// Every case is read by this package exactly as docker compose read it: the same
// document, or a refusal where it refused. The one deliberate difference is a file whose
// later documents carry content: docker compose merges them, this package refuses them
// and says so. A later document that is empty or null is not that case — docker compose
// refuses the whole file, and so does this package, saying THAT instead.
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
			case want.Documents > 1 && want.LoadError != "":
				if err == nil || !strings.Contains(err.Error(), "refuses such a file") {
					t.Fatalf("docker compose refuses this file (%s); this package should say so, got err = %v",
						want.LoadError, err)
				}
			case want.Documents > 1 && err != nil:
				if !strings.Contains(err.Error(), "more than one YAML document") {
					t.Fatalf("a %d-document file docker compose loads was refused for the wrong reason: %v",
						want.Documents, err)
				}
			case want.Error != "":
				if err == nil {
					t.Fatalf("docker compose refuses this file (%s), and this package read it", want.Error)
				}
			case want.Documents > 1 && (want.RestChangesProject == nil || *want.RestChangesProject):
				// Reading the first document alone is only right when docker compose says the
				// rest changes nothing; ParseYAML's model below is the first document's.
				t.Fatalf("this package read a %d-document file whose later documents change what docker "+
					"compose runs", want.Documents)
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

// The cases the review describes rather than refuses, where docker compose's verdict
// still has to come through: the deliberate refusal of a merged second document is
// matched above; these are the ones that must load, and the one the schema refuses.
func TestComposeDocument_TrailingDocuments(t *testing.T) {
	for _, tc := range []struct {
		name   string
		loads  bool
		reason string
	}{
		{"trailing-separator", false, "refuses such a file"},
		{"trailing-null", false, "refuses such a file"},
		{"trailing-comment", false, "refuses such a file"},
		{"trailing-empty-mapping", true, ""},
		{"document-markers", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("testdata", "composego", "cases", tc.name+".yml"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = readComposeDocument(src)
			if tc.loads && err != nil {
				t.Fatalf("docker compose loads this file, and it was refused: %v", err)
			}
			if !tc.loads && (err == nil || !strings.Contains(err.Error(), tc.reason)) {
				t.Fatalf("err = %v, want it to say docker compose %s", err, tc.reason)
			}
		})
	}
}

// A key spelled "<<" that is not a merge key is the manifest's doing, and docker compose
// refuses it. The finding says that — not that the tool is broken.
func TestReviewCompose_LiteralMergeKeySpelling(t *testing.T) {
	for _, name := range []string{"merge-key-quoted", "merge-key-tagged-str"} {
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("testdata", "composego", "cases", name+".yml"))
			if err != nil {
				t.Fatal(err)
			}
			f := requireFinding(t, reviewOf(t, manifest(string(src))), SeverityBlocking, "app", "<<")
			if strings.Contains(f.Detail, "defect in this tool") || !strings.Contains(f.Detail, "not allowed") {
				t.Fatalf("detail: %s", f.Detail)
			}
		})
	}
}

// The baseline side reads its blocks with the reader the manifest goes through. A block
// recorded with compose's tags reduces the way the same text does in a manifest, and a
// stray document separator in a recorded block is refused rather than truncating it.
func TestCanonicalizeServiceBlock_ReadsAsDockerComposeDoes(t *testing.T) {
	body := "image: app\nprivileged: !reset true\nuser: !override root\n"
	observed := requireBlock(t, "services:\n  app:\n    image: app\n    privileged: !reset true\n    user: !override root\n", "app")
	if observed.Err != nil {
		t.Fatal(observed.Err)
	}
	recorded, err := CanonicalizeServiceBlock([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if recorded != observed.Canonical {
		t.Fatalf("the same text reduced two ways:\n recorded %q\n observed %q", recorded, observed.Canonical)
	}
	if strings.Contains(recorded, "privileged") {
		t.Fatalf("a !reset key survived on the baseline side:\n%s", recorded)
	}
	if _, err := CanonicalizeServiceBlock([]byte("image: app\n---\nprivileged: true\n")); err == nil {
		t.Fatal("a block with a second document was accepted")
	}
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
