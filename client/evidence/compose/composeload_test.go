package compose

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The cases this package's own YAML reader was once held to against compose-go, kept as
// assertions about what the REVIEW reports now that the loader is compose-go itself.
// Each was a way for a reader to see something other than what docker compose runs; the
// first two were exploitable.
func TestLoad_ReadsWhatDockerComposeRuns(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		// service and key name a finding the review must report; empty for none.
		service, key string
		sev          Severity
	}{
		{"a second document is merged into what runs",
			"services:\n  app:\n    image: app\n---\nservices:\n  app:\n    privileged: true\n",
			"app", "privileged", SeverityBlocking},
		{"!reset on an override undoes it, so the merged value runs",
			"x-base: &base\n  privileged: true\n  cap_add: [SYS_ADMIN]\nservices:\n  app:\n    image: app\n" +
				"    <<: *base\n    privileged: !reset false\n    cap_add: !reset []\n",
			"app", "cap_add", SeverityBlocking},
		{"a merged key the service does not override runs",
			"x-base: &base\n  privileged: true\nservices:\n  after:\n    image: app\n    <<: *base\n    user: \"1000\"\n",
			"after", "privileged", SeverityBlocking},
		{"a merge list takes each key from its earliest source",
			"x-a: &a {user: a}\nx-b: &b {user: b, network_mode: host}\nservices:\n  app:\n    image: app\n    <<: [*a, *b]\n",
			"app", "network_mode", SeverityBlocking},
		{"a quoted string at a typed path is what docker compose casts it to",
			"services:\n  app:\n    image: app\n    privileged: \"true\"\n", "app", "privileged", SeverityBlocking},
		{"!override true is cast like the bool it spells",
			"services:\n  app:\n    image: app\n    privileged: !override true\n", "app", "privileged", SeverityBlocking},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewOf(t, manifest(tc.doc))
			if r.LoadErr != nil {
				t.Fatalf("refused: %v", r.LoadErr)
			}
			requireFinding(t, r, tc.sev, tc.service, tc.key)
		})
	}

	t.Run("an explicit key beats the merged one", func(t *testing.T) {
		r := reviewOf(t, manifest("x-base: &base\n  privileged: true\nservices:\n  before:\n    image: app\n"+
			"    privileged: false\n    <<: *base\n"))
		if got := find(r, "before", "privileged"); r.LoadErr != nil || len(got) != 0 {
			t.Fatalf("privileged: false lost to the merge: %v %+v", r.LoadErr, got)
		}
	})
}

// What docker compose refuses, the review refuses as a whole file: nothing in it runs.
func TestLoad_RefusesWhatDockerComposeRefuses(t *testing.T) {
	bomb := "a0: &a0 [\"x\"]\n"
	for i := 1; i <= 9; i++ {
		prev := "*a" + string(rune('0'+i-1))
		bomb += "a" + string(rune('0'+i)) + ": &a" + string(rune('0'+i)) + " [" +
			strings.TrimSuffix(strings.Repeat(prev+", ", 9), ", ") + "]\n"
	}
	for _, tc := range []struct{ name, doc, says string }{
		{"an alias bomb", "x-" + strings.ReplaceAll(bomb, "\na", "\nx-a") +
			"services:\n  app:\n    image: app\n    labels: {bomb: *a9}\n", "excessive aliasing"},
		{"an anchor that contains itself", "services:\n  app: &x\n    image: app\n    depends_on: [*x]\n", "contains itself"},
		{"a duplicate key", "services:\n  app:\n    image: app\n    privileged: false\n    privileged: true\n",
			"already defined"},
		{"a duplicate service", "services:\n  a:\n    image: mysql:8.0\n  a:\n    image: redis:7\n", "already defined"},
		{"a quoted merge key", "x-base: &base {privileged: true}\nservices:\n  app:\n    image: app\n    \"<<\": *base\n",
			"<<"},
		{"a merge of a list", "x-list: &list [a, b]\nservices:\n  app:\n    image: app\n    <<: *list\n", "map merge"},
		{"a trailing empty document", "services:\n  app:\n    image: app\n---\n", "mapping"},
		{"a non-string key", "services:\n  app:\n    image: app\n    labels:\n      1: one\n", "Non-string key"},
		{"a typed field docker compose cannot cast", "services:\n  app:\n    image: app\n    privileged: sort-of\n",
			"privileged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewOf(t, manifest(tc.doc))
			if r.LoadErr == nil || !strings.Contains(r.LoadErr.Error(), tc.says) {
				t.Fatalf("LoadErr = %v, want it to mention %q", r.LoadErr, tc.says)
			}
			if len(r.Services) != 0 {
				t.Fatalf("a refused file was described: %+v", r.Services)
			}
		})
	}
}

// include and extends are resolved by reading files from the loader's working directory —
// on a verifier, its own machine. Neither is loaded, and both are reported as blocking.
func TestLoad_IncludeAndExtendsAreNotLoaded(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	r := reviewOf(t, manifest("include:\n  - /etc/compose.yml\nservices:\n  app:\n    image: "+pinned+"\n"))
	if r.LoadErr != nil {
		t.Fatalf("an include was resolved or refused: %v", r.LoadErr)
	}
	requireFinding(t, r, SeverityBlocking, "", "compose.include")

	r = reviewOf(t, manifest("services:\n  base:\n    image: "+pinned+"\n    privileged: true\n  app:\n"+
		"    image: "+pinned+"\n    extends:\n      service: base\n"))
	if r.LoadErr != nil {
		t.Fatalf("an extends was resolved or refused: %v", r.LoadErr)
	}
	f := requireFinding(t, r, SeverityBlocking, "app", "extends")
	if !strings.Contains(f.Detail, "does not load extends") {
		t.Fatalf("detail = %s", f.Detail)
	}
	// Not loaded means not merged: app does not acquire base's privileged here, which is
	// exactly why extends itself is the blocking finding.
	if got := find(r, "app", "privileged"); len(got) != 0 {
		t.Fatalf("extends was applied: %+v", got)
	}
	r = reviewOf(t, manifest("services:\n  app:\n    image: "+pinned+"\n    extends:\n      file: /etc/other.yml\n"+
		"      service: x\n"))
	if r.LoadErr != nil {
		t.Fatalf("an extends from a file was resolved: %v", r.LoadErr)
	}
	requireFinding(t, r, SeverityBlocking, "app", "extends")
}

// compose-go reads `${HOSTROOT}:/host` as a volume named "${HOSTROOT}" — it parses before
// interpolation. What it mounts is the environment's choice, so it is not a volume name.
func TestLoad_AnInterpolatedMountSourceIsTheEnvironmentsChoice(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, src := range []string{"${HOSTROOT}", "/${ROOT}/etc", "$DATA"} {
		r := reviewOf(t, manifest("services:\n  app:\n    image: "+pinned+"\n    volumes:\n      - "+src+":/host\n"))
		if r.LoadErr != nil {
			t.Fatalf("%s: %v", src, r.LoadErr)
		}
		f := requireFinding(t, r, SeverityBlocking, "app", "volumes")
		if !strings.Contains(f.Detail, "decided by the deployment's environment") {
			t.Fatalf("%s: detail = %s", src, f.Detail)
		}
	}
}

// The loader reads no file: a working directory that existed would be the verifier's.
func TestLoad_WorkingDirDoesNotExist(t *testing.T) {
	if _, err := os.Stat(loadWorkingDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("loadWorkingDir %q exists (or cannot be checked): %v", loadWorkingDir, err)
	}
}

// dockerComposeLinks is what dstack's docker compose v2.26.0 links for the loader: its
// go.mod (proxy.golang.org/github.com/docker/compose/v2/@v/v2.26.0.mod). These are the
// modules that decide how a manifest READS — the loader, its YAML, the parsers its
// canonical transforms call for port specs and image references, and its schema. A
// different version of any of them is a different reading of the same text.
var dockerComposeLinks = map[string]string{
	"github.com/compose-spec/compose-go/v2": "v2.0.2",
	"gopkg.in/yaml.v3":                      "v3.0.1",
	"github.com/docker/go-connections":      "v0.5.0",
	"github.com/distribution/reference":     "v0.5.0",
	"github.com/mitchellh/mapstructure":     "v1.5.0",
	"github.com/xeipuuv/gojsonschema":       "v1.2.0",
	"github.com/mattn/go-shellwords":        "v1.0.12",
	"github.com/docker/go-units":            "v0.5.0",
}

// TestLoaderLinksDockerComposesVersions holds both modules that build this package to
// dockerComposeLinks: the client module, and pcverify's — the binary that runs it — where
// sigstore's dependencies would otherwise pull two of them forward (see the replace in
// its go.mod).
func TestLoaderLinksDockerComposesVersions(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to list modules with")
	}
	paths := make([]string, 0, len(dockerComposeLinks))
	for p := range dockerComposeLinks {
		paths = append(paths, p)
	}
	for _, dir := range []string{"../..", "../../cmd/pcverify"} {
		cmd := exec.Command(gobin, append([]string{"list", "-m", "-f",
			"{{.Path}} {{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}"}, paths...)...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list -m in %s: %v\n%s", dir, err, out)
		}
		got := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if path, version, ok := strings.Cut(line, " "); ok {
				got[path] = version
			}
		}
		for path, want := range dockerComposeLinks {
			if got[path] != want {
				t.Errorf("%s: %s is %q, but dstack's docker compose links %s", dir, path, got[path], want)
			}
		}
	}
}

// The gateway and the sidecar import client/evidence, never this package, so compose-go
// is not linked into either — and moving the version of anything they link would have to
// be a decision taken about them, not a side effect of the verifier's loader.
func TestComposeGoStaysOutOfTheGateway(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to list dependencies with")
	}
	out, err := exec.Command(gobin, "list", "-deps",
		"github.com/0gfoundation/0g-pc-e2ee/client/cmd/gateway",
		"github.com/0gfoundation/0g-pc-e2ee/client/cmd/sidecar").CombinedOutput()
	if err != nil {
		t.Skipf("go list: %v\n%s", err, out)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if strings.HasPrefix(pkg, "github.com/compose-spec/") || strings.HasSuffix(pkg, "/client/evidence/compose") {
			t.Errorf("the gateway or sidecar now depends on %s", pkg)
		}
	}
}
