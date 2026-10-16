package compose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"
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

// docker compose substitutes before it validates, so a schema violation at a value that
// holds a template is the environment's to settle, and docker compose loads the file
// whenever it does. These used to be refused as a whole file because the check deleted
// every templated value and re-validated: deleting a required field, or one branch of a
// oneOf, failed where substituting would not.
func TestLoad_ViolationsAtTemplatedValuesAreTheEnvironments(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct{ name, body string }{
		{"a templated ulimit beside a literal one", "    ulimits:\n      nofile:\n        soft: ${NOFILE}\n        hard: 2\n"},
		{"a templated depends_on condition", "    depends_on:\n      db:\n        condition: ${C}\n"},
		{"a templated typed field", "    privileged: ${PRIV}\n"},
		{"a templated port target", "    ports:\n      - target: ${PORT}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := "services:\n  app:\n    image: " + pinned + "\n" + tc.body + "  db:\n    image: " + pinned + "\n"
			if r := reviewOf(t, manifest(doc)); r.LoadErr != nil {
				t.Fatalf("refused a manifest docker compose loads once the environment fills it in: %v", r.LoadErr)
			}
		})
	}
}

// The other direction: what no value of any variable changes is still refused.
func TestLoad_ViolationsNoEnvironmentRepairsAreRefused(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct{ name, doc, says string }{
		// An unknown key is about the key, not its value.
		{"an unknown key whose value is templated",
			"services:\n  app:\n    image: " + pinned + "\n    bogus: \"${X}\"\n", "bogus"},
		// A templated value does not cover a literal violation beside it.
		{"a literal violation beside a templated value",
			"services:\n  app:\n    image: " + pinned + "\n    ulimits:\n      nofile:\n        soft: ${NOFILE}\n        hard: abc\n",
			"hard"},
		// docker compose validates after each document is merged in, so a later document
		// cannot repair an earlier one.
		{"a violation a later document removes",
			"services:\n  app:\n    image: " + pinned + "\n    bogus: x\n---\nservices:\n  app:\n    bogus: !reset null\n",
			"(document 1 of 2)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reviewOf(t, manifest(tc.doc))
			if r.LoadErr == nil || !strings.Contains(r.LoadErr.Error(), tc.says) {
				t.Fatalf("LoadErr = %v, want a refusal mentioning %q", r.LoadErr, tc.says)
			}
		})
	}

	// And a multi-document file whose every prefix is valid still loads, merged.
	r := reviewOf(t, manifest("services:\n  app:\n    image: "+pinned+"\n---\nservices:\n  app:\n    privileged: true\n"))
	if r.LoadErr != nil {
		t.Fatalf("a valid multi-document file: %v", r.LoadErr)
	}
	requireFinding(t, r, SeverityBlocking, "app", "privileged")
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

// A short-syntax mount holding a template is not parsed (composeload.go,
// templatedShortSyntax): docker compose parses it after substitution, so the review
// reports the text as written rather than a split of it.
func TestLoad_ATemplatedShortMountIsReportedAsWritten(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	for _, entry := range []string{"${HOSTROOT}:/host", "/${ROOT}/etc:/host", "$DATA:/host", "/data:/d:${MODE}",
		"${DATA:-./data}:/data"} {
		r := reviewOf(t, manifest("services:\n  app:\n    image: "+pinned+"\n    volumes:\n      - \""+entry+"\"\n"))
		if r.LoadErr != nil {
			t.Fatalf("%s: %v", entry, r.LoadErr)
		}
		f := requireFinding(t, r, SeverityBlocking, "app", "volumes")
		if !strings.Contains(f.Detail, fmt.Sprintf("%q is a short-syntax mount holding a template", entry)) {
			t.Fatalf("%s: detail = %s", entry, f.Detail)
		}
	}
	// A long-syntax source holding a template is not parsed by anyone, and keeps its rule.
	r := reviewOf(t, manifest("services:\n  app:\n    image: "+pinned+"\n    volumes:\n      - type: bind\n"+
		"        source: ${HOSTROOT}\n        target: /host\n"))
	f := requireFinding(t, r, SeverityBlocking, "app", "volumes")
	if !strings.Contains(f.Detail, "decided by the deployment's environment") {
		t.Fatalf("long syntax: detail = %s", f.Detail)
	}
}

// The canonical form keeps a templated short-syntax entry as written, so it cannot equal
// the form of a text docker compose would run differently. Parsed before substitution,
// `/data:/d:${MODE}` lost its options and reduced to exactly `/data:/d`.
func TestLoad_ATemplatedShortEntryKeepsItsText(t *testing.T) {
	for _, tc := range []struct{ name, plain, templated, keeps string }{
		{"mount options", "image: x\nvolumes: [\"/data:/d\"]\n", "image: x\nvolumes: [\"/data:/d:${MODE}\"]\n",
			"/data:/d:${MODE}"},
		{"a default with a colon", "image: x\nvolumes: [\"./data:/data\"]\n",
			"image: x\nvolumes: [\"${DATA:-./data}:/data\"]\n", "${DATA:-./data}:/data"},
		{"a port", "image: x\nports: [\"8080:80\"]\n", "image: x\nports: [\"${P:-8080}:80\"]\n", "${P:-8080}:80"},
		{"a ulimit", "image: x\nulimits: {nofile: 1024}\n", "image: x\nulimits: {nofile: \"${U}\"}\n", "${U}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, err := CanonicalizeServiceBlock("a", []byte(tc.plain))
			if err != nil {
				t.Fatal(err)
			}
			templated, err := CanonicalizeServiceBlock("a", []byte(tc.templated))
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if plain == templated || !strings.Contains(templated, tc.keeps) {
				t.Fatalf("the template did not survive:\n%s\nvs\n%s", plain, templated)
			}
			// And the text is stable: reducing it again changes nothing.
			again, err := CanonicalizeServiceBlock("a", []byte(templated))
			if err != nil || again != templated {
				t.Fatalf("not idempotent (%v):\n%s\nvs\n%s", err, templated, again)
			}
		})
	}

	// So a baseline recorded with the plain mount does not match the templated manifest.
	b, err := ParseComposeBaseline([]byte(`{"deployments": [{"name": "d", "contract": "` + testContract + `",
		"providers": ["` + testProvider + `"], "services": [{"name": "a", "block": ["image: x", "volumes:",
		"  - /data:/d"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := reviewOf(t, manifest("services:\n  a:\n    image: x\n    volumes: [\"/data:/d:${MODE}\"]\n"))
	if got := CheckReview(b, testReleases, testContract, testProvider, r); got.OK() {
		t.Fatalf("a templated mount matched the plain one it is not:\n%s", dumpMismatches(got))
	}
}

// A provider can write an `x-` key into a long-syntax mount, port or ulimit — compose's
// schema allows it and docker compose ignores it. Writing the key templates are held under
// must not make the loader swap a real entry for a string the provider chose: that hid a
// bind of the host's root behind `./data:/data`, from the review and from the baseline.
func TestLoad_AManifestCannotForgeAHeldTemplate(t *testing.T) {
	for _, key := range []string{"x-pcverify-held-template", holdKeyPrefix + strings.Repeat("0", 32), holdKeyPrefix} {
		t.Run(key, func(t *testing.T) {
			doc := "services:\n  app:\n    image: app\n    volumes:\n      - type: bind\n        source: /\n" +
				"        target: /host\n        " + key + ": ./data:/data\n"
			r := reviewOf(t, manifest(doc))
			if r.LoadErr != nil {
				t.Fatalf("refused: %v", r.LoadErr)
			}
			f := requireFinding(t, r, SeverityBlocking, "app", "volumes")
			if !strings.Contains(f.Detail, "/ -> /host (rw)") {
				t.Fatalf("the root bind is not what the review reports: %s\n%s", f.Detail, dumpFindings(r))
			}
			if strings.Contains(dumpFindings(r), "./data -> /data") {
				t.Fatalf("the forged string was read as a mount:\n%s", dumpFindings(r))
			}
			if !strings.Contains(r.Blocks[0].Canonical, "source: /\n") {
				t.Fatalf("the canonical form lost the real mount:\n%s", r.Blocks[0].Canonical)
			}

			// And the baseline does not take it for the mount it impersonates.
			b, err := ParseComposeBaseline([]byte(`{"deployments": [{"name": "d", "contract": "` + testContract + `",
				"providers": ["` + testProvider + `"], "services": [{"name": "app", "block": ["image: app", "volumes:",
				"  - ./data:/data"]}]}]}`))
			if err != nil {
				t.Fatal(err)
			}
			if got := CheckReview(b, testReleases, testContract, testProvider, r); got.OK() {
				t.Fatal("a manifest binding the host root matched a baseline recording ./data:/data")
			}
		})
	}

	// The exploitable form against a baseline: a record holding a templated mount, and a
	// manifest whose root bind forges that template. Before the key was drawn per load,
	// the two rendered identically and the baseline matched 1 of 1.
	b, err := ParseComposeBaseline([]byte(`{"deployments": [{"name": "d", "contract": "` + testContract + `",
		"providers": ["` + testProvider + `"], "services": [{"name": "app", "block": ["image: app", "volumes:",
		"  - ${DATA}:/data"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	forged := reviewOf(t, manifest("services:\n  app:\n    image: app\n    volumes:\n      - type: bind\n"+
		"        source: /\n        target: /host\n        x-pcverify-held-template: ${DATA}:/data\n"))
	if got := CheckReview(b, testReleases, testContract, testProvider, forged); got.OK() {
		t.Fatal("a root bind forging a held template matched the templated mount it impersonates")
	}
	// The genuine templated mount still matches its record.
	genuine := reviewOf(t, manifest("services:\n  app:\n    image: app\n    volumes:\n      - \"${DATA}:/data\"\n"))
	if got := CheckReview(b, testReleases, testContract, testProvider, genuine); !got.OK() || got.Matched != 1 {
		t.Fatalf("the genuine templated mount no longer matches its record:\n%s", dumpMismatches(got))
	}

	// The same for a port and a ulimit: the provider's mapping stays the mapping it is.
	r := reviewOf(t, manifest("services:\n  app:\n    image: app\n    ports:\n      - target: 80\n        published: \"80\"\n"+
		"        x-pcverify-held-template: \"127.0.0.1:8080:80\"\n    ulimits:\n      nofile:\n        soft: 1\n        hard: 2\n"+
		"        x-pcverify-held-template: \"1024\"\n"))
	if r.LoadErr != nil {
		t.Fatalf("refused: %v", r.LoadErr)
	}
	canonical := r.Blocks[0].Canonical
	if strings.Contains(canonical, "- 127.0.0.1:8080:80") || !strings.Contains(canonical, "published: \"80\"") ||
		!strings.Contains(canonical, "hard: 2") {
		t.Fatalf("a forged port or ulimit was swapped:\n%s", canonical)
	}
}

// Every load holds its templates under a key of its own.
func TestLoad_HoldKeysAreDrawnPerLoad(t *testing.T) {
	a, err := newHoldKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newHoldKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !strings.HasPrefix(a, holdKeyPrefix) || len(a) != len(holdKeyPrefix)+32 {
		t.Fatalf("keys %q and %q", a, b)
	}
}

// A port holding a template is the environment's to read too.
func TestLoad_ATemplatedPortIsReported(t *testing.T) {
	r := reviewOf(t, manifest("services:\n  app:\n    image: app\n    ports: [\"${P:-8080}:80\", \"9090:90\"]\n"))
	f := requireFinding(t, r, SeverityJustify, "app", "ports")
	if !strings.Contains(f.Detail, `"${P:-8080}:80" is a short-syntax port holding a template`) {
		t.Fatalf("detail = %s", f.Detail)
	}
}

// Template syntax is checked as docker compose checks it: a malformed template is a
// refusal, a missing or required variable is the environment's.
func TestLoad_TemplateSyntax(t *testing.T) {
	if r := reviewOf(t, manifest("services:\n  app:\n    image: app\n    environment: [\"A=${\"]\n")); r.LoadErr == nil ||
		!strings.Contains(r.LoadErr.Error(), "invalid interpolation format") {
		t.Fatalf("a malformed template: %v", r.LoadErr)
	}
	for _, v := range []string{"${X:?set X}", "${X?}", "${X:-d}", "$X", "$${X}"} {
		if r := reviewOf(t, manifest("services:\n  app:\n    image: app\n    environment: [\"A="+v+"\"]\n")); r.LoadErr != nil {
			t.Fatalf("%s: %v", v, r.LoadErr)
		}
	}
}

// Validation loads every prefix of the documents, and the text is the provider's, so the
// document count is bounded and a long run of documents is refused before any is loaded.
func TestLoad_DocumentCountIsBounded(t *testing.T) {
	ok := strings.Repeat("services: {}\n---\n", maxDocuments-1) + "services:\n  app:\n    image: app\n"
	if r := reviewOf(t, manifest(ok)); r.LoadErr != nil {
		t.Fatalf("%d documents: %v", maxDocuments, r.LoadErr)
	}
	start := time.Now()
	r := reviewOf(t, manifest(strings.Repeat("---\nservices: {}\n", 5000)))
	if r.LoadErr == nil || !strings.Contains(r.LoadErr.Error(), "the most pcverify reads") {
		t.Fatalf("5000 documents: %v", r.LoadErr)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("refusing 5000 documents took %v", d)
	}
}

// The loader reads no file. include and extends are the steps that would — compose-go
// resolves both from the machine running it — and neither is run: a manifest naming a
// real file on the verifier gets none of its content.
func TestLoad_ReadsNoFileOnTheVerifier(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "other.yml")
	if err := os.WriteFile(other, []byte("services:\n  x:\n    image: x\n    privileged: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, doc := range []string{
		"include:\n  - " + other + "\nservices:\n  app:\n    image: app\n",
		"services:\n  app:\n    image: app\n    extends:\n      file: " + other + "\n      service: x\n",
	} {
		r := reviewOf(t, manifest(doc))
		if r.LoadErr != nil {
			t.Fatalf("%v", r.LoadErr)
		}
		if got := find(r, "x", "privileged"); len(got) != 0 || len(find(r, "app", "privileged")) != 0 {
			t.Fatalf("a file on the verifier was read into the manifest:\n%s", dumpFindings(r))
		}
		for _, s := range r.Services {
			if s.Name == "x" {
				t.Fatalf("the included service appeared: %+v", r.Services)
			}
		}
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

// loadModel reproduces compose-go's own per-document loop, so that schema validation can
// come before the transforms (and filter what the environment settles). Its result must be
// compose-go's: for every input both accept, the model is the one compose-go's loader
// builds with the same options — the live manifests, and the cross-document cases where
// the reproduced !reset handling decides the outcome.
func TestLoad_IsComposeGosLoader(t *testing.T) {
	var cases []string
	for _, f := range []string{"testnet-app-compose.json", "cn20-app-compose.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		var ac struct {
			DockerComposeFile string `json:"docker_compose_file"`
		}
		if err := json.Unmarshal(raw, &ac); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, ac.DockerComposeFile)
	}
	cases = append(cases,
		"x-base: &base\n  privileged: true\n  cap_add: [SYS_ADMIN]\nservices:\n  app:\n    image: app\n    <<: *base\n    privileged: !reset false\n",
		"services:\n  app:\n    image: app\n    privileged: true\n    user: root\n---\nservices:\n  app:\n    privileged: !reset null\n",
		"services:\n  app:\n    image: app\n    environment: [A=1]\n---\nservices:\n  app:\n    environment: !override [B=2]\n",
		"services:\n  app:\n    image: app\n    volumes: [/a:/a, /b:/b]\n---\nservices:\n  app:\n    volumes: [/c:/a]\n",
		"{}\n---\nservices: {a: {image: x}}\n",
		"version: '3.8'\nservices:\n  app:\n    image: app\n    ports: ['8080:80']\n    privileged: \"true\"\n",
	)
	for i, text := range cases {
		ours, err := loadModel([]byte(text), "case")
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		key, _ := newHoldKey()
		theirs, err := loader.LoadModelWithContext(context.Background(), types.ConfigDetails{
			WorkingDir:  "/nonexistent",
			ConfigFiles: []types.ConfigFile{{Filename: "docker-compose.yaml", Content: []byte(text)}},
			Environment: map[string]string{},
		}, func(o *loader.Options) {
			o.SetProjectName("app", true)
			o.Interpolate = castOnly(key)
			o.SkipInclude, o.SkipExtends, o.SkipNormalization, o.SkipDefaultValues = true, true, true, true
			o.SkipResolveEnvironment, o.ResolvePaths, o.SkipConsistencyCheck = true, false, true
		})
		if err != nil {
			t.Fatalf("case %d: compose-go refused what loadModel accepted: %v", i, err)
		}
		restoreTemplates(theirs, key)
		if !reflect.DeepEqual(ours, theirs) {
			a, _ := json.MarshalIndent(ours, "", " ")
			b, _ := json.MarshalIndent(theirs, "", " ")
			t.Fatalf("case %d: loadModel and compose-go's loader differ:\n%s\nvs\n%s", i, a, b)
		}
	}
}

// Input the schema refuses must be refused, never handed to compose-go's transforms: they
// type-assert on schema-valid shapes and panic on anything else, and one panic took the
// whole verifier down with it. The last two make docker compose's own loader panic too (it
// de-duplicates before validating): reported as not read, never a crash.
func TestLoad_SchemaInvalidInputIsRefusedNotAPanic(t *testing.T) {
	for _, tc := range []struct {
		doc     string
		notRead bool
	}{
		{"services:\n  a:\n    image: x\nvolumes: {v: hello}\n", false},
		{"services:\n  a:\n    image: x\n    networks: [1]\n", false},
		{"services:\n  a:\n    image: x\n    env_file: [{required: true}]\n", true},
		{"services:\n  a:\n    image: x\n    secrets: [{target: 1}]\n", true},
	} {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("%q panicked: %v", tc.doc, p)
				}
			}()
			r := reviewOf(t, manifest(tc.doc))
			switch {
			case tc.notRead && !errors.Is(r.LoadErr, errNotRead):
				t.Fatalf("%q: LoadErr = %v, want not read", tc.doc, r.LoadErr)
			case !tc.notRead && (r.LoadErr == nil || !strings.Contains(r.LoadErr.Error(), "docker compose refuses")):
				t.Fatalf("%q: LoadErr = %v, want docker compose's refusal", tc.doc, r.LoadErr)
			}
		}()
	}
}

// docker compose checks for an empty file once every document is merged, so an empty
// first document is not a refusal.
func TestLoad_AnEmptyFirstDocument(t *testing.T) {
	r := reviewOf(t, manifest("{}\n---\nservices: {a: {image: x}}\n"))
	if r.LoadErr != nil || len(r.Services) != 1 {
		t.Fatalf("LoadErr = %v, services %+v", r.LoadErr, r.Services)
	}
}

// Past the document bound the manifest is not read, and a recorded deployment reports the
// comparison as not run (exit 3), not as a mismatch docker compose would not make.
func TestLoad_PastTheDocumentBoundIsNotCompared(t *testing.T) {
	doc := strings.Repeat("services: {}\n---\n", maxDocuments) + "services:\n  mysql:\n    image: mysql:8.0\n"
	r := reviewOf(t, manifest(doc))
	if !errors.Is(r.LoadErr, errNotRead) {
		t.Fatalf("LoadErr = %v, want not read", r.LoadErr)
	}
	b, err := ParseComposeBaseline([]byte(`{"deployments": [{"name": "d", "contract": "` + testContract + `",
		"providers": ["` + testProvider + `"], "services": [{"name": "mysql", "block": ["image: mysql:8.0"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := CheckReview(b, testReleases, testContract, testProvider, r)
	if !got.OK() || got.Complete() || len(got.Unverified) != 1 {
		t.Fatalf("want an incomplete comparison, not a mismatch: %+v", got)
	}
}

// A real mount cannot be merged into a held template: their targets never coincide.
func TestLoad_ARealMountIsNotMergedIntoAHeldTemplate(t *testing.T) {
	r := reviewOf(t, manifest("services:\n  a:\n    image: x\n    volumes: [{type: bind, source: /, target: '${X}:/data'}, '${X}:/data']\n"))
	if r.LoadErr != nil {
		t.Fatal(r.LoadErr)
	}
	var root bool
	for _, f := range find(r, "a", "volumes") {
		if strings.Contains(f.Detail, "/ -> ${X}:/data") {
			root = true
		}
	}
	if !root {
		t.Fatalf("the root bind is not reported:\n%s", dumpFindings(r))
	}
	// And which of the two docker compose keeps is the environment's: no canonical form.
	if b := r.Blocks[0]; b.Pinnable() || !strings.Contains(b.Err.Error(), "identified by a template") {
		t.Fatalf("block = %+v", b)
	}
}

// Wherever docker compose de-duplicates by an identity the environment decides, the block
// cannot be pinned; alone, a templated entry can.
func TestLoad_TemplatedIdentitiesLeaveNoCanonicalForm(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		pinnable   bool
	}{
		{"a templated mount after a literal one on its target, across documents", "", false},
		{"a templated mount beside a literal one", "    volumes: [/safe:/data, '${X}:/data']\n", false},
		{"a templated environment key beside another", "    environment: ['A=1', '${K}=2']\n", false},
		{"a templated environment value", "    environment: ['A=${V}', 'B=2']\n", true},
		{"a templated mount alone", "    volumes: ['${X}:/data']\n", true},
		{"a templated secret target beside another", "    secrets: [{source: s, target: '${T}'}, {source: t, target: u}]\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := "services:\n  a:\n    image: x\n" + tc.body + "secrets: {s: {file: ./s}, t: {file: ./t}}\n"
			if tc.body == "" {
				doc = "services:\n  a:\n    image: x\n    volumes: [/safe:/data]\n---\nservices:\n  a:\n    volumes: ['${X}:/data']\n"
			}
			r := reviewOf(t, manifest(doc))
			if r.LoadErr != nil {
				t.Fatal(r.LoadErr)
			}
			if got := r.Blocks[0].Pinnable(); got != tc.pinnable {
				t.Fatalf("pinnable = %v, want %v (%v)", got, tc.pinnable, r.Blocks[0].Err)
			}
		})
	}
}

// Every reviewed key holding a template is reported at the worst its rule could find.
func TestLoad_TemplatedReviewedKeys(t *testing.T) {
	for _, tc := range []struct {
		body, key string
		sev       Severity
	}{
		{"    security_opt: ['${S}']\n", "security_opt", SeverityBlocking},
		{"    network_mode: ${NM}\n", "network_mode", SeverityBlocking},
		{"    pid: ${P}\n", "pid", SeverityBlocking},
		{"    cgroup: ${C}\n", "cgroup", SeverityBlocking},
		{"    ipc: ${I}\n", "ipc", SeverityJustify},
		{"    userns_mode: ${U}\n", "userns_mode", SeverityJustify},
		{"    devices: ['${D}']\n", "devices", SeverityJustify},
	} {
		t.Run(tc.key, func(t *testing.T) {
			r := reviewOf(t, manifest("services:\n  a:\n    image: x\n"+tc.body))
			if r.LoadErr != nil {
				t.Fatal(r.LoadErr)
			}
			var found bool
			for _, f := range find(r, "a", tc.key) {
				found = found || (f.Severity == tc.sev && strings.Contains(f.Detail, "holds a template"))
			}
			if !found {
				t.Fatalf("no %s finding that the value holds a template:\n%s", tc.sev, dumpFindings(r))
			}
		})
	}
}
