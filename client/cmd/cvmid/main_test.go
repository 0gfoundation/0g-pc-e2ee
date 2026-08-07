package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/dstack"
)

// readSD parses a written file_sd document the way Prometheus would.
func readSD(t *testing.T, path string) []promSDEntry {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc []promSDEntry
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, body)
	}
	return doc
}

func TestWritePromSDLabelsTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sd", "prom-agent.json")
	info := dstack.Info{
		InstanceID: "aa11bb22cc33dd44ee55ff6600112233445566aa",
		AppID:      "3327603e03f5bd1f830812ca4a789277fc31f577",
		// Deliberately NOT expected in the output: these are orientation for a human
		// reading the log, not label material — compose_hash in particular would be a
		// second copy of what app_id already says.
		AppName:     "0g-pc-gateway",
		ComposeHash: "beef00",
	}
	if err := writePromSD(path, "localhost:9090", info); err != nil {
		t.Fatalf("writePromSD: %v", err)
	}

	doc := readSD(t, path)
	if len(doc) != 1 {
		t.Fatalf("document has %d entries, want 1", len(doc))
	}
	if len(doc[0].Targets) != 1 || doc[0].Targets[0] != "localhost:9090" {
		t.Errorf("targets = %v", doc[0].Targets)
	}
	want := map[string]string{"instance_id": info.InstanceID, "app_id": info.AppID}
	if len(doc[0].Labels) != len(want) {
		t.Fatalf("labels = %v, want %v", doc[0].Labels, want)
	}
	for k, v := range want {
		if doc[0].Labels[k] != v {
			t.Errorf("labels[%s] = %q, want %q", k, doc[0].Labels[k], v)
		}
	}
	// Prometheus runs as nobody and this binary as root, so a 0600 document would
	// leave the self-scrape target undiscoverable.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o644 {
		t.Errorf("file mode = %o, want 644", perm)
	}
}

// Without an identity the document must still name the target: an unlabelled
// self-scrape is a recoverable loss of one dimension, while no document at all
// means Prometheus discovers nothing and the agent's own health — the signal that
// says a replica has gone deaf — disappears entirely.
func TestWritePromSDWithoutIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prom-agent.json")
	if err := writePromSD(path, "localhost:9090", dstack.Info{}); err != nil {
		t.Fatalf("writePromSD: %v", err)
	}
	doc := readSD(t, path)
	if len(doc) != 1 || len(doc[0].Targets) != 1 || doc[0].Targets[0] != "localhost:9090" {
		t.Fatalf("document = %+v, want the target with no labels", doc)
	}
	// Omitted rather than empty: `"labels": {}` is accepted but says something
	// different from "we could not label this".
	if doc[0].Labels != nil {
		t.Errorf("labels = %v, want omitted", doc[0].Labels)
	}
	body, _ := os.ReadFile(path)
	if got := string(body); len(got) == 0 || got[len(got)-1] != '\n' {
		t.Errorf("document is not newline-terminated: %q", got)
	}
}

// A partial identity yields the part we have — instance_id is what separates
// colliding replica series; app_id only adds the blue/green dimension.
func TestWritePromSDPartialIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prom-agent.json")
	if err := writePromSD(path, "localhost:9090", dstack.Info{InstanceID: "aa11"}); err != nil {
		t.Fatalf("writePromSD: %v", err)
	}
	doc := readSD(t, path)
	if len(doc[0].Labels) != 1 || doc[0].Labels["instance_id"] != "aa11" {
		t.Errorf("labels = %v, want only instance_id", doc[0].Labels)
	}
}

// Rewriting must replace the document wholesale and leave no temp file behind:
// Prometheus watches this path, and a stray .sd-* would be discovered as a second
// (stale) source of the same target.
func TestWritePromSDOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prom-agent.json")
	if err := writePromSD(path, "localhost:9090", dstack.Info{InstanceID: "aa11"}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writePromSD(path, "localhost:9090", dstack.Info{InstanceID: "bb22"}); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got := readSD(t, path)[0].Labels["instance_id"]; got != "bb22" {
		t.Errorf("instance_id = %q, want bb22", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "prom-agent.json" {
		t.Errorf("directory holds %v, want only prom-agent.json", entries)
	}
}
