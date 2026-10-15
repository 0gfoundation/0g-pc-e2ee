// Command composego records how docker compose reads each file in cases/, for
// TestComposeDocument_AgreesWithComposeGo to compare this package's reading against.
//
// WHY THIS EXISTS. The review and the canonical block resolve YAML anchors, merge keys and
// compose's !reset / !override tags themselves (composeanchor.go). If they resolve
// anything differently from docker compose, the manifest the review describes is not the
// one that runs — and a baseline match then vouches for text nobody executes. Reading
// compose-go's source and reasoning about it is how the first version went wrong in two
// places; this runs the real thing.
//
// WHICH docker compose. The one dstack's OS images ship: dstack v0.5.4.1 and v0.5.9 (the
// two the fleet boots, see osimages.json) both build docker compose v2.26.0 from
// meta-virtualization's recipe, and its vendored modules.txt pins
// github.com/compose-spec/compose-go/v2 v2.0.2 and gopkg.in/yaml.v3 v3.0.1. go.mod here
// pins the same two. Moving to a newer dstack means re-checking that recipe and, if the
// versions moved, bumping them here and regenerating.
//
// WHICH STAGE. loader.ParseYAML: compose-go's !reset / !override pass followed by the
// yaml.v3 decode, which is where aliases and merge keys are resolved. Everything after
// it in loadYamlModel — interpolation, extends, include, canonical transforms — is a
// different question from "what does this YAML say", and is not compared here.
// ParseYAML reads ONE document; a file with more is reported with its document count.
//
// WHETHER IT LOADS AT ALL is recorded too, from the loader docker compose runs
// (loader.LoadWithContext, with only the consistency check skipped, since the cases do not
// all define what their services depend on). That is the verdict for what ParseYAML
// cannot see — a second document merged in, an empty one that stops the load, a key the
// compose schema refuses.
//
// It is a separate module, under testdata/ so the client module's ./... never builds
// it, and so compose-go never enters the client's dependency graph. Run it from this
// directory:
//
//	go run . cases
//
// and commit the .json files it writes next to each case.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"
	"gopkg.in/yaml.v3"
)

// result is what one case records. Exactly one of Model and Error is set.
type result struct {
	// Documents is how many YAML documents the file holds; the loader merges them all.
	Documents int `json:"documents"`
	// Model is ParseYAML's reading of the first document.
	Model map[string]any `json:"model,omitempty"`
	// Error is ParseYAML's refusal, when it refuses.
	Error string `json:"error,omitempty"`
	// LoadError is the full loader's refusal, or "" when docker compose loads the file.
	LoadError string `json:"load_error,omitempty"`
	// RestChangesProject is set for a multi-document file the loader accepts: whether the
	// project it loads differs from the one the first document alone loads. That is
	// docker compose's own answer to "can the first document be read on its own".
	RestChangesProject *bool `json:"rest_changes_project,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run . <cases dir>")
		os.Exit(2)
	}
	files, err := filepath.Glob(filepath.Join(os.Args[1], "*.yml"))
	if err != nil || len(files) == 0 {
		fmt.Fprintln(os.Stderr, "no cases found:", err)
		os.Exit(2)
	}
	for _, f := range files {
		if err := record(f); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", f, err)
			os.Exit(1)
		}
	}
}

func record(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var r result
	if r.Documents, err = countDocuments(src); err != nil {
		r.Error = err.Error()
	} else if m, err := loader.ParseYAML(src); err != nil {
		r.Error = err.Error()
	} else {
		r.Model = m
	}
	whole, err := load(src)
	if err != nil {
		r.LoadError = err.Error()
	} else if r.Documents > 1 {
		first, err := firstDocument(src)
		if err != nil {
			return err
		}
		alone, err := load(first)
		if err != nil {
			return fmt.Errorf("the first document alone does not load: %w", err)
		}
		changes := whole != alone
		r.RestChangesProject = &changes
	}
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(strings.TrimSuffix(path, ".yml")+".json", append(out, '\n'), 0o644)
}

// load runs the loader docker compose runs and returns the project it loads, as JSON.
func load(src []byte) (string, error) {
	p, err := loader.LoadWithContext(context.Background(), types.ConfigDetails{
		WorkingDir:  "/",
		ConfigFiles: []types.ConfigFile{{Filename: "docker-compose.yaml", Content: src}},
		Environment: map[string]string{},
	}, func(o *loader.Options) {
		o.SetProjectName("case", true)
		o.SkipConsistencyCheck = true
	})
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(p)
	return string(out), err
}

// firstDocument returns the first YAML document of src, re-encoded on its own.
func firstDocument(src []byte) ([]byte, error) {
	var node yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(src)).Decode(&node); err != nil {
		return nil, err
	}
	return yaml.Marshal(&node)
}

// countDocuments counts documents the way the loader's decode loop walks them.
func countDocuments(src []byte) (int, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	n := 0
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		n++
	}
}
