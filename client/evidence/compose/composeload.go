package compose

// composeload.go reads compose text WITH docker compose's own loader, before anything in
// this package looks at a service.
//
// WHY THE LOADER AND NOT A READER OF OUR OWN. Everything downstream — the review's
// findings and the canonical block a baseline is matched against — describes what the
// YAML says. If that reading differs from docker compose's, the review describes a
// deployment that does not run, and a baseline match vouches for text nobody executes.
// This package used to reproduce the loader's YAML semantics itself (multi-document
// merging, compose's !reset / !override tags, anchors and merge keys) and held the
// result to compose-go with recorded cases. Two exploitable differences were found that
// way, and the cases only ever covered the inputs someone thought of. Loading with the
// library docker compose loads with removes the difference by construction.
//
// WHICH docker compose. The one dstack ships: v2.26.0 on both OS images the fleet boots
// (see client/evidence/osimages.json), whose vendored modules pin
// github.com/compose-spec/compose-go/v2 v2.0.2 over gopkg.in/yaml.v3 v3.0.1. client/go.mod
// pins exactly those. Moving to a dstack with a newer docker compose means re-checking
// that recipe and moving the pin with it — and re-checking that the gateway's linked
// dependencies still do not move (TestComposeGoStaysOutOfTheGateway).
//
// WHAT IS LOADED, AND WHAT IS NOT. The loader's own pipeline — every YAML document,
// merged, with !reset / !override applied, anchors and merge keys resolved by yaml.v3,
// key uniqueness enforced, and compose's canonical transforms (short syntax to long) —
// with these stages switched off, each for a stated reason:
//
//   - Substitution. `${VAR}` values come from the CVM's encrypted environment, which the
//     verifier does not have; every template is left as written, and the review treats
//     every `$` as provider-controlled. The type casts interpolation also performs are
//     kept (castOnly).
//   - include, and extends: compose-go resolves both by reading FILES, from the working
//     directory of whoever runs the loader. On a verifier that is the verifier's own
//     machine — a manifest saying `include: /etc/…` would have pcverify read its host's
//     files. Neither is loaded; the review reports both as blocking, since what they pull
//     in is not in the measured manifest.
//   - Normalization, default values, environment resolution and path resolution: each
//     rewrites the model toward what a particular host would run (project names, the
//     default network, env_file contents, absolute paths under the working directory).
//     None of it is in the manifest, and folding it in would make a record depend on
//     where it was taken.
//   - The project consistency check: it cross-references names (depends_on targets and
//     the like). A manifest failing it runs nothing at all; no rule here depends on it.
//
// Schema validation runs separately (validateAsLoaded): per document, as docker compose
// runs it, and judging each violation on its own, because without the environment the
// schema refuses some manifests docker compose accepts — `privileged: ${P}` is not a
// boolean until the environment fills it in.
//
// WHAT THE REVIEW THEN WALKS. The loaded model re-encoded as a yaml.Node tree: the rules
// were written against nodes, and a node tree keeps what a Go map would lose for them —
// whether a key is present, and a scalar's type (`privileged: "true"` is a string). Key
// order is not kept: compose-go's model is a map, so every canonical form is key-sorted.
//
// BOTH SIDES OF A BASELINE COMPARISON load through here: the observed manifest, and every
// block a baseline records (loadServiceBlock, loadTopLevelBlock). One loader for both
// sides is what lets a recorded block be compared with a manifest at all.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	interp "github.com/compose-spec/compose-go/v2/interpolation"
	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/schema"
	"github.com/compose-spec/compose-go/v2/template"
	"github.com/compose-spec/compose-go/v2/tree"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/compose-spec/compose-go/v2/validation"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

// loadWorkingDir is the working directory the loader is given. Nothing is read from it —
// include and extends are off, and so is path resolution — and it names a path that
// does not exist, so that a future option that started reading files would fail rather
// than read the verifier's own.
const loadWorkingDir = "/nonexistent/pcverify-compose"

// loadModel runs docker compose's loader over text, with the stages composeload.go's
// header switches off, then validates it the way docker compose does (validateAsLoaded).
// An error is a refusal docker compose would make whatever the environment holds.
func loadModel(text []byte, what string) (map[string]any, error) {
	model, err := loadFiles([]types.ConfigFile{{Filename: composeFilename, Content: text}})
	if err != nil {
		return nil, fmt.Errorf("docker compose cannot load %s: %v", what, err)
	}
	if err := validateAsLoaded(text, model); err != nil {
		return nil, fmt.Errorf("docker compose refuses %s: %v", what, err)
	}
	return model, nil
}

// composeFilename is the name the loader is given for the text; it appears in its errors.
const composeFilename = "docker-compose.yaml"

// loadFiles is the loader with this file's options and schema validation off.
func loadFiles(files []types.ConfigFile) (map[string]any, error) {
	return loader.LoadModelWithContext(context.Background(), types.ConfigDetails{
		WorkingDir:  loadWorkingDir,
		ConfigFiles: files,
		Environment: map[string]string{},
	}, func(o *loader.Options) {
		o.SetProjectName("app", true)
		o.Interpolate = castOnly(o.Interpolate)
		o.SkipInclude = true
		o.SkipExtends = true
		o.SkipNormalization = true
		o.SkipDefaultValues = true
		o.SkipResolveEnvironment = true
		o.ResolvePaths = false
		o.SkipConsistencyCheck = true
		o.SkipValidation = true
	})
}

// castOnly turns the loader's interpolation stage into its type casts alone.
//
// docker compose's interpolation does two things: it substitutes `${VAR}` from the
// environment, and it casts the strings at typed paths — `privileged: "true"` becomes the
// boolean true, `ports[].target: "80"` the integer 80. The first needs an environment the
// verifier does not have, so every template is left exactly as written. The second
// decides what runs, so it is kept: skipping it would read `privileged: "true"` as a
// string, which docker compose does not, and refuse a manifest docker compose loads. A
// value still holding `$` is left uncast, since its type is the environment's to decide.
func castOnly(opts *interp.Options) *interp.Options {
	casts := make(map[tree.Path]interp.Cast, len(opts.TypeCastMapping))
	for p, cast := range opts.TypeCastMapping {
		casts[p] = func(v string) (any, error) {
			if strings.Contains(v, "$") {
				return v, nil
			}
			return cast(v)
		}
	}
	return &interp.Options{
		LookupValue:     func(string) (string, bool) { return "", false },
		TypeCastMapping: casts,
		Substitute:      func(s string, _ template.Mapping) (string, error) { return s, nil },
	}
}

// validateAsLoaded applies compose's schema where docker compose applies it — after each
// YAML document is merged in, not only once at the end — and then its post-load checks.
//
// Per document, because a later document can repair an earlier one: `bogus: x` in the
// first and `bogus: !reset null` in the second loads as valid as a whole, but docker
// compose validated the merge after the first document and refused it there. So each
// prefix of the documents is loaded and validated in turn. (The prefix models are
// compose's canonical form rather than the raw merge it validates; the canonical
// transforms only rewrite shapes the schema accepts either way.)
func validateAsLoaded(text []byte, model map[string]any) error {
	docs, err := splitDocuments(text)
	if err != nil {
		return err // unreachable: the loader just decoded the same text
	}
	for k := 1; k < len(docs); k++ {
		files := make([]types.ConfigFile, k)
		for i := range files {
			files[i] = types.ConfigFile{Filename: composeFilename, Content: docs[i]}
		}
		prefix, err := loadFiles(files)
		if err != nil {
			return fmt.Errorf("after document %d of %d: %v", k, len(docs), err)
		}
		if err := validateSchema(prefix); err != nil {
			return fmt.Errorf("after document %d of %d: %v", k, len(docs), err)
		}
	}
	if err := validateSchema(model); err != nil {
		return err
	}
	return validation.Validate(model)
}

// splitDocuments returns each YAML document of text on its own, re-encoded from its node
// tree — compose's tags, anchors and aliases included, since they are all on the nodes.
func splitDocuments(text []byte) ([][]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(text))
	var docs [][]byte
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		out, err := yaml.Marshal(&doc)
		if err != nil {
			return nil, err
		}
		docs = append(docs, out)
	}
}

// validateSchema checks model against compose's schema, and reports a violation only when
// it does not rest on a value the environment decides.
//
// docker compose substitutes `${VAR}` before it validates, so a violation AT a value
// holding a template — `ulimits.nofile.soft: ${NOFILE}` is not an integer yet,
// `depends_on.db.condition: ${C}` is in no enum yet — is the environment's to settle, and
// docker compose loads the file whenever it does. Every violation the schema reports is
// judged on its own (compose-go's Validate keeps only one), and one is set aside when the
// value it is about contains `$`. Two kinds never are: an unknown key and a missing
// required one, which are about which KEYS exist, and no value of any variable changes
// that — `bogus: "${X}"` is refused, as docker compose refuses it.
//
// What this does not establish is the converse. A violation set aside may be one no value
// could repair (`cap_add: "${X}"` is a string whatever X holds), so a manifest this accepts
// can still be one docker compose refuses for every environment. That direction describes
// a deployment that runs nothing, so the review reads it rather than refusing it; the
// direction that matters — refusing a manifest docker compose loads — does not occur.
func validateSchema(model map[string]any) error {
	result, err := gojsonschema.Validate(gojsonschema.NewStringLoader(schema.Schema), gojsonschema.NewGoLoader(model))
	if err != nil {
		return err
	}
	var kept []gojsonschema.ResultError
	for _, e := range result.Errors() {
		if !settledByEnvironment(e) {
			kept = append(kept, e)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	// The most specific violation reads best: a oneOf failure is reported alongside the
	// errors of its closest branch, and those name the field.
	pick := kept[0]
	for _, e := range kept {
		if t := e.Type(); t != "number_one_of" && t != "number_any_of" {
			pick = e
			break
		}
	}
	return fmt.Errorf("%s: %s", pick.Field(), pick.Description())
}

// settledByEnvironment reports whether a schema violation is about a value whose final
// form the environment decides.
func settledByEnvironment(e gojsonschema.ResultError) bool {
	switch e.Type() {
	case "additional_property_not_allowed", "required", "invalid_property_name":
		return false
	}
	return holdsTemplate(e.Value())
}

// holdsTemplate reports whether v, or anything under it, is a string containing `$`.
// Keys are not looked at: compose substitutes values only.
func holdsTemplate(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.Contains(t, "$")
	case map[string]any:
		for _, e := range t {
			if holdsTemplate(e) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if holdsTemplate(e) {
				return true
			}
		}
	}
	return false
}

// toNode re-encodes a loaded model as the node tree the review and the renderer walk.
func toNode(model any, what string) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(model); err != nil {
		// Unreachable for a model the loader produced, which holds only YAML-decoded values.
		return nil, fmt.Errorf("%s does not re-encode: %v", what, err)
	}
	return &n, nil
}

// readComposeDocument loads a manifest's compose text and returns its top level.
func readComposeDocument(doc []byte) (*yaml.Node, error) {
	model, err := loadModel(doc, "the compose text")
	if err != nil {
		return nil, err
	}
	return toNode(model, "the compose text")
}

// loadServiceBlock loads one recorded service body exactly as a manifest's service is
// loaded: wrapped in a compose file under its own name, then read back out. The wrapper is
// what lets the loader's per-service transforms apply to it at all.
func loadServiceBlock(name string, body []byte) (*yaml.Node, error) {
	what := "the recorded block for " + name
	parsed, err := parseOneDocument(body, what)
	if err != nil {
		return nil, err
	}
	if parsed.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s is not a mapping", what)
	}
	model, err := loadModel(wrap(map[string]*yaml.Node{"services": mapOf(name, parsed)}), what)
	if err != nil {
		return nil, err
	}
	services, _ := model["services"].(map[string]any)
	return toNode(services[name], what)
}

// loadTopLevelBlock loads one recorded top-level section the same way: as the only
// section of a compose file with no services, then read back out.
func loadTopLevelBlock(key string, value []byte) (*yaml.Node, error) {
	what := "the recorded top-level " + key + " section"
	parsed, err := parseOneDocument(value, what)
	if err != nil {
		return nil, err
	}
	model, err := loadModel(wrap(map[string]*yaml.Node{key: parsed}), what)
	if err != nil {
		return nil, err
	}
	return toNode(model[key], what)
}

// parseOneDocument parses recorded text that must be exactly one YAML document. A second
// document is refused rather than dropped: in a manifest docker compose would merge it,
// so a recorded block that silently lost one would describe less than it says.
func parseOneDocument(text []byte, what string) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(text))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s is empty", what)
		}
		return nil, fmt.Errorf("%s does not parse as YAML: %v", what, err)
	}
	var next yaml.Node
	if err := dec.Decode(&next); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s holds more than one YAML document", what)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("%s is empty", what)
	}
	return doc.Content[0], nil
}

// mapOf is a one-entry mapping node.
func mapOf(key string, value *yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value}}
}

// wrap renders a compose file from top-level sections. Marshalling the parsed nodes
// rather than splicing text keeps the recorded block's indentation from mattering.
func wrap(sections map[string]*yaml.Node) []byte {
	top := &yaml.Node{Kind: yaml.MappingNode}
	for _, k := range sortedNodeKeys(sections) {
		top.Content = append(top.Content, mapOf(k, sections[k]).Content...)
	}
	out, err := yaml.Marshal(top)
	if err != nil {
		// A node tree yaml.v3 itself just parsed always marshals.
		panic(err)
	}
	return out
}

func sortedNodeKeys(m map[string]*yaml.Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// cloneNode deep-copies a node tree. The trees here come from toNode and hold no aliases,
// so a plain recursive copy is complete.
func cloneNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, ch := range n.Content {
		c.Content[i] = cloneNode(ch)
	}
	return &c
}
