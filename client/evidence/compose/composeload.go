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
// WHAT IS LOADED, AND WHAT IS NOT. docker compose's per-document loop, run step for
// step with compose-go's own functions (loadModel lists them): every YAML document decoded
// with !reset / !override applied and anchors and merge keys resolved by yaml.v3, merged,
// de-duplicated and validated against compose's schema, and then compose's canonical
// transforms (short syntax to long). Not loader.LoadModelWithContext itself, because it
// can only validate with substitution or not at all, and this needs validation without
// substitution — run in docker compose's place, before the transforms, which panic on
// input the schema has not passed. TestLoad_IsComposeGosLoader holds the result to that
// function's on every input both accept. What is not done, each for a stated reason:
//
//   - Substitution. `${VAR}` values come from the CVM's encrypted environment, which the
//     verifier does not have; every template is left as written, and the review treats
//     every `$` as provider-controlled. The type casts interpolation also performs, and
//     its template syntax check, are kept (castOnly); strings docker compose parses after
//     substituting are held back from parsing (templatedShortSyntax).
//   - include, and extends: compose-go resolves both by reading FILES, from the machine
//     running the loader — on a verifier, the verifier's own. Neither is loaded; the
//     review reports both as blocking, since what they pull in is not in the manifest.
//   - Normalization, default values, environment resolution and path resolution: each
//     rewrites the model toward what a particular host would run (project names, the
//     default network, env_file contents, absolute paths under the working directory).
//     None of it is in the manifest, and folding it in would make a record depend on
//     where it was taken.
//   - The project consistency check: it cross-references names (depends_on targets and
//     the like). A manifest failing it runs nothing at all; no rule here depends on it.
//
// Schema violations are judged one by one (validateSchema), because without the
// environment the schema refuses some manifests docker compose accepts — `privileged: ${P}`
// is not a boolean until the environment fills it in.
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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	interp "github.com/compose-spec/compose-go/v2/interpolation"
	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/override"
	"github.com/compose-spec/compose-go/v2/schema"
	"github.com/compose-spec/compose-go/v2/template"
	"github.com/compose-spec/compose-go/v2/transform"
	"github.com/compose-spec/compose-go/v2/tree"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/compose-spec/compose-go/v2/validation"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

// errNotRead marks a manifest pcverify did not read — too many documents, or a failure of
// its own loader. That is not docker compose refusing the manifest, and not a finding about
// it: a recorded deployment it hits is reported as not compared (exit 3), never as a
// mismatch.
var errNotRead = errors.New("not read by pcverify")

// loadModel loads compose text as docker compose v2.26.0's loader does, in its order and
// with compose-go's own steps (loadYamlModel in compose-go v2.0.2's loader/loader.go), for
// each YAML document in turn:
//
//	decode, applying !reset / !override within the document (loader.ParseYAML)
//	interpolate — here, type casts and template syntax only (castOnly)
//	null lists to empty ones (fixEmptyNotNull)
//	apply the document's !reset / !override to what earlier documents built (applyResets)
//	merge it in (override.Merge), de-duplicate (override.EnforceUnicity)
//	validate the result against compose's schema (validateSchema)
//
// and then, once, the canonical transforms, a second de-duplication and compose's
// post-load validation. The order is the point. compose-go's transforms assume
// schema-valid input and type-assert accordingly; run on input the schema has not passed,
// `volumes: {v: hello}` or `networks: [1]` panics them, and a verifier a provider can
// crash with one line is a verifier any provider can take offline. docker compose never
// gets there, because it validates every document first; neither does this.
//
// extends and include are not steps here at all: compose-go resolves both by reading
// files, on whatever machine runs the loader (the review reports both as blocking).
// Normalization, default values and environment and path resolution are not either:
// each rewrites the model toward what one particular host would run.
func loadModel(text []byte, what string) (model map[string]any, err error) {
	// compose-go's code runs on input a provider chose, and some of it panics on input it
	// has not validated yet — `env_file: [{required: true}]` crashes docker compose's own
	// loader. Whatever it does, the run reports; it does not crash.
	defer func() {
		if p := recover(); p != nil {
			model, err = nil, fmt.Errorf("compose-go, the loader docker compose runs, failed while loading %s (%v). "+
				"docker compose's own loader fails the same way on such input — it de-duplicates lists before it "+
				"validates them — but where templates are involved pcverify cannot rule out its own part, so the "+
				"manifest was not compared (%w)", what, p, errNotRead)
		}
	}()
	docs, err := documents(text)
	if err != nil {
		return nil, fmt.Errorf("docker compose cannot load %s: %v", what, err)
	}
	if len(docs) > maxDocuments {
		return nil, fmt.Errorf("%s holds more than %d YAML documents, the most pcverify reads (%w)",
			what, maxDocuments, errNotRead)
	}
	key, err := newHoldKey()
	if err != nil {
		return nil, fmt.Errorf("%v (%w)", err, errNotRead)
	}
	opts := castOnly(key)
	model = map[string]any{}
	for i, doc := range docs {
		where := ""
		if len(docs) > 1 {
			where = fmt.Sprintf(" (document %d of %d)", i+1, len(docs))
		}
		if doc.empty {
			// What docker compose's decode loop makes of a document with nothing in it.
			return nil, fmt.Errorf("docker compose cannot load %s%s: Top-level object must be a mapping", what, where)
		}
		raw, err := loader.ParseYAML(doc.text)
		if err != nil {
			return nil, fmt.Errorf("docker compose cannot load %s%s: %v", what, where, err)
		}
		cfg, err := interp.Interpolate(raw, *opts)
		if err != nil {
			return nil, fmt.Errorf("docker compose cannot load %s%s: %v", what, where, err)
		}
		fixEmptyNotNull(cfg)
		applyResets(model, doc.resets, tree.NewPath())
		if model, err = override.Merge(model, cfg); err != nil {
			return nil, fmt.Errorf("docker compose cannot load %s%s: %v", what, where, err)
		}
		if model, err = override.EnforceUnicity(model); err != nil {
			return nil, fmt.Errorf("docker compose cannot load %s%s: %v", what, where, err)
		}
		// Validated as the strings the held templates will be restored to, which is what
		// the schema sees in docker compose (as substituted text).
		if err := validateSchema(withTemplatesRestored(model, key)); err != nil {
			return nil, fmt.Errorf("docker compose refuses %s%s: %v", what, where, err)
		}
		delete(model, "version") // docker compose drops it, with a warning, once validated
	}
	if len(model) == 0 {
		return nil, fmt.Errorf("docker compose cannot load %s: empty compose file", what)
	}
	if model, err = transform.Canonical(model); err != nil {
		return nil, fmt.Errorf("docker compose cannot load %s: %v", what, err)
	}
	if model, err = override.EnforceUnicity(model); err != nil {
		return nil, fmt.Errorf("docker compose cannot load %s: %v", what, err)
	}
	restoreTemplates(model, key)
	if err := validation.Validate(model); err != nil {
		return nil, fmt.Errorf("docker compose refuses %s: %v", what, err)
	}
	return model, nil
}

// maxDocuments bounds the YAML documents in one compose text. docker compose has no such
// bound, but it re-validates everything merged so far after each document, so the cost of
// a text grows with the square of its document count — and the text is the provider's to
// write. A manifest has no need for more than one; one past the bound is not read (exit 3).
const maxDocuments = 16

// document is one YAML document of a compose text: its own text, and where it tags
// !reset or !override.
type document struct {
	text   []byte
	resets []tree.Path
	empty  bool
}

// documents splits text into its YAML documents. Each is re-encoded from its node tree —
// compose's tags, anchors and aliases are all on the nodes — so loader.ParseYAML can read
// it on its own.
func documents(text []byte) ([]document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(text))
	var docs []document
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		out, err := yaml.Marshal(&node)
		if err != nil {
			return nil, err
		}
		// A document with nothing in it (a trailing `---`) is a null: its re-encoding is
		// empty text, which ParseYAML would report as end-of-file rather than as what
		// docker compose reports.
		empty := len(node.Content) == 0 ||
			(len(node.Content) == 1 && node.Content[0].Kind == yaml.ScalarNode && node.Content[0].Tag == "!!null")
		doc := document{text: out, empty: empty}
		if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
			recordResets(node.Content[0], tree.NewPath(), &doc.resets)
		}
		if len(docs) == maxDocuments {
			return append(docs, doc), nil // one past the bound is enough to say so; not read further
		}
		docs = append(docs, doc)
	}
}

// recordResets and applyResets are compose-go v2.0.2's ResetProcessor (loader/reset.go)
// — resolveReset's path recording and applyNullOverrides — which compose-go does not let a
// caller construct. They are reproduced exactly, the inconsistency included: a path inside
// a sequence is recorded as its index ("0") and matched as "[0]", so across documents a
// !reset inside a list never applies, in docker compose as here.
func recordResets(n *yaml.Node, p tree.Path, out *[]tree.Path) {
	if n.Tag == "!reset" || n.Tag == "!override" {
		*out = append(*out, p)
		return
	}
	switch n.Kind {
	case yaml.SequenceNode:
		for i, c := range n.Content {
			recordResets(c, p.Next(strconv.Itoa(i)), out)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			recordResets(n.Content[i+1], p.Next(n.Content[i].Value), out)
		}
	}
}

func applyResets(target any, paths []tree.Path, p tree.Path) {
	if len(paths) == 0 {
		return
	}
	switch v := target.(type) {
	case map[string]any:
	keys:
		for k, e := range v {
			next := p.Next(k)
			for _, pattern := range paths {
				if next.Matches(pattern) {
					delete(v, k)
					continue keys
				}
			}
			applyResets(e, paths, next)
		}
	case []any:
	items:
		for i, e := range v {
			next := p.Next(fmt.Sprintf("[%d]", i))
			for _, pattern := range paths {
				if next.Matches(pattern) {
					continue items
				}
			}
			applyResets(e, paths, next)
		}
	}
}

// fixEmptyNotNull is compose-go v2.0.2's (loader/fix.go): a list decoded empty is an
// empty list, not a null one.
func fixEmptyNotNull(value any) any {
	switch v := value.(type) {
	case []any:
		if v == nil {
			return []any{}
		}
		for i, e := range v {
			v[i] = fixEmptyNotNull(e)
		}
	case map[string]any:
		for k, e := range v {
			v[k] = fixEmptyNotNull(e)
		}
	}
	return value
}

// typeCasts is the loader's own table of typed paths, as its interpolation receives it.
// compose-go keeps the table unexported; a loader call with no files hands it to an option
// function and returns before reading anything.
var typeCasts = sync.OnceValue(func() map[tree.Path]interp.Cast {
	var casts map[tree.Path]interp.Cast
	_, _ = loader.LoadModelWithContext(context.Background(), types.ConfigDetails{}, func(o *loader.Options) {
		casts = o.Interpolate.TypeCastMapping
	})
	return casts
})

// castOnly turns the loader's interpolation stage into its type casts alone.
//
// docker compose's interpolation does two things: it substitutes `${VAR}` from the
// environment, and it casts the strings at typed paths — `privileged: "true"` becomes the
// boolean true, `ports[].target: "80"` the integer 80. The first needs an environment the
// verifier does not have, so every template is left exactly as written — after the same
// syntax check docker compose makes, so a malformed template is still refused. The second
// decides what runs, so it is kept: skipping it would read `privileged: "true"` as a
// string, which docker compose does not, and refuse a manifest docker compose loads. A
// value still holding `$` is left uncast, since its type is the environment's to decide.
//
// And the strings docker compose PARSES after substituting are held back from parsing
// here (heldTemplate).
func castOnly(key string) *interp.Options {
	table := typeCasts()
	casts := make(map[tree.Path]interp.Cast, len(table)+len(templatedShortSyntax))
	for p, cast := range table {
		casts[p] = func(v string) (any, error) {
			if strings.Contains(v, "$") {
				return v, nil
			}
			return cast(v)
		}
	}
	for _, p := range templatedShortSyntax {
		cast, typed := casts[p]
		casts[p] = func(v string) (any, error) {
			if strings.Contains(v, "$") {
				return heldTemplate(key, v), nil
			}
			if typed {
				return cast(v)
			}
			return v, nil
		}
	}
	return &interp.Options{
		LookupValue:     func(string) (string, bool) { return "", false },
		TypeCastMapping: casts,
		Substitute: func(s string, _ template.Mapping) (string, error) {
			// docker compose refuses a template it cannot parse; a variable that is missing
			// or empty is the environment's business, not a refusal. Every variable is
			// reported present (and empty) so the parse runs without compose-go's
			// "variable is not set" warning for each one.
			_, err := template.Substitute(s, func(string) (string, bool) { return "", true })
			var invalid *template.InvalidTemplateError
			if errors.As(err, &invalid) {
				return s, err
			}
			return s, nil
		},
	}
}

// templatedShortSyntax are the paths whose strings compose's canonical transforms PARSE:
// a short-syntax mount (`source:target:options`), a short-syntax port
// (`ip:published:target/proto`), and a ulimit given as one number. docker compose parses
// them after substituting the environment. Parsed here, before substitution, a template
// is read as text it is not — `/data:/d:${MODE}` loses its options entirely (the volume
// parser ignores what it does not recognise), `${DATA:-./data}:/data` splits at the
// default's colon, a templated ulimit is refused outright — and the canonical form then
// equals that of a text docker compose would run differently. So such a string is not
// parsed at all: it is held in a mapping the transforms pass through unchanged, and put
// back as written once the loader is done (restoreTemplates). The canonical form keeps
// the text, and the review reports it as the environment's.
var templatedShortSyntax = []tree.Path{
	tree.NewPath("services", tree.PathMatchAll, "volumes", tree.PathMatchList),
	tree.NewPath("services", tree.PathMatchAll, "ports", tree.PathMatchList),
	tree.NewPath("services", tree.PathMatchAll, "ulimits", tree.PathMatchAll),
}

// A held template is a mapping under a key no manifest can write: `x-pcverify-held-`
// and 128 random bits, drawn afresh for every load. It has to be unguessable, not merely
// unusual. compose's schema allows `x-` keys inside a long-syntax mount, port or ulimit,
// and docker compose ignores them, so a provider who knew the key could write a real
// mount — `{type: bind, source: /, target: /host}` — carrying it, and have restoreTemplates
// swap that mount for whatever string it named: the review would read the string and the
// canonical form would record it, while docker compose mounted the host's root. A key
// drawn at load time cannot appear in a manifest written before it, and a mapping is
// restored only if it is exactly what heldTemplate built — that key, and a `target` of
// the key and the held text — so a provider's own `x-` key never qualifies. `target` is
// set because the loader's uniqueness pass indexes mounts and ports by it, and it carries
// the key so that it can equal no real entry's target: set to the text alone, a real
// mount whose target was that text was merged into the held entry and vanished, a bind of
// the host's root included. Which entries docker compose merges is decided after
// substitution; blockOf says so when it matters (templatedIdentity).
const holdKeyPrefix = "x-pcverify-held-"

func newHoldKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cannot draw a key to hold templates under: %v", err)
	}
	return holdKeyPrefix + hex.EncodeToString(b[:]), nil
}

func heldTemplate(key, v string) map[string]any {
	return map[string]any{key: v, "target": key + ":" + v}
}

// restoreTemplates puts every template castOnly held under key back as the string it was
// written as.
func restoreTemplates(model map[string]any, key string) {
	services, _ := model["services"].(map[string]any)
	for _, svc := range services {
		body, _ := svc.(map[string]any)
		for _, field := range []string{"volumes", "ports"} {
			if list, ok := body[field].([]any); ok {
				for i, e := range list {
					if held, ok := heldText(e, key); ok {
						list[i] = held
					}
				}
			}
		}
		if limits, ok := body["ulimits"].(map[string]any); ok {
			for k, e := range limits {
				if held, ok := heldText(e, key); ok {
					limits[k] = held
				}
			}
		}
	}
}

// withTemplatesRestored is model with its held templates as strings, copying only what it
// changes: the services, the lists and maps that hold a template, nothing else.
func withTemplatesRestored(model map[string]any, key string) map[string]any {
	services, ok := model["services"].(map[string]any)
	if !ok {
		return model
	}
	view := make(map[string]any, len(model))
	for k, v := range model {
		view[k] = v
	}
	svcs := make(map[string]any, len(services))
	for name, svc := range services {
		body, ok := svc.(map[string]any)
		if !ok {
			svcs[name] = svc
			continue
		}
		b := make(map[string]any, len(body))
		for k, v := range body {
			b[k] = v
		}
		for _, field := range []string{"volumes", "ports"} {
			if list, ok := body[field].([]any); ok {
				cp := make([]any, len(list))
				for i, e := range list {
					if held, ok := heldText(e, key); ok {
						cp[i] = held
					} else {
						cp[i] = e
					}
				}
				b[field] = cp
			}
		}
		if limits, ok := body["ulimits"].(map[string]any); ok {
			cp := make(map[string]any, len(limits))
			for k, e := range limits {
				if held, ok := heldText(e, key); ok {
					cp[k] = held
				} else {
					cp[k] = e
				}
			}
			b["ulimits"] = cp
		}
		svcs[name] = b
	}
	view["services"] = svcs
	return view
}

// heldText returns the text of a mapping heldTemplate built under key, and nothing for
// any other mapping.
func heldText(v any, key string) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 2 {
		return "", false
	}
	s, ok := m[key].(string)
	if !ok || m["target"] != key+":"+s {
		return "", false
	}
	return s, true
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
	compiled, err := composeSchema()
	if err != nil {
		return err
	}
	result, err := compiled.Validate(gojsonschema.NewGoLoader(model))
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

// composeSchema is compose's schema, compiled once: compiling it is most of what one
// validation costs, and a run validates every recorded block as well as the manifest.
var composeSchema = sync.OnceValues(func() (*gojsonschema.Schema, error) {
	return gojsonschema.NewSchema(gojsonschema.NewStringLoader(schema.Schema))
})

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
