package evidence

// composedoc.go reads the compose text the way docker compose reads it, before anything
// in this package looks at a service.
//
// WHY THAT IS A RULE AND NOT A DETAIL. Everything downstream — the review's findings and
// the canonical block a baseline is matched against — describes what the YAML says. If
// that reading differs from docker compose's, the review describes a deployment that does
// not run, and a baseline match vouches for text nobody executes. Two such differences
// were found by running docker compose's own loader against this package
// (testdata/composego), and both were exploitable:
//
//   - A file may hold several YAML documents, and docker compose MERGES them all into the
//     project it runs. yaml.Unmarshal reads the first and silently drops the rest. So a
//     benign first document matched a recorded baseline exactly, while a second one
//     (`services: {app: {privileged: true}}`) made the running container privileged.
//
//   - compose's !reset tag removes the node it tags BEFORE the YAML is decoded. On a key
//     that overrides a merged one, that undoes the override: `<<: *base` with
//     `privileged: !reset false` runs PRIVILEGED, from the anchor, while a reader that
//     ignored the tag saw `false`.
//
// WHICH docker compose. The one dstack ships — v2.26.0 on both OS images the fleet boots,
// which loads with compose-go v2.0.2 over gopkg.in/yaml.v3 v3.0.1, the yaml.v3 this
// module links. testdata/composego/main.go has the provenance and records that loader's
// reading of every case; TestComposeDocument_AgreesWithComposeGo holds this file to it.
//
// HOW. In compose-go's own order: the !reset / !override pass over the node tree, then
// yaml.v3's decode of the result — the decode that resolves aliases and merge keys in
// docker compose. Running that same decode here, rather than reimplementing each of its
// refusals, is what makes this file agree with it on what is NOT a valid compose text:
// duplicate keys, a merge of something that is not a mapping, a self-containing anchor,
// and an alias bomb are all refused by the decoder itself, with its own limits, before
// resolveAnchors expands a single alias. Only then is the tree resolved into the form the
// review walks.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"
)

// The two tags compose defines on top of YAML. compose-go compares Node.Tag against these
// exact strings, and so does this file.
const (
	composeResetTag    = "!reset"
	composeOverrideTag = "!override"
)

// readComposeDocument parses compose text and returns its top-level node with compose's
// tags applied and every anchor resolved, or the reason docker compose would read it
// differently from this package — in which case nothing below the top level can be
// described honestly, and the caller reports that instead.
func readComposeDocument(doc []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the compose text is an empty document")
		}
		return nil, fmt.Errorf("the compose text does not parse as YAML: %w", err)
	}
	var next yaml.Node
	switch err := dec.Decode(&next); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return nil, fmt.Errorf("the compose text does not parse as YAML: %w", err)
	default:
		// Refused rather than merged. A manifest has no need for a second document, and
		// reproducing compose's cross-document merge here would be a second
		// reimplementation of its semantics to keep in step — the thing this file exists
		// to avoid.
		return nil, errors.New("the compose text holds more than one YAML document. docker compose merges " +
			"every document in the file into the project it runs, so the first one alone does not describe " +
			"what runs; this review reads only single-document compose files")
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, errors.New("the compose text is an empty document")
	}

	top := applyComposeTags(root.Content[0])
	if top == nil {
		return nil, fmt.Errorf("the compose text's top level is tagged %s, which leaves docker compose "+
			"nothing to load", composeResetTag)
	}

	// The decode docker compose runs. Its result is not used — only its refusal is.
	var decoded any
	if err := top.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("docker compose's YAML reader refuses the compose text (%v), so what each "+
			"service contains cannot be read", err)
	}
	if err := requireStringKeys(decoded, ""); err != nil {
		return nil, err
	}

	resolved, err := resolveAnchors(top)
	if err != nil {
		// Unreachable for anything the decode accepted, which refuses every input
		// resolveAnchors does. Kept because the review's view must never be built from a
		// half-resolved tree.
		return nil, fmt.Errorf("the compose text's YAML anchors do not resolve, so what each service "+
			"actually contains cannot be read: %w", err)
	}
	return resolved, nil
}

// applyComposeTags applies !reset and !override as compose-go v2.0.2's ResetProcessor
// does to a single file, IN PLACE: a node tagged !reset is removed from the mapping or
// sequence that holds it, and a node tagged !override is kept and not looked inside.
// It returns nil when n itself is tagged !reset.
//
// The rest is compose-go's behaviour, reproduced exactly, including the parts that look
// like oversights — because the point is to agree with what runs, not with what compose
// may have meant:
//
//   - Only VALUES are visited. A mapping key tagged !reset stays.
//   - Aliases are not followed. A !reset inside an anchored mapping is removed where the
//     anchor is written, so every alias of it loses the key; a !reset on the anchored
//     node itself removes it from where it is written but not from the anchor, so its
//     aliases keep it.
//   - !override stops the walk, so a !reset beneath one is never applied.
//   - Within one file !override has no other effect. Its cross-file meaning needs a
//     second file, which a dstack deployment does not have.
func applyComposeTags(n *yaml.Node) *yaml.Node {
	switch n.Tag {
	case composeResetTag:
		return nil
	case composeOverrideTag:
		return n
	}
	switch n.Kind {
	case yaml.SequenceNode:
		kept := n.Content[:0:0]
		for _, c := range n.Content {
			if r := applyComposeTags(c); r != nil {
				kept = append(kept, r)
			}
		}
		n.Content = kept
	case yaml.MappingNode:
		kept := n.Content[:0:0]
		for i := 0; i+1 < len(n.Content); i += 2 {
			if r := applyComposeTags(n.Content[i+1]); r != nil {
				kept = append(kept, n.Content[i], r)
			}
		}
		n.Content = kept
	}
	return n
}

// requireStringKeys refuses a decoded document with a mapping key that is not a string,
// as compose-go does right after decoding (convertToStringKeysRecursive). `1: x` decodes
// to an int key, and docker compose will not load the file.
func requireStringKeys(v any, path string) error {
	at := func(k string) string {
		if path == "" {
			return k
		}
		return path + "." + k
	}
	switch m := v.(type) {
	case map[string]any:
		for _, k := range sortedAnyKeys(m) {
			if err := requireStringKeys(m[k], at(k)); err != nil {
				return err
			}
		}
	case map[any]any:
		keys := make([]any, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		for _, k := range keys {
			s, ok := k.(string)
			if !ok {
				where := "at the top level"
				if path != "" {
					where = "in " + path
				}
				return fmt.Errorf("the compose text has a mapping key that is not a string (%#v %s), which "+
					"docker compose refuses to load", k, where)
			}
			if err := requireStringKeys(m[k], at(s)); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range m {
			if err := requireStringKeys(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortedAnyKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
