package evidence

// composeanchor.go resolves YAML anchors — aliases (`*name`) and merge keys (`<<`) —
// into the content they name, so that everything downstream reads a service as it will
// actually run rather than as it happens to be written.
//
// WHY THIS REPLACED A REFUSAL. The first version of this package refused any block
// containing an alias or a merge key, on the reasoning that the canonical form would
// otherwise describe a pointer rather than a service. The reasoning was right; the remedy
// was wrong, and a fleet sweep showed how wrong. Of the four providers checked on
// 2026-10-10, three could not produce a canonical form for a SINGLE service — cn-39 (23
// services), cn-19 (13) and cn-41 (10) all write the ordinary compose idiom
//
//	x-logging: &default-logging
//	  driver: json-file
//	services:
//	  broker: {logging: *default-logging}
//
// and every service was refused. Only cn-20 produced blocks at all, and only because it
// happens not to use anchors. A baseline mechanism that cannot describe three quarters of
// the fleet is not strict, it is inapplicable.
//
// Resolving is also the more correct answer, not merely the more convenient one. An
// anchor is REPRESENTATION — the same class of thing as quoting, indentation and
// flow-versus-block style, all of which this package already drops. Two manifests that
// resolve to the same services ARE the same deployment, and a comparison that calls them
// different is measuring the author's editing habits. The refusal treated representation
// as content; that was the actual bug.
//
// It closes a reporting hole as well. composereview.go used to report a merged service as
// undescribable and, worse, reported `laya-w2` on cn-39 as naming no image — because the
// image was in the anchor the service merged. A review that cannot see `privileged: true`
// behind a merge key is not reporting conservatively, it is reporting wrongly.
//
// WHAT CANNOT BE RESOLVED is a cycle, and only a cycle. An alias to an anchor the
// document never defines is rejected by yaml.v3 at parse time, so a document that parsed
// has every alias pointing somewhere. A self-referencing anchor does not:
//
//	a: &x
//	  b: *x
//
// parses cleanly and gives a node graph with a BACK-EDGE, which is what once turned this
// package's deep copy into unbounded recursion and killed the process on input a provider
// chooses freely. Expansion here is bounded by the path check in resolveNode, so the same
// input now produces an error rather than a stack overflow.

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// mergeKey is YAML's merge key. Not a compose key at all — the compose schema never
// defines it, which is why composereview.go has no rule for it and why resolution has to
// happen before that walk rather than inside it.
const mergeKey = "<<"

// isMergeKey is yaml.v3's own test (isMerge in its decode.go), so that what merges here
// is exactly what merges in docker compose. The spelling alone is not enough: a QUOTED
// "<<", or one tagged !!str, is an ordinary key named "<<" that merges nothing.
func isMergeKey(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Value == mergeKey &&
		(k.Tag == "" || k.Tag == "!" || k.ShortTag() == "!!merge")
}

// resolveAnchors returns an alias-free, merge-key-free deep copy of n.
//
// A COPY, always, even when there is nothing to resolve. Callers mutate what they get
// back (blockOf deletes the image key and rewrites scalars), and the tree they are given
// is also walked by composereview.go — so returning the original on the "nothing to do"
// path would make the no-anchor case the one that corrupts the review's view, which is
// precisely the case every test would exercise and none would catch.
func resolveAnchors(n *yaml.Node) (*yaml.Node, error) {
	return resolveNode(n, map[*yaml.Node]bool{})
}

// resolveNode copies n with every alias expanded. expanding holds the anchor targets on
// the current expansion PATH, not every target seen: twenty services sharing one
// `*default-logging` is the normal case and must resolve twenty times, while an anchor
// reached while it is still being expanded is a cycle and has no finite value.
func resolveNode(n *yaml.Node, expanding map[*yaml.Node]bool) (*yaml.Node, error) {
	if n == nil {
		return nil, nil
	}
	if n.Kind == yaml.AliasNode {
		target := n.Alias
		if target == nil {
			// Unreachable through yaml.Unmarshal, which fails with "unknown anchor" before
			// returning a document. Kept so a hand-built node tree gets a sentence rather
			// than a nil dereference.
			return nil, fmt.Errorf("the compose text references the anchor *%s, which the document does not define", n.Value)
		}
		if expanding[target] {
			return nil, fmt.Errorf("the anchor *%s contains a reference to itself, so it expands forever "+
				"and names no finite value", n.Value)
		}
		expanding[target] = true
		defer delete(expanding, target)
		return resolveNode(target, expanding)
	}
	if n.Kind == yaml.MappingNode {
		return resolveMapping(n, expanding)
	}

	out := *n
	out.Alias, out.Anchor, out.Content = nil, "", nil
	if len(n.Content) > 0 {
		out.Content = make([]*yaml.Node, 0, len(n.Content))
		for _, child := range n.Content {
			rc, err := resolveNode(child, expanding)
			if err != nil {
				return nil, err
			}
			out.Content = append(out.Content, rc)
		}
	}
	return &out, nil
}

// resolveMapping copies a mapping, expanding its merge keys in place.
//
// KEY ORDER, which the canonical form keeps and therefore has to pin down: the mapping's
// own keys first, in the order written, then the merged keys in the order their sources
// were merged. YAML itself defines no order for a mapping, so this is a choice rather
// than a reading of the spec — but the canonical form already treats key order as
// significant, so it needs one rule, stated here, instead of whatever the emitter happens
// to do.
//
// PRECEDENCE is the spec's: a key written in the mapping beats the same key from any
// merge, and among merges the earlier source wins (`<<: [*a, *b]` takes a's). That is
// also the order docker compose itself resolves, so what this produces is what runs —
// checked against docker compose's own loader, not assumed (testdata/composego).
func resolveMapping(n *yaml.Node, expanding map[*yaml.Node]bool) (*yaml.Node, error) {
	out := *n
	out.Alias, out.Anchor = nil, ""
	out.Content = make([]*yaml.Node, 0, len(n.Content))

	var merged []*yaml.Node
	have := map[string]bool{}

	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if isMergeKey(k) {
			src, err := mergeSources(v, expanding)
			if err != nil {
				return nil, err
			}
			merged = append(merged, src...)
			continue
		}
		rk, err := resolveNode(k, expanding)
		if err != nil {
			return nil, err
		}
		rv, err := resolveNode(v, expanding)
		if err != nil {
			return nil, err
		}
		if rk.Kind == yaml.ScalarNode {
			have[rk.Value] = true
		}
		out.Content = append(out.Content, rk, rv)
	}

	for _, m := range merged {
		for i := 0; i+1 < len(m.Content); i += 2 {
			k, v := m.Content[i], m.Content[i+1]
			if k.Kind != yaml.ScalarNode {
				// A non-scalar key cannot be compared against the explicit ones, so it
				// cannot be known to be overridden. Dropping it would hide content;
				// keeping it is the conservative half of the two.
				out.Content = append(out.Content, k, v)
				continue
			}
			if have[k.Value] {
				continue
			}
			have[k.Value] = true
			out.Content = append(out.Content, k, v)
		}
	}
	return &out, nil
}

// mergeSources resolves a merge key's value into the mappings it names, most significant
// first. The value is a mapping or an alias to one, or a sequence of those — but not an
// alias to a sequence, which yaml.v3 refuses even when the sequence holds mappings.
func mergeSources(v *yaml.Node, expanding map[*yaml.Node]bool) ([]*yaml.Node, error) {
	if v.Kind == yaml.AliasNode && v.Alias != nil && v.Alias.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("a merge key (%s) names something that is not a mapping, so the keys it "+
			"would contribute cannot be read", mergeKey)
	}
	r, err := resolveNode(v, expanding)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("a merge key (%s) has no value, so there is nothing to merge into the service", mergeKey)
	}
	switch r.Kind {
	case yaml.MappingNode:
		return []*yaml.Node{r}, nil
	case yaml.SequenceNode:
		out := make([]*yaml.Node, 0, len(r.Content))
		for _, e := range r.Content {
			if e.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("a merge key (%s) lists something that is not a mapping, so the keys "+
					"it would contribute cannot be read", mergeKey)
			}
			out = append(out, e)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("a merge key (%s) names something that is not a mapping, so the keys it "+
			"would contribute cannot be read", mergeKey)
	}
}
