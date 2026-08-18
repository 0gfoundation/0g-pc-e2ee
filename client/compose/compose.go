// Package compose reads the container list out of a docker-compose document.
//
// It exists for one caller shape: something that already holds an AUTHENTICATED
// compose text — the `docker_compose_file` embedded in an app-compose whose
// SHA-256 equals the compose_hash a verified quote commits to (see
// client/evidence) — and needs to say which images that text runs. The gateway's
// /v1/gateway/identity endpoint is the first such caller.
//
// What this package is NOT is a verification step. Everything it returns is a
// re-reading of bytes that were already pinned; parsing them differently cannot
// make a deployment more or less trustworthy, it can only make the *display* of
// it wrong. Nothing here should ever become an input to a trust decision — the
// comparison that carries weight is byte-for-byte over the whole text (a released
// manifest versus the deployed one), never a field-by-field comparison of what
// this extracts.
//
// It reads only `services.<name>.image`, and deliberately nothing else. Ports,
// volumes, environment and the rest are all covered by the same hash, so a UI
// that wanted them could have them — but each field decoded here is a field
// someone could later mistake for a checked one, and the container images are
// what the verification sidebar actually shows.
package compose

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Service is one entry of the compose file's `services` mapping.
type Service struct {
	// Name is the service key, e.g. "gateway". Compose names the container by it.
	Name string
	// Ref is the image reference exactly as written, e.g.
	// "prom/prometheus:v2.55.1@sha256:2659…". Kept verbatim so a caller that wants
	// to show what the file says, rather than what this package made of it, can.
	Ref string
	// Image is Ref's repository: no tag, no digest. Empty when the service names no
	// image at all (a `build:`-only service), which is reported rather than dropped.
	Image string
	// Tag is Ref's tag, or "" when it carries none. A deployment pinned by digest
	// usually still carries one, and it is the human-readable half.
	Tag string
	// Digest is Ref's "sha256:…" digest, or "" when the reference is not pinned.
	// An unpinned image in an attested deployment is a real finding — the compose
	// hash then commits to a *name*, whose contents can change — so callers must
	// render its absence rather than hide it.
	Digest string
}

// maxDocBytes bounds the document handed to the YAML parser. The compose text
// arrives inside an app-compose that client/evidence already caps (4 MiB); this
// is the narrower bound for the compose text itself, which is a page of YAML.
const maxDocBytes = 1 << 20

// ErrNoServices reports a document with no `services` mapping. It is a distinct
// error because it is the shape a caller most likely wants to report specially:
// the bytes parsed as YAML but are not a compose file.
var ErrNoServices = errors.New("compose: document has no services mapping")

// ParseServices returns the document's services **in file order**.
//
// Order is part of the answer, not an accident of iteration: the compose file
// lists containers in an order its author chose, and a caller rendering them has
// nothing better to sort by. That is why this walks the YAML node tree rather
// than unmarshalling into a map, which Go would hand back in a random order on
// every call — and a list that reshuffles itself between two fetches of the same
// unchanged deployment reads as the deployment having changed.
func ParseServices(doc []byte) ([]Service, error) {
	if len(doc) > maxDocBytes {
		return nil, fmt.Errorf("compose: document is larger than %d bytes", maxDocBytes)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("compose: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, ErrNoServices
	}
	services := mappingValue(root.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, ErrNoServices
	}
	// A mapping node's Content alternates key, value, key, value…
	out := make([]Service, 0, len(services.Content)/2)
	for i := 0; i+1 < len(services.Content); i += 2 {
		name := services.Content[i].Value
		if name == "" {
			continue
		}
		svc := Service{Name: name}
		if body := services.Content[i+1]; body.Kind == yaml.MappingNode {
			if img := mappingValue(body, "image"); img != nil && img.Kind == yaml.ScalarNode {
				svc.Ref = strings.TrimSpace(img.Value)
				svc.Image, svc.Tag, svc.Digest = SplitImageRef(svc.Ref)
			}
		}
		out = append(out, svc)
	}
	if len(out) == 0 {
		return nil, ErrNoServices
	}
	return out, nil
}

// mappingValue returns the value node for key in a mapping node, or nil.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// SplitImageRef splits a Docker image reference into repository, tag and digest.
//
// The parse is the reference grammar's, not a naive split: the digest is taken
// from the last "@", and the tag only from a ":" that comes AFTER the last "/",
// so a registry with a port ("localhost:5000/app") does not have its port read as
// a tag. Anything this cannot make sense of comes back as a bare repository with
// no tag and no digest — this is display plumbing, and a reference it cannot
// split is better shown whole (Service.Ref) than split wrongly.
func SplitImageRef(ref string) (image, tag, digest string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", ""
	}
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		image, digest = ref[:at], ref[at+1:]
	} else {
		image = ref
	}
	// The tag separator is a ":" in the final path segment. A ":" before the last
	// "/" belongs to a registry host:port.
	if colon := strings.LastIndex(image, ":"); colon > strings.LastIndex(image, "/") {
		image, tag = image[:colon], image[colon+1:]
	}
	return image, tag, digest
}
