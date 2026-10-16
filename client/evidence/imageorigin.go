package evidence

// imageorigin.go decides whether an image is one we published. It is shared by the
// gateway's identity endpoints and by the provider compose review (evidence/compose).

import "strings"

// ImageOrigin classifies an image reference by the namespace it was pushed to.
//
// This is REPORTING, not adjudication, and the distinction is the whole reason it is
// a separate field from any Finding. "Under our namespace" is a real property when
// the reference is digest-pinned — a pinned pull resolves scoped to that repository,
// so the bytes really are something that was pushed there — but it is not the
// property a baseline wants: it cannot distinguish the current official build from an
// official build with a year-old CVE, and every third-party image in a manifest
// (mysql, an exporter, a model server) is third-party for a legitimate reason. So the
// origin column tells a reviewer which lines they can resolve by asking us and which
// need an upstream answer, and nothing more.
type ImageOrigin int

const (
	// OriginNone: the service names no image (see Finding for the "build:" case).
	OriginNone ImageOrigin = iota
	// OriginFirstParty: our namespace on a registry we publish through.
	OriginFirstParty
	// OriginThirdParty: anything else, including an unqualified Docker Hub library
	// image.
	OriginThirdParty
	// OriginForeignRegistry: OUR namespace on a registry that is not ours. It is its own
	// state because it is neither answer: a pull-through mirror is a legitimate reason to
	// see it, and so is an image named to look like ours. Either way we cannot answer for
	// the contents, so calling it first-party would be false — and the namespace part of
	// the digest-pinning argument only holds when the registry is one we control.
	OriginForeignRegistry
)

func (o ImageOrigin) String() string {
	switch o {
	case OriginFirstParty:
		return "first-party"
	case OriginThirdParty:
		return "third-party"
	case OriginForeignRegistry:
		return "our-name/not-ours"
	default:
		return "no image"
	}
}

// FirstPartyNamespace is the organisation whose builds we can answer for.
const FirstPartyNamespace = "0gfoundation"

// firstPartyRegistries are the registries that namespace means anything on: the ones we
// PUBLISH THROUGH, which is ghcr.io and nothing else (.github/workflows/release.yml and
// docker.yml both set REGISTRY: ghcr.io, and no workflow here pushes anywhere else).
//
// Docker Hub used to be in this set — "docker.io", its "index.docker.io" spelling, and
// the implicit host of an unqualified reference — on the argument that a Hub namespace is
// globally unique, so "0gfoundation/x" there names one specific account rather than a
// string anyone can choose. The argument is sound and the conclusion did not follow: a
// Hub namespace names one account, but nothing in this repository establishes that the
// account is OURS. We never push there, so if that name is unregistered or held by
// someone else, "0gfoundation/broker" is a path a stranger can publish under and this
// function would have called it ours.
//
// That was survivable while the answer only reached a human-read report column. It is
// not now: it labels a container list taken from a PROVIDER's compose text, which the
// provider writes, so an unqualified reference would have been an unregistered
// namespace away from a "published by 0G" stamp on someone else's image. Registering
// the Hub name would not fix it either — the fix is that this set means "where we
// publish", and a registry we do not publish through cannot vouch for a namespace.
//
// On any other host the namespace is just a path segment the manifest's author picked,
// which is what made "evil.example.com/0gfoundation/broker" read as first-party. Our
// namespace off ghcr.io is now uniformly OriginForeignRegistry — the state that exists
// for "reads as ours at a glance, and we cannot answer for it".
var firstPartyRegistries = map[string]bool{"ghcr.io": true}

// ClassifyImageOrigin reads the registry AND the namespace out of an image repository.
// See ImageOrigin for why the answer is a column in a report and not a rule.
//
// Both halves, because the namespace alone means nothing: anyone can push
// "0gfoundation/broker" to a registry they control, and a classifier that read the path
// and ignored the host called that first-party — i.e. said "ask us and we can resolve
// this" about an image we never published.
//
// Exported because it is the ONE place this repository decides whether an image is
// ours, and both of the gateway's identity endpoints label their container lists with
// it (`client/cmd/gateway`).
//
// It takes a REPOSITORY — no tag, no digest — which is what compose.Service.Image and
// ReviewedService.Image both hold; a caller starting from a raw reference should split
// it with compose.SplitImageRef first. Today a full reference happens to classify the
// same way, since only the host and the FIRST path segment are read and a tag or digest
// rides on the last one, but that is a coincidence of this implementation and not a
// promise: the parameter is a repository, and a caller relying on the coincidence would
// be relying on where the split lands.
func ClassifyImageOrigin(image string) ImageOrigin {
	registry, repo := SplitRegistry(strings.TrimSpace(image))
	if repo == "" {
		return OriginNone
	}
	ns, _, hasNamespace := strings.Cut(repo, "/")
	if !hasNamespace || !strings.EqualFold(ns, FirstPartyNamespace) {
		return OriginThirdParty
	}
	if firstPartyRegistries[strings.ToLower(registry)] {
		return OriginFirstParty
	}
	return OriginForeignRegistry
}

// SplitRegistry separates an image reference's registry host from its repository path,
// returning "" for the implicit Docker Hub host.
//
// The first segment is a host only when it LOOKS like one — it contains a "." or a ":",
// or is exactly "localhost" — which is the rule the reference grammar uses. Without it
// "0gfoundation/broker" would have "0gfoundation" read as a registry, and
// "mysql" would have no repository left at all.
func SplitRegistry(image string) (registry, repo string) {
	first, rest, hasSlash := strings.Cut(image, "/")
	if hasSlash && (strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost") {
		return first, rest
	}
	return "", image
}
