package evidence

// composeblock.go reduces each compose service to a CANONICAL FORM — the shape a
// per-service baseline can be written against, and compared with.
//
// WHY A CANONICAL FORM AT ALL. Hop 3 pins the OS; composereview.go reads what runs
// inside it and reports, adjudicating nothing. The check that will adjudicate has to be
// byte-exact against a recorded baseline, and "byte-exact" cannot mean the raw bytes:
// re-indenting the compose file, moving a comment, or changing `'x'` to `"x"` are not
// changes to what runs, and a check that failed on them would be abandoned within a
// month. So the comparison needs a form that keeps every difference that matters and
// drops every one that does not. That form is what this file produces.
//
// THE BASELINE WILL STORE TEXT, NOT DIGESTS, and the canonicalizer is why it can. Both
// sides — the stored baseline and the manifest being checked — go through the SAME
// function at comparison time, so which version of gopkg.in/yaml.v3 is linked in cancels
// out entirely. Storing a precomputed digest instead would bake the library's formatting
// preferences into the file, and a minor-version bump that changed the default indent
// would invalidate every entry at once, refusing every provider for a dependency
// upgrade. Text also has the property digests lack: a reviewer can READ it, and a broker
// upgrade shows up as a legible diff instead of a changed hash. Same shape as
// MatchCompose, which already compares the gateway's own manifest as text.
//
// The digests here are therefore for REPORTING — a stable short name for a block, so a
// sweep across providers can say "these eleven run the same broker block" without
// printing eleven blocks. Nothing compares them.
//
// WHAT THE CANONICAL FORM DROPS, and why each is safe:
//
//   - Comments. Stated policy: they do not gate. They also cannot — they are the one
//     part of a compose file that changes nothing about what runs.
//   - Indentation and flow-vs-block style (`ports: [a]` versus a block sequence).
//   - Quoting style: `'secret'` and `"secret"` are the same string.
//
// What it KEEPS, deliberately:
//
//   - The scalar TAG. `privileged: true` and `privileged: "true"` do not collapse —
//     yaml.v3 re-quotes a `!!str` that would otherwise read as a bool, so the
//     distinction survives the round trip. Verified by a test, because it is the one
//     collapse that would matter.
//   - Key order. Reordering keys is a real edit to the file, and a baseline that
//     accepted any order would accept a diff a reviewer never saw. It is also the one
//     knob here that could reasonably go the other way: sorting would remove a source
//     of churn at the cost of a canonical text that no longer resembles the file.
//
// THE CANONICAL TEXT IS NOT DEPLOYABLE YAML. Dropping quote style means a value like
// "3000:3000" comes out unquoted, which a YAML parser would read back as a mapping, and
// the image hold-out replaces a real reference with a placeholder. It is a comparison
// form, not a template — anything that copies it into a compose file is misusing it. That
// costs nothing here, because nothing ever re-parses it.
//
// THE IMAGE HOLD-OUT IS BY IDENTITY, NOT BY KEY, and that distinction came from a live
// provider rather than from reasoning. Deleting the `image` key looks sufficient until a
// manifest copies the digest somewhere else in the same block — cn-20's broker services
// carry `IMAGE_DIGEST=sha256:…` in their environment — at which point the reduced form
// moves on every release and the hold-out protects nothing. stripImageIdentity has the
// full argument, including why its matching stops where it does.

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
)

// ServiceBlock is one compose service in canonical form.
//
// Two forms, not one, because the baseline will pin them differently. Everything about
// a service except its image is a deployment decision that should not move without
// review — volumes, namespaces, capabilities, ports. The image reference DOES move,
// every time the broker ships: three of cn-20's services run the same
// ghcr.io/0gfoundation/0g-serving-broker digest, and pinning it exactly would mean a
// gateway release per broker release. Splitting the image out lets a baseline say "this
// block exactly, and any digest-pinned image under our namespace" for those, and "this
// block exactly, and this exact digest" for everything else.
type ServiceBlock struct {
	// Name is the service key, as written.
	Name string
	// Canonical is the whole service body in canonical form, and Digest is sha256 over
	// it. It carries the real image reference, digest and all — this is the form that
	// describes the deployment as it stands. The name is NOT included: a baseline is
	// keyed by name, so folding it in would both duplicate that and make two identical
	// blocks under different names look different when they are not.
	Canonical string
	Digest    string
	// CanonicalNoImage is Canonical with the block's IMAGE IDENTITY erased, and
	// DigestNoImage is sha256 over that. This is the half a baseline pins for a service
	// whose image is allowed to move.
	//
	// Identity, not the `image` key. Removing the key alone was not enough on a real
	// manifest: cn-20's broker services copy the digest into an environment variable
	// (`IMAGE_DIGEST=sha256:…`), so the reduced form moved on every broker release
	// anyway and the hold-out bought nothing. stripImageIdentity erases the reference and
	// its digest wherever they appear in the block, and documents exactly how far that
	// goes — deliberately not far enough to touch a value that merely looks like a digest,
	// because erasing too much hides a real change while erasing too little only churns.
	CanonicalNoImage string
	DigestNoImage    string
	// ImageRef is the image reference as written, or "" when the service names none.
	ImageRef string
	// Err is set when this block has no canonical form (see canonicalizeNode). The block
	// is still returned, with empty forms, because "this service cannot be pinned" is
	// itself what a report needs to say.
	Err error
}

// Pinnable reports whether the block reduced to a canonical form.
//
// There is deliberately no standalone "canonicalize this whole compose file" entry
// point: blocks are built inside ReviewCompose, one per service, in the same loop that
// builds ComposeReview.Services — which is what makes the two index-aligned by
// construction rather than by a lookup that a duplicate service name could break. Read
// them from ComposeReview.Blocks.
func (b ServiceBlock) Pinnable() bool { return b.Err == nil }

// blockOf canonicalizes one service body, twice — with and without its image.
//
// It works on a CLONE, and that is not defensive habit: canonicalization clears comments
// and styles, and the image hold-out deletes a key. The caller's tree is also read by
// composereview.go, which walks the same nodes for its own rules — so a mutation here
// would silently change what the review sees, in a way no test of either file alone
// would catch. yaml.v3 has no Clone, hence cloneNode.
func blockOf(name string, body *yaml.Node) ServiceBlock {
	b := ServiceBlock{Name: name}
	// BEFORE the clone, and that order is load-bearing rather than tidy. yaml.v3 resolves
	// an alias by pointing Node.Alias at the anchored node, so a body that is anchored and
	// references itself — `a: &x {depends_on: [*x]}` — gives a node graph with a CYCLE, not
	// a tree. Cloning that first recursed forever and took the process down with an
	// unrecoverable stack overflow, on input a provider chooses freely (they hash their own
	// manifest, so the compose_hash gate is no obstacle at all). refuseIndirection walks
	// only Content, which stays acyclic, and hits the AliasNode before anything follows the
	// back-edge.
	//
	// It also still has the reason it was moved ahead of the mapping check: an alias body
	// is not a mapping either, and "the body is not a mapping" would send a reader looking
	// for a syntax error in a file that has none.
	if err := refuseIndirection(body); err != nil {
		b.Err = err
		return b
	}
	body = cloneNode(body)
	if body == nil || body.Kind != yaml.MappingNode {
		b.Err = fmt.Errorf("the service body is not a mapping, so it has no canonical form")
		return b
	}
	if img := mapValue(body, "image"); img != nil && img.Kind == yaml.ScalarNode {
		b.ImageRef = strings.TrimSpace(img.Value)
	}

	canonical, err := canonicalizeNode(body)
	if err != nil {
		b.Err = err
		return b
	}
	b.Canonical, b.Digest = canonical, digestOf(canonical)

	removeKey(body, "image")
	stripImageIdentity(body, b.ImageRef)
	noImage, err := canonicalizeNode(body)
	if err != nil {
		// Unreachable: the full form already succeeded and removing a key cannot
		// introduce an alias or a merge key. Reported rather than ignored, because a
		// half-populated block is worse than one that says it failed.
		b.Err = err
		b.Canonical, b.Digest = "", ""
		return b
	}
	b.CanonicalNoImage, b.DigestNoImage = noImage, digestOf(noImage)
	return b
}

// canonicalizeNode renders a node in the canonical form this file defines.
//
// It REFUSES a subtree containing a YAML alias or a merge key. Both mean the keys that
// actually apply to the service are somewhere else in the file, so yaml.Marshal would
// emit `*base` or `<<: *base` — a stable, reproducible digest of a pointer rather than of
// a service. A baseline built on that would pin the reference and not the content, which
// is the one failure this whole file exists to avoid. composereview.go blocks the same
// construct for the same reason.
func canonicalizeNode(n *yaml.Node) (string, error) {
	if err := refuseIndirection(n); err != nil {
		return "", err
	}
	normalize(n)
	out, err := yaml.Marshal(n)
	if err != nil {
		return "", fmt.Errorf("cannot render the service block: %w", err)
	}
	return string(out), nil
}

// normalize clears everything that is presentation rather than content. Style is not
// optional here: yaml.v3 records quoting and flow-versus-block on the node, so without
// clearing it `'secret'` and `"secret"` render differently and two identical deployments
// compare unequal. Anchor goes too — a defined anchor is formatting; anything that
// USES it is an alias, which refuseIndirection has already rejected.
func normalize(n *yaml.Node) {
	if n == nil {
		return
	}
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	n.Style = 0
	n.Anchor = ""
	for _, c := range n.Content {
		normalize(c)
	}
}

// refuseIndirection walks the subtree for an alias or a merge key.
func refuseIndirection(n *yaml.Node) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("the block references a YAML anchor (*%s), so its canonical form would "+
			"describe a pointer rather than the service", n.Value)
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "<<" {
				return fmt.Errorf("the block is merged from a YAML anchor, so the keys that apply to " +
					"it are not the ones it lists")
			}
		}
	}
	for _, c := range n.Content {
		if err := refuseIndirection(c); err != nil {
			return err
		}
	}
	return nil
}

// cloneNode deep-copies a node tree. Content is a slice of pointers, so a struct copy
// alone would leave the clone sharing children with the original — which is the failure
// mode that makes "I only mutate my own copy" untrue.
//
// Alias is DROPPED rather than followed, for two independent reasons. It is the only edge
// in a yaml.v3 node graph that can point backwards — an anchored node that references
// itself makes a cycle — so following it is what turned this function into an infinite
// recursion, and clearing it makes the walk structurally unable to loop regardless of
// what any future caller does first. And it would be wrong even without the cycle: the
// clone's Alias would point into a second copy of the tree rather than into the clone,
// so nothing could use it correctly anyway. Every alias is refused upstream
// (refuseIndirection), so no caller reaches here needing one.
func cloneNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	c.Alias = nil
	c.Content = nil
	if len(n.Content) > 0 {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, child := range n.Content {
			c.Content[i] = cloneNode(child)
		}
	}
	return &c
}

// imageHeldOut stands in for the image identity the hold-out erases.
//
// It is deliberately not a digest-shaped string and contains neither "sha256:" nor a run
// of hex, so a second pass over a canonical form finds nothing left to replace — which is
// what makes the reduction idempotent. It is also a valid YAML plain scalar ("<" is not a
// YAML indicator character), so it does not force the emitter into quoting that would
// depend on where the value sits.
const imageHeldOut = "<image-held-out>"

// stripImageIdentity erases this block's image identity from every scalar in the subtree,
// not just from the `image` key.
//
// FOUND ON A LIVE PROVIDER, not constructed. cn-20's broker services carry the digest
// twice — once as the image reference and once copied into an environment variable:
//
//	image: ghcr.io/0gfoundation/0g-serving-broker@sha256:ec5df834…
//	environment:
//	  - IMAGE_REPO=ghcr.io/0gfoundation/0g-serving-broker
//	  - IMAGE_DIGEST=sha256:ec5df834…
//
// Removing the KEY left the copy behind, so DigestNoImage moved on every broker release
// anyway — which destroys the one thing the hold-out exists for. Three of cn-20's
// services share that digest, so one release broke three baseline entries at once, and
// the whole point was to keep a broker release from forcing a gateway release.
//
// WHAT IT MATCHES, and why the bounds are where they are. Only two strings, both exact
// substrings of THIS block's own image reference: the full reference, then the digest
// ("sha256:…"). Longest first, or a full reference would come out as
// "<held-out>@<held-out>". The bare hex without its algorithm prefix is NOT matched, and
// that is a deliberate asymmetry: erasing too little costs churn, while erasing too much
// hides a real change — a modified block that compared equal to its baseline is a hole,
// and a 64-hex run is not distinctive enough to erase on sight. A manifest that copied
// only the bare hex would therefore still churn; that is the safe direction, and it shows
// up as a moving fingerprint rather than as a silent pass.
//
// Nothing else is touched, and two real values depend on that. cn-20's
// IMAGE_REPO=ghcr.io/0gfoundation/0g-serving-broker must SURVIVE: it does not move on a
// release, and it is worth pinning, since it says which registry and namespace the broker
// came from. And 0gm-sglang's `--revision 802e58f5…` is a MODEL revision that happens to
// be 40 hex; a looser matcher would erase it and stop the baseline noticing a model
// swap.
//
// Only applied when the reference carries a digest. compose.SplitImageRef is reused for
// that (a mis-split can only lose a digest, never invent one). A tag-only image is left
// exactly as it was: a tag string is short and easy to hit by accident, and such a
// service's DigestNoImage is not worth much anyway — an unpinned image means the
// fingerprint pins a name whose contents can change underneath it.
func stripImageIdentity(n *yaml.Node, imageRef string) {
	if imageRef == "" {
		return
	}
	_, _, digest := compose.SplitImageRef(imageRef)
	if digest == "" {
		return // tag-only, or unparseable: nothing specific enough to erase
	}
	replaceScalars(n, []string{imageRef, digest})
}

// replaceScalars rewrites every scalar value in the subtree, substituting each needle in
// the order given. Keys are scalars too and are covered by the same walk: a digest can
// appear on the key side of a mapping.
//
// It works on the node tree rather than on the rendered text so the emitter re-decides
// quoting for the value it is actually given — a substitution on rendered YAML could
// leave a value that no longer parses as what it claims to be.
func replaceScalars(n *yaml.Node, needles []string) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		for _, needle := range needles {
			if needle != "" {
				n.Value = strings.ReplaceAll(n.Value, needle, imageHeldOut)
			}
		}
	}
	for _, c := range n.Content {
		replaceScalars(c, needles)
	}
}

// removeKey deletes EVERY key/value pair with the given key from a mapping node.
//
// Every, not the first: a body that declares `image` twice would otherwise keep the
// second one in the reduced form, leaving exactly the reference the hold-out is there to
// remove. (mapValue and ImageRef still read the first, which matches how a compose
// runtime resolves a duplicate key — and composereview.go reports the duplicate, since
// which image runs is then ambiguous.)
func removeKey(n *yaml.Node, key string) {
	if n == nil || n.Kind != yaml.MappingNode {
		return
	}
	kept := make([]*yaml.Node, 0, len(n.Content))
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			continue
		}
		kept = append(kept, n.Content[i], n.Content[i+1])
	}
	// A mapping node always has an even Content, but if a future parser hands over an odd
	// one, carrying the stray element is better than silently dropping a value.
	if len(n.Content)%2 == 1 {
		kept = append(kept, n.Content[len(n.Content)-1])
	}
	n.Content = kept
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// CanonicalizeServiceBlock is the entry point a BASELINE side needs: it takes one
// service body as YAML text and returns the same canonical form ServiceBlocks produces.
//
// It exists so the two sides of the eventual comparison cannot drift. A baseline stored
// as text is only meaningful if the stored text and the observed text are reduced by one
// function; two functions would be two definitions of "the same block".
func CanonicalizeServiceBlock(blockText []byte) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(blockText, &root); err != nil {
		return "", fmt.Errorf("service block does not parse as YAML: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return "", fmt.Errorf("service block is an empty document")
	}
	return canonicalizeNode(root.Content[0])
}
