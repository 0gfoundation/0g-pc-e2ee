package evidence

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// blocksOf runs the REAL path — ReviewCompose, hash gate included — over a compose text
// and indexes the blocks by name. Going through the production entry point rather than a
// test-only one is the point: there is no standalone canonicalize-a-whole-file function
// to test, because blocks are built inside the review so they stay aligned with its
// service list.
func blocksOf(t *testing.T, doc string) map[string]ServiceBlock {
	t.Helper()
	r := reviewOf(t, manifest(doc))
	out := make(map[string]ServiceBlock, len(r.Blocks))
	for _, b := range r.Blocks {
		out[b.Name] = b
	}
	return out
}

// oneBlock is the shape most cases want: a single service named "svc".
func oneBlock(t *testing.T, body string) ServiceBlock {
	t.Helper()
	b := blocksOf(t, "services:\n  svc:\n"+body)["svc"]
	if b.Err != nil {
		t.Fatalf("block has no canonical form: %v", b.Err)
	}
	return b
}

// --- the equivalences the design claims -----------------------------------------
//
// This is the load-bearing test in the file. The canonical form exists to make a
// byte-exact baseline survivable, and it is only worth having if it drops EXACTLY the
// differences that change nothing about what runs. Each case below is one such
// difference, written the way a broker maintainer would actually write it — so if a
// future change to the canonicalizer starts letting one of them through, the failure
// names the real-world edit that would have broken every provider's baseline.

func TestServiceBlock_DropsPresentationOnly(t *testing.T) {
	const base = `    image: grafana/grafana-oss:11.4.0
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: 'secret'
    restart: always
`
	want := oneBlock(t, base)

	for _, tc := range []struct{ name, body string }{
		{
			"deeper indentation",
			"        image: grafana/grafana-oss:11.4.0\n" +
				"        ports:\n            - \"3000:3000\"\n" +
				"        environment:\n            GF_SECURITY_ADMIN_PASSWORD: 'secret'\n" +
				"        restart: always\n",
		},
		{
			"comments added, moved and removed",
			"    # the dashboard\n    image: grafana/grafana-oss:11.4.0 # pinned by ops\n" +
				"    ports:\n      - \"3000:3000\"     # host:container\n" +
				"    environment:\n      GF_SECURITY_ADMIN_PASSWORD: 'secret'\n" +
				"    restart: always\n    # end\n",
		},
		{
			"double quotes instead of single",
			"    image: grafana/grafana-oss:11.4.0\n" +
				"    ports:\n      - \"3000:3000\"\n" +
				"    environment:\n      GF_SECURITY_ADMIN_PASSWORD: \"secret\"\n" +
				"    restart: always\n",
		},
		{
			"flow style instead of block style",
			"    image: grafana/grafana-oss:11.4.0\n" +
				"    ports: [\"3000:3000\"]\n" +
				"    environment: {GF_SECURITY_ADMIN_PASSWORD: secret}\n" +
				"    restart: always\n",
		},
		{
			"blank lines between keys",
			"    image: grafana/grafana-oss:11.4.0\n\n" +
				"    ports:\n      - \"3000:3000\"\n\n" +
				"    environment:\n      GF_SECURITY_ADMIN_PASSWORD: 'secret'\n\n" +
				"    restart: always\n",
		},
		{
			"trailing whitespace",
			"    image: grafana/grafana-oss:11.4.0   \n" +
				"    ports:\n      - \"3000:3000\"  \n" +
				"    environment:\n      GF_SECURITY_ADMIN_PASSWORD: 'secret'\t\n" +
				"    restart: always  \n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := oneBlock(t, tc.body)
			if got.Canonical != want.Canonical {
				t.Fatalf("presentation-only change moved the canonical form:\n got:\n%s\nwant:\n%s",
					got.Canonical, want.Canonical)
			}
			if got.Digest != want.Digest {
				t.Fatalf("digest moved: %s != %s", got.Digest, want.Digest)
			}
		})
	}
}

// The other half: a change to what actually runs MUST move the canonical form. Without
// these, "drops presentation" could be satisfied by a canonicalizer that drops
// everything.
func TestServiceBlock_KeepsEverythingThatRuns(t *testing.T) {
	const base = `    image: grafana/grafana-oss:11.4.0
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: 'secret'
    restart: always
`
	want := oneBlock(t, base)

	for _, tc := range []struct{ name, body string }{
		{
			"image tag changed",
			strings.Replace(base, "11.4.0", "11.5.0", 1),
		},
		{
			"a value changed",
			strings.Replace(base, "'secret'", "'hunter2'", 1),
		},
		{
			"a port added",
			strings.Replace(base, "      - \"3000:3000\"\n", "      - \"3000:3000\"\n      - \"3001:3001\"\n", 1),
		},
		{
			"a key added",
			base + "    privileged: true\n",
		},
		{
			"a key removed",
			strings.Replace(base, "    restart: always\n", "", 1),
		},
		{
			// Reordering is a real edit to the file. A baseline that accepted any order
			// would accept a diff nobody reviewed — see the file header, which also notes
			// this is the one knob that could reasonably go the other way.
			"keys reordered",
			"    restart: always\n" +
				"    environment:\n      GF_SECURITY_ADMIN_PASSWORD: 'secret'\n" +
				"    ports:\n      - \"3000:3000\"\n" +
				"    image: grafana/grafana-oss:11.4.0\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := oneBlock(t, tc.body); got.Canonical == want.Canonical {
				t.Fatalf("a real change did NOT move the canonical form:\n%s", got.Canonical)
			}
		})
	}
}

// The one collapse that would matter. Dropping quote style is what makes `'x'` and `"x"`
// equal, and the obvious worry is that it also makes `true` and `"true"` equal — which
// would let a string sneak into a boolean field, exactly where composereview.go's
// wrong-shape rules live. yaml.v3 re-quotes a !!str that would otherwise read as a bool,
// so it does not; asserted here because the whole quote-normalization decision rests on
// it and it is a property of the library, not of our code.
func TestServiceBlock_DoesNotCollapseScalarTags(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"bool vs string", "    privileged: true\n", "    privileged: \"true\"\n"},
		{"int vs string", "    shm_size: 64\n", "    shm_size: \"64\"\n"},
		{"null vs string", "    command: ~\n", "    command: \"~\"\n"},
		{"float vs string", "    cpus: 1.5\n", "    cpus: \"1.5\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := oneBlock(t, tc.a), oneBlock(t, tc.b)
			if a.Canonical == b.Canonical {
				t.Fatalf("%s collapsed to the same canonical form:\n%s", tc.name, a.Canonical)
			}
		})
	}
}

// --- the image hold-out ---------------------------------------------------------

// The split exists so a baseline can pin a block exactly while letting the image move —
// which is what keeps a broker release from forcing a gateway release. So the property
// to assert is precisely that: changing ONLY the image leaves DigestNoImage alone, and
// changing anything else moves both.
func TestServiceBlock_ImageHoldOut(t *testing.T) {
	const body = `    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:%s
    volumes:
      - zg-tee:/var/lib/zg-tee
    restart: always
`
	a := oneBlock(t, fmt.Sprintf(body, strings.Repeat("a", 64)))
	b := oneBlock(t, fmt.Sprintf(body, strings.Repeat("b", 64)))

	if a.DigestNoImage != b.DigestNoImage {
		t.Fatalf("a new broker digest moved DigestNoImage:\n%s\nvs\n%s", a.CanonicalNoImage, b.CanonicalNoImage)
	}
	if a.Digest == b.Digest {
		t.Fatal("a new broker digest did not move the full Digest")
	}
	if !strings.Contains(a.ImageRef, strings.Repeat("a", 64)) {
		t.Fatalf("ImageRef = %q, want the reference as written", a.ImageRef)
	}
	if strings.Contains(a.CanonicalNoImage, "image:") {
		t.Fatalf("CanonicalNoImage still carries the image key:\n%s", a.CanonicalNoImage)
	}
	// Everything else has to survive the hold-out, or the reduced form pins nothing.
	for _, want := range []string{"volumes", "zg-tee:/var/lib/zg-tee", "restart", "always"} {
		if !strings.Contains(a.CanonicalNoImage, want) {
			t.Errorf("CanonicalNoImage lost %q:\n%s", want, a.CanonicalNoImage)
		}
	}

	// A change OUTSIDE the image must move both digests — otherwise the hold-out is
	// dropping more than the image.
	c := oneBlock(t, strings.Replace(fmt.Sprintf(body, strings.Repeat("a", 64)),
		"    restart: always\n", "    privileged: true\n", 1))
	if c.DigestNoImage == a.DigestNoImage || c.Digest == a.Digest {
		t.Fatal("a change outside the image did not move both digests")
	}

	// A service with no image at all still reduces, and the two forms then agree.
	noImg := oneBlock(t, "    restart: always\n")
	if noImg.ImageRef != "" {
		t.Fatalf("ImageRef = %q for a service with no image", noImg.ImageRef)
	}
	if noImg.Digest != noImg.DigestNoImage {
		t.Fatal("with no image to hold out, the two forms must be identical")
	}
}

// --- indirection is refused, not digested ---------------------------------------

// A block whose keys live behind an anchor would marshal to `*base` — a perfectly
// stable digest of a pointer. Pinning that pins the reference and not the content, which
// is the one thing this file exists to prevent, so it is refused rather than reduced.
func TestServiceBlock_RefusesIndirection(t *testing.T) {
	for _, tc := range []struct{ name, doc, says string }{
		{
			"merge key",
			"x-base: &base\n  privileged: true\nservices:\n  svc:\n    <<: *base\n    image: mysql:8\n",
			"merged from a YAML anchor",
		},
		{
			"whole body is an alias",
			"x-base: &base\n  privileged: true\nservices:\n  svc: *base\n",
			"references a YAML anchor",
		},
		{
			"a nested value is an alias",
			"x-vols: &vols\n  - /etc:/host-etc\nservices:\n  svc:\n    image: mysql:8\n    volumes: *vols\n",
			"references a YAML anchor",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := blocksOf(t, tc.doc)["svc"]
			if b.Err == nil {
				t.Fatalf("indirection was reduced to a canonical form:\n%s", b.Canonical)
			}
			if b.Pinnable() {
				t.Fatal("Pinnable() is true for a block with no canonical form")
			}
			if !strings.Contains(b.Err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to mention %q", b.Err, tc.says)
			}
			// Nothing half-populated: a digest of a partially-read block is worse than none.
			if b.Canonical != "" || b.Digest != "" || b.CanonicalNoImage != "" || b.DigestNoImage != "" {
				t.Fatalf("a refused block still carries forms: %+v", b)
			}
		})
	}
}

func TestServiceBlock_BodyThatIsNotAMapping(t *testing.T) {
	b := blocksOf(t, "services:\n  svc: notamapping\n")["svc"]
	if b.Err == nil {
		t.Fatalf("a scalar body was reduced: %q", b.Canonical)
	}
	if !strings.Contains(b.Err.Error(), "not a mapping") {
		t.Fatalf("err = %v", b.Err)
	}
}

// --- shape of the result --------------------------------------------------------

func TestServiceBlocks_FileOrderAndDigests(t *testing.T) {
	pin := "@sha256:" + strings.Repeat("c", 64)
	doc := fmt.Sprintf(`services:
  broker-ingress:
    image: dstacktee/dstack-ingress:2.2%s
  0gm-sglang:
    image: lmsysorg/sglang%s
    ipc: host
  mysql:
    image: mysql:8.0%s
`, pin, pin, pin)

	got := reviewOf(t, manifest(doc)).Blocks
	var names []string
	for _, b := range got {
		names = append(names, b.Name)
	}
	// File order, not sorted and not map order — the operator chose it, and a list that
	// reshuffles between two reads of one unchanged deployment reads as a change.
	if want := "broker-ingress,0gm-sglang,mysql"; strings.Join(names, ",") != want {
		t.Fatalf("names = %s, want %s", strings.Join(names, ","), want)
	}
	for _, b := range got {
		if !b.Pinnable() {
			t.Fatalf("%s: %v", b.Name, b.Err)
		}
		if b.Digest != digestOf(b.Canonical) || b.DigestNoImage != digestOf(b.CanonicalNoImage) {
			t.Fatalf("%s: digest does not match its own canonical text", b.Name)
		}
		if want := fmt.Sprintf("%x", sha256.Sum256([]byte(b.Canonical))); b.Digest != want {
			t.Fatalf("%s: Digest = %s, want sha256 over Canonical = %s", b.Name, b.Digest, want)
		}
	}
	// The name is deliberately NOT folded into the digest: a baseline is keyed by name,
	// so two identical blocks under different names are identical blocks.
	same := blocksOf(t, "services:\n  a:\n    image: mysql:8.0\n  b:\n    image: mysql:8.0\n")
	if same["a"].Digest != same["b"].Digest {
		t.Fatal("two identical bodies produced different digests, so the name leaked in")
	}
}

// Two runs over one unchanged text must produce identical output. The canonicalizer
// mutates the node tree it walks (clearing comments and styles, removing a key), so the
// risk is real rather than theoretical: an implementation that shared state between the
// two forms, or between calls, would show up here.
func TestServiceBlocks_Deterministic(t *testing.T) {
	doc := "services:\n  a:\n    image: mysql:8.0\n    # a comment\n    restart: always\n" +
		"  b:\n    image: 'redis:7'\n    ports: [\"6379:6379\"]\n"
	first := reviewOf(t, manifest(doc)).Blocks
	for i := 0; i < 8; i++ {
		again := reviewOf(t, manifest(doc)).Blocks
		if len(again) != len(first) {
			t.Fatalf("run %d returned %d blocks, want %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d block %s differs:\n%+v\nvs\n%+v", i, first[j].Name, again[j], first[j])
			}
		}
	}
	// Comments must be gone from the canonical text, not merely ignored in the digest.
	for _, b := range first {
		if strings.Contains(b.Canonical, "#") {
			t.Fatalf("%s: canonical form still carries a comment:\n%s", b.Name, b.Canonical)
		}
	}
}

// Unusable compose text is covered by composereview_test.go's
// TestReviewCompose_UnreadableComposeTextIsAFinding, and covered there on purpose: the
// bytes are authenticated, so "not readable YAML" is a fact about the deployment and
// belongs in the report as a finding rather than surfacing here as an error.

// --- the two consumers of one node tree -----------------------------------------

// The block builder clears comments and styles and deletes the image key. It runs on the
// same node tree composereview.go walks for its own rules, so if it mutated the caller's
// nodes the review would silently see a different manifest — and no test of either file
// alone would notice, because each would still pass. Asserted from the review's side:
// every rule that reads the tree AFTER blocks are built must still fire.
func TestServiceBlocks_DoNotDisturbTheReview(t *testing.T) {
	pinned := "ghcr.io/0gfoundation/broker@sha256:" + strings.Repeat("a", 64)
	doc := fmt.Sprintf(`services:
  broker:
    image: %s   # pinned by ops
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`, pinned)
	r := reviewOf(t, manifest(doc))

	// The review's image reading survives — the hold-out deleted the key on a clone.
	if len(r.Services) != 1 {
		t.Fatalf("services = %+v", r.Services)
	}
	if got := r.Services[0]; got.Ref != pinned || !got.Pinned() || got.Origin != OriginFirstParty {
		t.Fatalf("the review lost the image after blocks were built: %+v", got)
	}
	// And the rules that walk the same nodes still fire.
	requireFinding(t, r, SeverityBlocking, "broker", "privileged")
	requireFinding(t, r, SeverityBlocking, "broker", "volumes")

	// The blocks are there, aligned with Services, and carry the image the review saw.
	if len(r.Blocks) != len(r.Services) {
		t.Fatalf("Blocks (%d) and Services (%d) are not aligned", len(r.Blocks), len(r.Services))
	}
	b := r.Blocks[0]
	if b.Name != "broker" || b.ImageRef != pinned || !b.Pinnable() {
		t.Fatalf("block = %+v", b)
	}
	if strings.Contains(b.Canonical, "#") {
		t.Fatalf("canonical form carries the comment:\n%s", b.Canonical)
	}

	// The alignment claim is by construction, so it has to hold for the shapes that
	// bypass the normal path too: a body that is not a mapping still appends to both.
	r2 := reviewOf(t, manifest("services:\n  a:\n    image: mysql:8.0\n  b: notamapping\n"))
	if len(r2.Blocks) != len(r2.Services) || len(r2.Services) != 2 {
		t.Fatalf("alignment broken on an unreadable body: %d blocks, %d services", len(r2.Blocks), len(r2.Services))
	}
	for i, s := range r2.Services {
		if r2.Blocks[i].Name != s.Name {
			t.Fatalf("index %d: block %q vs service %q", i, r2.Blocks[i].Name, s.Name)
		}
	}
	if r2.Blocks[1].Pinnable() {
		t.Fatal("an unreadable body produced a pinnable block")
	}
}

// The reason alignment is by construction rather than by a name lookup. A compose file
// with the same service name twice is malformed, but yaml.v3 keeps both pairs, so a
// lookup keyed by name would silently return one block for two services — and the one
// it returned would describe the wrong container half the time. Positional alignment has
// no such failure.
func TestServiceBlocks_DuplicateServiceNames(t *testing.T) {
	r := reviewOf(t, manifest("services:\n  a:\n    image: mysql:8.0\n  a:\n    image: redis:7\n"))
	if len(r.Services) != 2 || len(r.Blocks) != 2 {
		t.Fatalf("services=%d blocks=%d, want 2 and 2", len(r.Services), len(r.Blocks))
	}
	for i, want := range []string{"mysql:8.0", "redis:7"} {
		if r.Services[i].Ref != want || r.Blocks[i].ImageRef != want {
			t.Fatalf("index %d: service ref %q, block image %q, want %q",
				i, r.Services[i].Ref, r.Blocks[i].ImageRef, want)
		}
	}
	if r.Blocks[0].Digest == r.Blocks[1].Digest {
		t.Fatal("two different bodies under one name produced the same digest")
	}
}

// --- the baseline side ----------------------------------------------------------

// The eventual comparison reduces BOTH sides with one function. That is what makes the
// stored baseline immune to the linked yaml.v3 version: whatever the library's
// formatting preferences are, they apply equally to the stored text and to the observed
// text. So the property to assert is that a block round-tripped through the baseline
// entry point lands on the same canonical form as the observed block — including when
// the stored text is formatted differently from the manifest it was taken from.
func TestCanonicalizeServiceBlock_AgreesWithTheObservedSide(t *testing.T) {
	observed := oneBlock(t, "    image: mysql:8.0\n    volumes:\n      - db:/var/lib/mysql\n    restart: always\n")

	// A baseline author would store the canonical text. Reducing it again must be a
	// no-op, or the comparison is not stable under its own output.
	again, err := CanonicalizeServiceBlock([]byte(observed.Canonical))
	if err != nil {
		t.Fatalf("CanonicalizeServiceBlock: %v", err)
	}
	if again != observed.Canonical {
		t.Fatalf("canonicalization is not idempotent:\n%s\nvs\n%s", again, observed.Canonical)
	}

	// And a baseline stored in some OTHER formatting — hand-edited, re-indented, with a
	// note added — must still reduce to the same thing.
	stored := "# reviewed 2026-08: db volume only\nimage: \"mysql:8.0\"\nvolumes: [db:/var/lib/mysql]\nrestart: always\n"
	got, err := CanonicalizeServiceBlock([]byte(stored))
	if err != nil {
		t.Fatalf("CanonicalizeServiceBlock: %v", err)
	}
	if got != observed.Canonical {
		t.Fatalf("a differently-formatted baseline did not reduce to the observed form:\n%s\nvs\n%s",
			got, observed.Canonical)
	}
}

func TestCanonicalizeServiceBlock_RefusesUnusable(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"not yaml", "image: [unclosed\n"},
		{"empty", ""},
		{"alias", "volumes: *vols\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CanonicalizeServiceBlock([]byte(tc.text)); err == nil {
				t.Fatal("unusable baseline text was accepted")
			}
		})
	}
}
