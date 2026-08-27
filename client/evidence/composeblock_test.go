package evidence

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
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

// requireBlock looks a block up by name and fails when it is ABSENT.
//
// The plain map index would hand back a zero ServiceBlock instead — Err nil, Canonical
// "" — which reads exactly like "this block reduced cleanly and is empty". A test written
// against that would pass while asserting nothing; this happened once already, on a
// fixture whose compose text turned out not to parse at all.
func requireBlock(t *testing.T, doc, name string) ServiceBlock {
	t.Helper()
	blocks := blocksOf(t, doc)
	b, ok := blocks[name]
	if !ok {
		names := make([]string, 0, len(blocks))
		for n := range blocks {
			names = append(names, n)
		}
		t.Fatalf("no block named %q — the compose text produced %v", name, names)
	}
	return b
}

// oneBlock is the shape most cases want: a single service named "svc", which must have
// reduced cleanly.
func oneBlock(t *testing.T, body string) ServiceBlock {
	t.Helper()
	b := oneBlock2(t, body)
	if b.Err != nil {
		t.Fatalf("block has no canonical form: %v", b.Err)
	}
	return b
}

// oneBlock2 is oneBlock without the success requirement, for cases whose subject IS the
// refusal.
func oneBlock2(t *testing.T, body string) ServiceBlock {
	t.Helper()
	return requireBlock(t, "services:\n  svc:\n"+body, "svc")
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

	// A service with no image at all still reduces, and the two forms then agree — the
	// hold-out has nothing to remove and must not invent a placeholder.
	noImg := oneBlock(t, "    restart: always\n    environment:\n      - SOME=sha256:deadbeef\n")
	if noImg.ImageRef != "" {
		t.Fatalf("ImageRef = %q for a service with no image", noImg.ImageRef)
	}
	if noImg.Digest != noImg.DigestNoImage || noImg.Canonical != noImg.CanonicalNoImage {
		t.Fatalf("with no image to hold out, the two forms must be identical:\n%s\nvs\n%s",
			noImg.Canonical, noImg.CanonicalNoImage)
	}
	if strings.Contains(noImg.CanonicalNoImage, imageHeldOut) {
		t.Fatalf("a placeholder appeared with no image to hold out:\n%s", noImg.CanonicalNoImage)
	}
}

// --- the hold-out is by identity, not by key ------------------------------------

// cn20BrokerService is the real shape from provider
// 0x4870CbC4D07d6Ac2EE5aA865588e5985FE77a4E9: the digest appears twice, once as the
// image reference and once copied into an environment variable. Verbatim rather than
// simplified, because the whole finding is that a plausible-looking manifest does this
// and a key-based hold-out silently fails on it.
const cn20BrokerService = `    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:%[1]s
    environment:
      - IMAGE_REPO=ghcr.io/0gfoundation/0g-serving-broker
      - IMAGE_DIGEST=sha256:%[1]s
    volumes:
      - zg-tee:/var/lib/zg-tee
      - ./logs/broker:/var/log/inference
    restart: always
`

const (
	cn20Digest = "ec5df8347f91c3b28a6638db4e24dba343799c0a3a7e2cdd44845a3a27f2e734"
	nextDigest = "1111111111111111111111111111111111111111111111111111111111111111"
)

// The core assertion of the identity hold-out. Deleting the `image` key left the copy in
// `environment` behind, so DigestNoImage moved on every broker release and the hold-out
// bought nothing — which is the coupling ("a broker release forces a gateway release")
// this split exists to prevent.
func TestServiceBlock_HoldsOutDigestCopiedIntoEnvironment(t *testing.T) {
	a := oneBlock(t, fmt.Sprintf(cn20BrokerService, cn20Digest))
	b := oneBlock(t, fmt.Sprintf(cn20BrokerService, nextDigest))

	if a.DigestNoImage != b.DigestNoImage {
		t.Fatalf("a digest bump moved DigestNoImage:\n%s\nvs\n%s", a.CanonicalNoImage, b.CanonicalNoImage)
	}
	if a.Digest == b.Digest {
		t.Fatal("a digest bump did not move the full Digest")
	}
	// Nothing digest-shaped may survive in the reduced form, in any spelling.
	for _, leak := range []string{cn20Digest, "sha256:" + cn20Digest, a.ImageRef} {
		if strings.Contains(a.CanonicalNoImage, leak) {
			t.Fatalf("CanonicalNoImage still carries %q:\n%s", leak, a.CanonicalNoImage)
		}
	}
	// The full form must still describe the deployment as it stands.
	if !strings.Contains(a.Canonical, cn20Digest) {
		t.Fatalf("Canonical lost the real digest:\n%s", a.Canonical)
	}
}

// cn-20 runs the same broker digest in three services. A key-based hold-out therefore
// broke three baseline entries per release, not one — which is what made the churn
// intolerable rather than merely annoying.
func TestServiceBlock_ThreeServicesSharingOneBrokerDigest(t *testing.T) {
	doc := func(digest string) string {
		return fmt.Sprintf(`services:
  0g-serving-provider-broker:
    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:%[1]s
    environment:
      - IMAGE_DIGEST=sha256:%[1]s
    volumes:
      - zg-tee:/var/lib/zg-tee
  0g-serving-provider-event:
    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:%[1]s
    environment:
      - IMAGE_DIGEST=sha256:%[1]s
    volumes:
      - zg-tee:/var/lib/zg-tee
      - ./logs/event:/var/log/inference
  0g-controller:
    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:%[1]s
    environment:
      - IMAGE_DIGEST=sha256:%[1]s
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
volumes:
  zg-tee:
`, digest)
	}
	before, after := blocksOf(t, doc(cn20Digest)), blocksOf(t, doc(nextDigest))

	for _, name := range []string{"0g-serving-provider-broker", "0g-serving-provider-event", "0g-controller"} {
		a, b := before[name], after[name]
		if !a.Pinnable() || !b.Pinnable() {
			t.Fatalf("%s: %v / %v", name, a.Err, b.Err)
		}
		if a.DigestNoImage != b.DigestNoImage {
			t.Errorf("%s: one digest bump moved its block-no-image", name)
		}
		if a.Digest == b.Digest {
			t.Errorf("%s: the full block did not move", name)
		}
	}
	// The three still differ from each other — the hold-out erases the image, not the
	// per-service differences a baseline is there to pin.
	seen := map[string]string{}
	for name, b := range before {
		if other, dup := seen[b.DigestNoImage]; dup {
			t.Errorf("%s and %s reduced to the same block despite different volumes", name, other)
		}
		seen[b.DigestNoImage] = name
	}
}

// The two values that must survive, both from cn-20. A looser matcher would erase either,
// and each erasure is a real loss: the repository says where the broker came from, and the
// model revision is what a baseline would notice a model swap by.
func TestServiceBlock_HoldOutDoesNotOverreach(t *testing.T) {
	t.Run("IMAGE_REPO survives", func(t *testing.T) {
		b := oneBlock(t, fmt.Sprintf(cn20BrokerService, cn20Digest))
		if !strings.Contains(b.CanonicalNoImage, "IMAGE_REPO=ghcr.io/0gfoundation/0g-serving-broker") {
			t.Fatalf("the repository was erased along with the digest:\n%s", b.CanonicalNoImage)
		}
		// And it is load-bearing: changing the registry must move the reduced form.
		swapped := strings.Replace(fmt.Sprintf(cn20BrokerService, cn20Digest),
			"IMAGE_REPO=ghcr.io/0gfoundation", "IMAGE_REPO=evil.example.com/0gfoundation", 1)
		if oneBlock(t, swapped).DigestNoImage == b.DigestNoImage {
			t.Fatal("changing IMAGE_REPO did not move DigestNoImage")
		}
	})

	t.Run("a model revision is untouched", func(t *testing.T) {
		// 0gm-sglang's shape: a 40-hex git revision, which is not an image digest.
		const rev = "802e58f5c8211f04079bfb5c27fb2c6ab629b686"
		body := "    image: lmsysorg/sglang@sha256:" + cn20Digest + "\n" +
			"    ipc: host\n    command: --revision " + rev + "\n"
		b := oneBlock(t, body)
		if !strings.Contains(b.CanonicalNoImage, rev) {
			t.Fatalf("the model revision was erased:\n%s", b.CanonicalNoImage)
		}
		// Changing the model must move the reduced form — that is the point of keeping it.
		other := strings.Replace(body, rev, strings.Repeat("f", 40), 1)
		if oneBlock(t, other).DigestNoImage == b.DigestNoImage {
			t.Fatal("swapping the model revision did not move DigestNoImage")
		}
	})

	t.Run("a tag-only image behaves as before", func(t *testing.T) {
		// cn-20 has four of these (prometheus, grafana, node-exporter, dcgm-exporter). No
		// value replacement happens: a tag is short and easy to hit by accident, and such a
		// service's reduced form is not worth much anyway.
		body := "    image: prom/prometheus:v2.45.2\n    environment:\n      - TAG=v2.45.2\n"
		b := oneBlock(t, body)
		if !strings.Contains(b.CanonicalNoImage, "TAG=v2.45.2") {
			t.Fatalf("a tag was erased from a value:\n%s", b.CanonicalNoImage)
		}
		if strings.Contains(b.CanonicalNoImage, "image:") {
			t.Fatalf("the image key survived:\n%s", b.CanonicalNoImage)
		}
	})
}

// Both awkward positions for the digest: on the key side of a mapping, and buried inside
// a longer scalar. The second is the cn-20 case; the first is the one a text-level
// substitution would be most likely to mishandle.
func TestServiceBlock_HoldOutCoversKeysAndSubstrings(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{
			"digest inside a longer scalar",
			"    image: mysql@sha256:%[1]s\n    command: --check sha256:%[1]s --go\n",
		},
		{
			"digest as a mapping key",
			"    image: mysql@sha256:%[1]s\n    labels:\n      sha256:%[1]s: self\n",
		},
		{
			"the whole reference repeated",
			"    image: mysql@sha256:%[1]s\n    environment:\n      REF: mysql@sha256:%[1]s\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := oneBlock(t, fmt.Sprintf(tc.body, cn20Digest))
			b := oneBlock(t, fmt.Sprintf(tc.body, nextDigest))
			if a.DigestNoImage != b.DigestNoImage {
				t.Fatalf("a digest bump moved DigestNoImage:\n%s\nvs\n%s", a.CanonicalNoImage, b.CanonicalNoImage)
			}
			if strings.Contains(a.CanonicalNoImage, cn20Digest) {
				t.Fatalf("the digest survived:\n%s", a.CanonicalNoImage)
			}
			// Longest-match-first: a repeated full reference must not come out as
			// "<held-out>@<held-out>".
			if strings.Contains(a.CanonicalNoImage, imageHeldOut+"@") {
				t.Fatalf("a full reference was replaced piecewise:\n%s", a.CanonicalNoImage)
			}
		})
	}
}

// A duplicate `image` key would leave the second one in the reduced form if removeKey
// stopped at the first — leaving exactly the reference the hold-out exists to remove.
func TestServiceBlock_DuplicateImageKey(t *testing.T) {
	doc := "services:\n  svc:\n    image: mysql@sha256:" + cn20Digest +
		"\n    restart: always\n    image: redis@sha256:" + nextDigest + "\n"
	b := requireBlock(t, doc, "svc")
	if b.Err != nil {
		t.Fatalf("block: %v", b.Err)
	}
	if strings.Contains(b.CanonicalNoImage, "image:") {
		t.Fatalf("an image key survived the hold-out:\n%s", b.CanonicalNoImage)
	}
	// Only the first reference's identity is erased by value, so the second's digest may
	// remain — but its KEY must be gone, which is what removeKey now guarantees.
	if strings.Contains(b.CanonicalNoImage, "redis@") {
		t.Fatalf("the second image reference survived:\n%s", b.CanonicalNoImage)
	}
	// And the review reports the ambiguity, since which image runs is not stated.
	requireFinding(t, reviewOf(t, manifest(doc)), SeverityBlocking, "svc", "image")
}

// Idempotence has to hold for the REDUCED form too, or a stored baseline would not
// survive being reduced again at comparison time — which is the whole reason the baseline
// stores text.
func TestServiceBlock_ReducedFormIsIdempotent(t *testing.T) {
	for _, body := range []string{
		fmt.Sprintf(cn20BrokerService, cn20Digest),
		"    image: prom/prometheus:v2.45.2\n    restart: always\n",
		"    restart: always\n",
	} {
		b := oneBlock(t, body)
		for _, form := range []string{b.Canonical, b.CanonicalNoImage} {
			again, err := CanonicalizeServiceBlock([]byte(form))
			if err != nil {
				t.Fatalf("CanonicalizeServiceBlock: %v", err)
			}
			if again != form {
				t.Fatalf("reducing a canonical form changed it:\n%s\nvs\n%s", again, form)
			}
		}
		// The placeholder must be a plain scalar the emitter leaves alone — if it started
		// getting quoted, the round trip above would already have failed, but say why.
		if strings.Contains(b.CanonicalNoImage, `"`+imageHeldOut+`"`) ||
			strings.Contains(b.CanonicalNoImage, `'`+imageHeldOut+`'`) {
			t.Fatalf("the placeholder is being quoted:\n%s", b.CanonicalNoImage)
		}
	}
}

// The needle is provider-controlled text, and compose.SplitImageRef performs no shape
// check — it returns whatever follows the last "@". So `image: nginx@e` yielded the
// one-character needle "e", and substituting it across every scalar shredded the block:
// the mapping key `environment` came out as `<image-held-out>nvironm<image-held-out>nt`,
// leaving a reduced form that described no service. Erasing too much is the direction
// this file's header calls dangerous, and the input is entirely the provider's.
func TestServiceBlock_MalformedDigestIsNotANeedle(t *testing.T) {
	for _, tc := range []struct{ name, ref string }{
		{"single character", "nginx@e"},
		{"no algorithm", "nginx@" + cn20Digest},
		{"hex too short", "nginx@sha256:abcdef"},
		{"not hex", "nginx@sha256:" + strings.Repeat("z", 64)},
		{"empty after the at", "nginx@"},
		{"algorithm only", "nginx@sha256:"},
		{"uppercase hex", "nginx@sha256:" + strings.Repeat("A", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The reference is quoted: a few of these end in a colon, which unquoted
			// would change what YAML parses rather than what the hold-out sees.
			b := oneBlock(t, "    image: "+strconv.Quote(tc.ref)+"\n    command: exec server\n"+
				"    environment:\n      - MODE=production\n")
			// Nothing may be substituted — not the digest half, and not the full reference
			// either, which is short enough to be dangerous when the digest half is junk.
			if strings.Contains(b.CanonicalNoImage, imageHeldOut) {
				t.Fatalf("a malformed digest was used as a needle:\n%s", b.CanonicalNoImage)
			}
			for _, intact := range []string{"command: exec server", "environment:", "MODE=production"} {
				if !strings.Contains(b.CanonicalNoImage, intact) {
					t.Fatalf("the block lost %q:\n%s", intact, b.CanonicalNoImage)
				}
			}
			// And the review must not call it pinned: it reads as pinned to anyone skimming
			// for "@sha256:", which is worse than an obviously unpinned tag.
			r := reviewOf(t, manifest("services:\n  svc:\n    image: "+strconv.Quote(tc.ref)+"\n"))
			if r.Services[0].Pinned() {
				t.Fatalf("%s reports as pinned by digest", tc.ref)
			}
			requireFinding(t, r, SeverityBlocking, "svc", "image")
		})
	}

	// The control: a real digest still works, and still holds out.
	b := oneBlock(t, "    image: nginx@sha256:"+cn20Digest+"\n    environment:\n      - D=sha256:"+cn20Digest+"\n")
	if !strings.Contains(b.CanonicalNoImage, imageHeldOut) {
		t.Fatalf("a well-formed digest was not held out:\n%s", b.CanonicalNoImage)
	}
	// A longer algorithm name and a longer hex are digests too.
	for _, ref := range []string{
		"nginx@sha512:" + strings.Repeat("a", 128),
		"nginx@multihash.sha2-256:" + strings.Repeat("b", 64),
	} {
		if _, _, d := compose.SplitImageRef(ref); !isDigestShaped(d) {
			t.Errorf("%s: digest %q rejected, but it is one", ref, d)
		}
	}
}

// The substitution is one-way and unescaped, so a manifest that literally carries the
// placeholder would reduce to the same text as one whose digest was erased at that
// position — two different deployments, one fingerprint. Refused for the same reason
// indirection is: a manifest has no legitimate reason to carry it, and the reduction a
// baseline matcher will be built on must not have a collision in it.
func TestServiceBlock_RefusesAManifestCarryingThePlaceholder(t *testing.T) {
	b := oneBlock2(t, "    image: nginx@sha256:"+cn20Digest+"\n    environment:\n      - D="+imageHeldOut+"\n")
	if b.Err == nil {
		t.Fatalf("a block carrying the placeholder was reduced:\n%s", b.Canonical)
	}
	if !strings.Contains(b.Err.Error(), imageHeldOut) {
		t.Fatalf("err = %v, want it to name the string", b.Err)
	}
	if b.Canonical != "" || b.CanonicalNoImage != "" {
		t.Fatalf("a refused block still carries forms: %+v", b)
	}

	// Refused even with no digest to hold out, where no substitution would run: the rule
	// is uniform rather than conditional on the image happening to be pinned today.
	if got := oneBlock2(t, "    image: nginx:1.25\n    environment:\n      - D="+imageHeldOut+"\n"); got.Err == nil {
		t.Fatal("a tag-only block carrying the placeholder was reduced")
	}

	// And the collision it closes: without the refusal these two reduced identically.
	a := oneBlock(t, "    image: x@sha256:"+strings.Repeat("d", 64)+"\n    environment:\n      - D=sha256:"+strings.Repeat("d", 64)+"\n")
	if strings.Contains(a.CanonicalNoImage, imageHeldOut) != true {
		t.Fatalf("expected the held-out form to contain the placeholder:\n%s", a.CanonicalNoImage)
	}
}

// The corrected form of a claim this file's header used to make. `"3000:3000"` does come
// out unquoted, but a colon is a mapping indicator only when followed by whitespace, so it
// reads back as the same scalar — and the emitter keeps quotes exactly where they are
// load-bearing. That second half is the property replaceScalars depends on: it substitutes
// into a VALUE and lets the emitter re-decide how to write it.
func TestServiceBlock_QuotingIsDroppedButMeaningIsNot(t *testing.T) {
	b := oneBlock(t, "    image: mysql:8\n    ports: [\"3000:3000\", \"127.0.0.1:8080:80\"]\n"+
		"    environment: [\"KEY=a: b\", \"OTHER=x#y\"]\n")
	// A value that needs no quotes loses them...
	if !strings.Contains(b.Canonical, "- 3000:3000") {
		t.Fatalf("expected an unquoted port:\n%s", b.Canonical)
	}
	// ...and one that does keeps them.
	if !strings.Contains(b.Canonical, `'KEY=a: b'`) {
		t.Fatalf("a value whose colon-space needs quoting lost them:\n%s", b.Canonical)
	}
	// Neither reading changed: reducing the canonical text again is a no-op, so the
	// unquoted form parsed back to the same scalar rather than to a mapping.
	again, err := CanonicalizeServiceBlock([]byte(b.Canonical))
	if err != nil {
		t.Fatalf("CanonicalizeServiceBlock: %v", err)
	}
	if again != b.Canonical {
		t.Fatalf("the canonical text did not survive a re-read:\n%s\nvs\n%s", again, b.Canonical)
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
			b := requireBlock(t, tc.doc, "svc")
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

// A CYCLE, not just an indirection. yaml.v3 resolves an alias by pointing Node.Alias at
// the anchored node, so a body that is anchored and references itself gives a node graph
// with a back-edge — and a deep copy that followed Alias recursed until the runtime
// killed the process with an unrecoverable stack overflow. The input is entirely the
// provider's: they write the manifest and hash it themselves, so nothing upstream filters
// it.
//
// The three cases above all put the anchor OUTSIDE the service body (`x-base: &base`),
// which is why they missed this: those graphs are still trees from the body's point of
// view. These put the anchor ON the body, which is what closes the loop.
//
// Asserted as a normal return rather than with a recover(): a stack overflow is a runtime
// fatal, so this test can only pass by not crashing — if the bug comes back, the whole
// test binary dies and no assertion runs.
func TestServiceBlock_SelfReferencingAnchorDoesNotCrash(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{
			"body anchors itself and a value aliases it",
			"services:\n  a: &x\n    image: mysql:8.0\n    depends_on: [*x]\n",
		},
		{
			"the alias is nested deeper",
			"services:\n  a: &x\n    image: mysql:8.0\n    deploy:\n      labels:\n        self: *x\n",
		},
		{
			"a mapping key is the alias",
			"services:\n  a: &x\n    image: mysql:8.0\n    labels:\n      ? *x\n      : self\n",
		},
		{
			// A later service aliasing an earlier one is legal and is NOT a cycle, but it
			// is the shape closest to one, so it belongs in this table: the refusal must
			// cover it too, since its canonical form would be `*x`.
			"a later service aliases an earlier body",
			"services:\n  a: &x\n    image: mysql:8.0\n  b: *x\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Every case names the service whose body carries the alias.
			name := "a"
			if strings.Contains(tc.doc, "  b: *x") {
				name = "b"
			}
			b := requireBlock(t, tc.doc, name)
			if b.Err == nil {
				t.Fatalf("a self-referencing anchor was reduced to a canonical form:\n%s", b.Canonical)
			}
			if !strings.Contains(b.Err.Error(), "anchor") {
				t.Fatalf("err = %v, want it to name the anchor", b.Err)
			}
		})
	}

	// Mutual cycles between two services are not expressible: YAML requires an anchor to
	// be defined before it is referenced, so a forward reference is a parse error and the
	// text never reaches a block at all. Asserted so nobody adds a fixture for it and
	// mistakes "no block" for "refused".
	t.Run("a forward anchor reference never becomes a block", func(t *testing.T) {
		doc := "services:\n  a:\n    image: mysql:8.0\n    depends_on: [*y]\n  b: &y\n    image: redis:7\n"
		r := reviewOf(t, manifest(doc))
		if len(r.Blocks) != 0 {
			t.Fatalf("blocks = %+v, want none — the compose text does not parse", r.Blocks)
		}
		requireFinding(t, r, SeverityBlocking, "", "docker_compose_file")
	})
}

// The cycle is only reachable through Alias, so clearing it in the clone is what makes
// cloneNode structurally unable to loop — independently of refuseIndirection running
// first. Asserted directly, because it is the reason a future caller that forgets the
// ordering still cannot crash the process.
func TestCloneNode_DropsAliasAndDoesNotFollowCycles(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("a: &x\n  self: *x\n"), &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	body := root.Content[0].Content[1]
	alias := body.Content[1]
	// The premise: yaml.v3 really does close the loop. If this stops holding, the guard
	// below is no longer testing anything and should be revisited rather than deleted.
	if alias.Kind != yaml.AliasNode || alias.Alias != body {
		t.Fatalf("yaml.v3 did not build a cycle: alias kind=%d Alias=%p body=%p", alias.Kind, alias.Alias, body)
	}

	clone := cloneNode(body) // must terminate
	if clone == body {
		t.Fatal("cloneNode returned the original node")
	}
	if clone.Content[1].Alias != nil {
		t.Fatal("the clone still carries an Alias pointer, so the walk can still loop")
	}
	// And it is a real deep copy: mutating the clone must not reach the original.
	clone.Content[0].Value = "mutated"
	if body.Content[0].Value == "mutated" {
		t.Fatal("the clone shares nodes with the original")
	}
}

func TestServiceBlock_BodyThatIsNotAMapping(t *testing.T) {
	b := requireBlock(t, "services:\n  svc: notamapping\n", "svc")
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

	// The image hold-out now REWRITES scalar values, not just deletes a key — so the
	// clone matters more than it did. If a substitution leaked back into the caller's
	// tree, the review would report a placeholder as the provider's image reference, and
	// every downstream judgement (pinned? which namespace?) would be about a string we
	// invented. This is the assertion most likely to break in a future change here.
	cn20 := fmt.Sprintf(`services:
  0g-serving-provider-broker:
    image: ghcr.io/0gfoundation/0g-serving-broker@sha256:%[1]s
    environment:
      - IMAGE_DIGEST=sha256:%[1]s
`, cn20Digest)
	rc := reviewOf(t, manifest(cn20))
	svc := rc.Services[0]
	if !strings.Contains(svc.Ref, cn20Digest) || svc.Digest != "sha256:"+cn20Digest {
		t.Fatalf("the review lost the real digest to the hold-out: ref=%q digest=%q", svc.Ref, svc.Digest)
	}
	if !svc.Pinned() || svc.Origin != OriginFirstParty {
		t.Fatalf("the review's image judgement changed: %+v", svc)
	}
	if strings.Contains(svc.Ref, imageHeldOut) {
		t.Fatalf("a placeholder reached the review: %q", svc.Ref)
	}
	// The reduced form did erase it, on the clone.
	if strings.Contains(rc.Blocks[0].CanonicalNoImage, cn20Digest) {
		t.Fatalf("the block kept the digest:\n%s", rc.Blocks[0].CanonicalNoImage)
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
