package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// baselineJSON builds a baseline document. Written as JSON rather than as Go structs so
// the tests exercise ParseComposeBaseline — including the line-array form, which is the
// part a human actually edits.
func baselineJSON(t *testing.T, services ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"services": services})
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	return raw
}

func parseBaseline(t *testing.T, services ...map[string]any) []BaselineService {
	t.Helper()
	got, err := ParseComposeBaseline(baselineJSON(t, services...))
	if err != nil {
		t.Fatalf("ParseComposeBaseline: %v", err)
	}
	return got
}

// entry is one baseline service, with the block given as the lines a reviewer would
// paste from `pcverify -blocks`.
func entry(name string, image map[string]any, blockLines ...string) map[string]any {
	e := map[string]any{"name": name, "block": blockLines}
	if image != nil {
		e["image"] = image
	}
	return e
}

const (
	brokerRepo   = "ghcr.io/0gfoundation/0g-serving-broker"
	digestA      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB      = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	mysqlDigestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// --- the empty baseline is a state ----------------------------------------------

// The contract the whole file rests on, and the one an operator's gate depends on: an
// empty baseline means the comparison DID NOT RUN. It must never read as a pass, and it
// must not read as a failure either — the claim is unavailable, not refuted.
func TestCheckCompose_EmptyBaselineIsNotConfigured(t *testing.T) {
	blocks := reviewOf(t, manifest("services:\n  a:\n    image: mysql@"+mysqlDigestC+"\n")).Blocks
	for _, baseline := range [][]BaselineService{nil, {}} {
		got := CheckCompose(baseline, blocks)
		if got.Configured {
			t.Fatal("an empty baseline reported as configured")
		}
		if !got.OK() {
			t.Fatal("an unconfigured comparison reported as a failure")
		}
		if len(got.Mismatches) != 0 {
			t.Fatalf("mismatches from a comparison that did not run: %+v", got.Mismatches)
		}
	}
}

// The shipped file is empty on purpose — a baseline freezes a manifest, and cn-20's
// current one carries ten blocking findings. It still has to PARSE, or the "not
// configured" state would be indistinguishable from a build defect.
func TestBuiltinComposeBaseline_ParsesAndIsDeliberatelyEmpty(t *testing.T) {
	got, err := BuiltinComposeBaseline()
	if err != nil {
		t.Fatalf("the embedded baseline does not parse: %v", err)
	}
	if len(got) != 0 {
		// Not a failure — filling it is the plan. But the file's own header explains why it
		// is empty, so the two must be changed together.
		t.Logf("the embedded baseline now has %d entry/entries; brokercompose.json's header "+
			"must no longer say it is empty", len(got))
	}
}

// --- a match, written independently of the observation ---------------------------

// The baseline is HAND-WRITTEN here rather than derived from the observed block. A test
// that recorded what it just observed would pass even if CheckCompose compared nothing —
// the whole point is that a text a human wrote matches a text the emitter produced.
func TestCheckCompose_MatchesAHandWrittenBaseline(t *testing.T) {
	doc := "services:\n  mysql:\n    image: mysql@" + mysqlDigestC + "\n" +
		"    restart: always\n    volumes:\n      - db:/var/lib/mysql\nvolumes:\n  db:\n"
	blocks := reviewOf(t, manifest(doc)).Blocks

	baseline := parseBaseline(t, entry("mysql", nil,
		"image: mysql@"+mysqlDigestC,
		"restart: always",
		"volumes:",
		"    - db:/var/lib/mysql",
	))
	got := CheckCompose(baseline, blocks)
	if !got.OK() {
		t.Fatalf("a hand-written baseline did not match:\n%s", dumpMismatches(got))
	}
	if got.Matched != 1 {
		t.Fatalf("Matched = %d, want 1", got.Matched)
	}

	// And the reduction is why it matched: the same entry written with different
	// indentation, quoting and a comment still matches, because both sides go through
	// CanonicalizeServiceBlock.
	reformatted := parseBaseline(t, entry("mysql", nil,
		"# reviewed 2026-08",
		"image: \"mysql@"+mysqlDigestC+"\"",
		"restart: 'always'",
		"volumes: [db:/var/lib/mysql]",
	))
	if got := CheckCompose(reformatted, blocks); !got.OK() {
		t.Fatalf("a reformatted baseline stopped matching:\n%s", dumpMismatches(got))
	}
}

// --- every direction is checked -------------------------------------------------

func TestCheckCompose_ChecksEveryDirection(t *testing.T) {
	pinned := "image: mysql@" + mysqlDigestC
	oneEntry := func() []BaselineService {
		return parseBaseline(t, entry("mysql", nil, pinned))
	}

	t.Run("a recorded service the manifest does not declare", func(t *testing.T) {
		blocks := reviewOf(t, manifest("services:\n  other:\n    image: redis@"+digestA+"\n")).Blocks
		got := CheckCompose(oneEntry(), blocks)
		if got.OK() {
			t.Fatal("a missing service matched")
		}
		requireMismatch(t, got, "mysql", "the baseline records this service but the manifest does not declare it")
	})

	// The direction worth stating: an unlisted container runs in the same guest as the
	// reviewed ones. "Ignore what we did not think of" is how a baseline becomes
	// decoration, so this is a mismatch rather than an omission.
	t.Run("a declared service the baseline does not record", func(t *testing.T) {
		doc := "services:\n  mysql:\n    " + pinned + "\n  sneaky:\n    image: evil@" + digestA + "\n"
		got := CheckCompose(oneEntry(), reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("an unlisted service matched")
		}
		requireMismatch(t, got, "sneaky", "the baseline does not record it")
		// The listed one still matched, and the count says so.
		if got.Matched != 1 {
			t.Fatalf("Matched = %d, want 1 — the recorded service did match", got.Matched)
		}
	})

	t.Run("the same service declared twice", func(t *testing.T) {
		doc := "services:\n  mysql:\n    " + pinned + "\n  mysql:\n    image: redis@" + digestA + "\n"
		got := CheckCompose(oneEntry(), reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("a duplicate service name matched")
		}
		requireMismatch(t, got, "mysql", "more than once")
	})

	t.Run("the block differs, and the report names the line", func(t *testing.T) {
		doc := "services:\n  mysql:\n    " + pinned + "\n    privileged: true\n"
		got := CheckCompose(oneEntry(), reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("an added key matched")
		}
		m := requireMismatch(t, got, "mysql", "the service block differs")
		if m.Diff == "" {
			t.Fatal("no diff — \"the block differs\" is unactionable on a twenty-line block")
		}
		if !strings.Contains(m.Diff, "privileged") {
			t.Fatalf("the diff does not name what changed: %q", m.Diff)
		}
	})

	t.Run("a block with no canonical form cannot be compared", func(t *testing.T) {
		doc := "x-base: &b\n  privileged: true\nservices:\n  mysql:\n    <<: *b\n    " + pinned + "\n"
		got := CheckCompose(oneEntry(), reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("an unreducible block matched")
		}
		requireMismatch(t, got, "mysql", "no canonical form")
	})
}

// --- the image rules ------------------------------------------------------------

// With no image rule, the recorded BLOCK pins the image — it contains the image line.
// This is why digest and reference rules were dropped: they could only restate what the
// text already says, and an entry whose rule disagreed with its own block would fail with
// a message about the wrong thing.
func TestCheckCompose_TheBlockPinsTheImage(t *testing.T) {
	baseline := parseBaseline(t, entry("mysql", nil, "image: mysql@"+mysqlDigestC))

	same := reviewOf(t, manifest("services:\n  mysql:\n    image: mysql@"+mysqlDigestC+"\n")).Blocks
	if got := CheckCompose(baseline, same); !got.OK() {
		t.Fatalf("the pinned image did not match:\n%s", dumpMismatches(got))
	}

	// A moved digest is caught, and the diff names the line — which is more actionable
	// than "the digest differs" would have been.
	moved := reviewOf(t, manifest("services:\n  mysql:\n    image: mysql@"+digestA+"\n")).Blocks
	got := CheckCompose(baseline, moved)
	if got.OK() {
		t.Fatal("a different digest matched")
	}
	m := requireMismatch(t, got, "mysql", "the service block differs")
	if !strings.Contains(m.Diff, mysqlDigestC[:20]) {
		t.Fatalf("the diff does not show the recorded digest: %q", m.Diff)
	}

	// A tag-only image works the same way: cn-20 runs four, and the baseline records what
	// is there. The review keeps calling it unpinned, which is the point of keeping the
	// two questions apart.
	tagged := "services:\n  prometheus:\n    image: prom/prometheus:v2.45.2\n    restart: always\n"
	tagBaseline := parseBaseline(t, entry("prometheus", nil,
		"image: prom/prometheus:v2.45.2", "restart: always"))
	review := reviewOf(t, manifest(tagged))
	if got := CheckCompose(tagBaseline, review.Blocks); !got.OK() {
		t.Fatalf("a recorded tag did not match:\n%s", dumpMismatches(got))
	}
	requireFinding(t, review, SeverityBlocking, "prometheus", "image")
	bumped := reviewOf(t, manifest(strings.Replace(tagged, "v2.45.2", "v2.46.0", 1))).Blocks
	if CheckCompose(tagBaseline, bumped).OK() {
		t.Fatal("a bumped tag matched")
	}
}

// The repository rule exists for exactly one case — an image whose release cadence would
// otherwise force a gateway release per broker release — so the property to assert is
// that a new digest in that repository matches while everything else about the block
// still has to hold.
func TestCheckCompose_RepositoryRule(t *testing.T) {
	svc := func(digest string) string {
		return "services:\n  0g-controller:\n    image: " + brokerRepo + "@" + digest + "\n" +
			"    environment:\n      - IMAGE_DIGEST=" + digest + "\n" +
			"    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n"
	}
	// The recorded block is the image-held-out form: no image line, and the copied digest
	// replaced by the placeholder. This is what `-blocks` prints under "no-image:".
	baseline := parseBaseline(t, entry("0g-controller", map[string]any{"repository": brokerRepo},
		"environment:",
		"    - IMAGE_DIGEST="+imageHeldOut,
		"volumes:",
		"    - /var/run/dstack.sock:/var/run/dstack.sock",
	))

	for _, digest := range []string{digestA, digestB} {
		if got := CheckCompose(baseline, reviewOf(t, manifest(svc(digest))).Blocks); !got.OK() {
			t.Fatalf("digest %s did not match the repository rule:\n%s", digest[:14], dumpMismatches(got))
		}
	}

	t.Run("a different repository does not match", func(t *testing.T) {
		doc := strings.ReplaceAll(svc(digestA), brokerRepo, "evil.example.com/0gfoundation/0g-serving-broker")
		got := CheckCompose(baseline, reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("another repository matched")
		}
		requireMismatch(t, got, "0g-controller", "accepts only "+brokerRepo)
	})

	// The rule accepts any image in the repository ONLY when pinned by content. A tag's
	// contents can be republished after the measurement, so "any image in our repository"
	// would otherwise mean "whatever is there now".
	t.Run("a tag in the right repository does not match", func(t *testing.T) {
		// No copy of the digest in this fixture: a manifest carrying the placeholder is
		// itself refused (see composeblock.go), so the block cannot mirror the held-out
		// form here.
		doc := "services:\n  0g-controller:\n    image: " + brokerRepo + ":v1.2.3\n" +
			"    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n"
		plain := parseBaseline(t, entry("0g-controller", map[string]any{"repository": brokerRepo},
			"volumes:",
			"    - /var/run/dstack.sock:/var/run/dstack.sock",
		))
		got := CheckCompose(plain, reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("an unpinned tag matched a repository rule")
		}
		requireMismatch(t, got, "0g-controller", "only pinned by digest")
	})

	// A change OUTSIDE the image must still fail — the hold-out lets the image move, not
	// the deployment.
	t.Run("the rest of the block still has to hold", func(t *testing.T) {
		doc := strings.Replace(svc(digestA),
			"      - /var/run/dstack.sock:/var/run/dstack.sock\n",
			"      - /var/run/docker.sock:/var/run/docker.sock\n", 1)
		got := CheckCompose(baseline, reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("a changed mount matched")
		}
		requireMismatch(t, got, "0g-controller", "the service block differs")
	})
}

// A recorded block with no image line requires a service with no image, for the same
// reason: the text is the pin. "No rule" must not read as "any image".
func TestCheckCompose_ABlockWithNoImageLine(t *testing.T) {
	baseline := parseBaseline(t, entry("init", nil, "restart: 'no'", "command: /bin/true"))

	ok := reviewOf(t, manifest("services:\n  init:\n    restart: 'no'\n    command: /bin/true\n")).Blocks
	if got := CheckCompose(baseline, ok); !got.OK() {
		t.Fatalf("an imageless service did not match:\n%s", dumpMismatches(got))
	}

	withImage := reviewOf(t, manifest("services:\n  init:\n    image: mysql@"+mysqlDigestC+
		"\n    restart: 'no'\n    command: /bin/true\n")).Blocks
	got := CheckCompose(baseline, withImage)
	if got.OK() {
		t.Fatal("a service that gained an image matched a no-image entry")
	}
}

// --- the file itself ------------------------------------------------------------

// A baseline file that cannot be trusted to mean what it says must be refused at LOAD,
// not silently reduced to something weaker. Each case below is a way an entry could
// accept more than its author intended.
func TestParseComposeBaseline_RefusesUnusableEntries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		svc   map[string]any
		says  string
		extra []map[string]any
	}{
		{
			"no name",
			map[string]any{"block": []string{"restart: always"}},
			"name is required", nil,
		},
		{
			"no block — would accept any body",
			map[string]any{"name": "a"},
			"block is required", nil,
		},
		{
			"empty block list",
			map[string]any{"name": "a", "block": []string{}},
			"block is required", nil,
		},
		{
			"block does not reduce",
			map[string]any{"name": "a", "block": []string{"volumes: *anchor"}},
			"does not reduce", nil,
		},
		{
			// Rejected rather than ignored: an author reaching for these has a reasonable
			// model of the format, and silently dropping the key would hand them a baseline
			// that pins less than they wrote.
			"a digest rule, which this format does not have",
			entry("a", map[string]any{"digest": mysqlDigestC}, "restart: always"),
			"the recorded block already contains the image line", nil,
		},
		{
			"a reference rule, likewise",
			entry("a", map[string]any{"reference": "mysql:8"}, "restart: always"),
			"the recorded block already contains the image line", nil,
		},
		{
			"image present but states no repository",
			entry("a", map[string]any{}, "restart: always"),
			"states no repository", nil,
		},
		{
			"listed twice",
			entry("a", nil, "restart: always"),
			"listed twice",
			[]map[string]any{entry("a", nil, "restart: never")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svcs := append([]map[string]any{tc.svc}, tc.extra...)
			_, err := ParseComposeBaseline(baselineJSON(t, svcs...))
			if err == nil {
				t.Fatal("an unusable entry was accepted")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.says)
			}
		})
	}

	if _, err := ParseComposeBaseline([]byte("not json")); err == nil {
		t.Fatal("a non-JSON baseline was accepted")
	}
}

// --- helpers --------------------------------------------------------------------

func requireMismatch(t *testing.T, c ComposeCheck, service, says string) ComposeMismatch {
	t.Helper()
	for _, m := range c.Mismatches {
		if m.Service == service && strings.Contains(m.Reason, says) {
			return m
		}
	}
	t.Fatalf("no mismatch for %q mentioning %q:\n%s", service, says, dumpMismatches(c))
	return ComposeMismatch{}
}

func dumpMismatches(c ComposeCheck) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  configured=%v matched=%d\n", c.Configured, c.Matched)
	for _, m := range c.Mismatches {
		fmt.Fprintf(&b, "  %s: %s\n", m.Service, m.Reason)
		if m.Diff != "" {
			fmt.Fprintf(&b, "    %s\n", m.Diff)
		}
	}
	return b.String()
}
