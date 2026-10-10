package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// --- the shipped file ------------------------------------------------------------

// The embedded baseline records cn-20's twelve services. Asserting the names and the
// count is not ceremony: the file is the only thing standing between a provider's
// containers and "unreviewed", and a bad merge that drops entries would leave the
// remaining ones passing while the dropped services silently become mismatches nobody
// looks at — or, if all of them go, would turn the whole check off as "not configured".
func TestBuiltinComposeBaseline_RecordsCn20(t *testing.T) {
	got, err := BuiltinComposeBaseline()
	if err != nil {
		t.Fatalf("the embedded baseline does not parse: %v", err)
	}
	want := []string{
		"broker-ingress", "0gm-sglang", "mysql", "broker-config-init",
		"0g-serving-provider-broker", "0g-serving-provider-event", "0g-controller",
		"prometheus-init", "prometheus", "grafana", "prometheus-node-exporter",
		"dcgm-exporter",
	}
	if len(got) != len(want) {
		t.Fatalf("the embedded baseline has %d entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("entry %d is %q, want %q", i, got[i].Name, w)
		}
	}
}

// The likeliest transcription error in this file is pasting the WRONG one of the two
// forms `-blocks` prints, and it is silent in the worst direction: a repository rule
// compares against the image-held-out form, so an entry that recorded the full block
// would never match and the service would read as changed on a deployment that had not
// changed. The two are distinguishable without the manifest — a held-out block has no
// top-level image line — so check it here rather than waiting for a live run to say so.
func TestBuiltinComposeBaseline_EachEntryRecordsTheFormItsRuleCompares(t *testing.T) {
	got, err := BuiltinComposeBaseline()
	if err != nil {
		t.Fatal(err)
	}
	withRule := 0
	for _, s := range got {
		hasImageLine := false
		for _, line := range strings.Split(s.Block, "\n") {
			if strings.HasPrefix(line, "image:") {
				hasImageLine = true
				break
			}
		}
		if s.Image.pinsImageInBlock() {
			// Every service in this manifest names an image. A format where one did not
			// would be legal, so this is an assertion about the FILE, not the format.
			if !hasImageLine {
				t.Errorf("%s: no image rule, so the block must pin the image — but it has no "+
					"image line. The image-held-out form was recorded by mistake", s.Name)
			}
			continue
		}
		withRule++
		if hasImageLine {
			t.Errorf("%s: has a repository rule, which compares the image-held-out form — but "+
				"the recorded block still carries an image line, so it can never match", s.Name)
		}
		if s.Image.Repository != brokerRepo {
			t.Errorf("%s: repository rule names %q; the only image meant to move is %q",
				s.Name, s.Image.Repository, brokerRepo)
		}
	}
	// Three services run 0G's own broker image. Guarding the count keeps the rule from
	// spreading by copy-paste to a service whose image has no release cadence to excuse it.
	if withRule != 3 {
		t.Errorf("%d entries let their image move within a repository, want 3", withRule)
	}
}

// The shipped baseline against a real manifest, which is the only test here that
// exercises the file rather than the mechanism. Everything else in this package builds a
// tiny manifest and a baseline to match it, so all of it would still pass if a block in
// brokercompose.json were mistyped.
//
// The fixture is NOT independent of the baseline — both come from one `-blocks` run — but
// it is independent in the dimension that can actually go wrong: it carries the FULL
// blocks with cn-20's real image references, while the baseline stores the image-held-out
// form for the three broker services. So a match here means the repository rule really
// does accept a live digest-pinned reference, which no synthetic fixture shows.
func TestBuiltinComposeBaseline_MatchesTheManifestItWasRecordedFrom(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("testdata", "cn20-services.yml"))
	if err != nil {
		t.Fatal(err)
	}
	review := reviewOf(t, manifest(string(doc)))
	baseline, err := BuiltinComposeBaseline()
	if err != nil {
		t.Fatal(err)
	}

	got := CheckCompose(baseline, review.Blocks)
	if !got.Configured {
		t.Fatal("the embedded baseline reported as not configured")
	}
	if !got.OK() {
		t.Fatalf("the recorded baseline does not match the manifest it was recorded from:\n%s",
			dumpMismatches(got))
	}
	if got.Matched != len(baseline) {
		t.Errorf("matched %d of %d recorded services", got.Matched, len(baseline))
	}

	// And the claim the file's header rests on: recording SILENCES NOTHING. The review is
	// a separate mechanism and goes on reporting the same manifest as unfit. Asserted on
	// the finding that matters rather than on a count, so a legitimate new review rule
	// does not fail this test.
	var found bool
	for _, f := range review.Findings {
		if f.Severity == SeverityBlocking && f.Service == "0g-controller" &&
			strings.Contains(f.Detail, "docker.sock") {
			found = true
		}
	}
	if !found {
		t.Error("the recorded manifest no longer reports 0g-controller's docker.sock mount as " +
			"blocking — recording a deployment must not silence the review of it")
	}
}

// Every entry carries its audit note. The comparison never reads one, which is exactly
// why a test has to: a `note` is the only record of why a block with a blocking review
// finding in it was recorded anyway, and an entry added without one has been frozen
// without being explained.
func TestBuiltinComposeBaseline_EveryEntryCarriesItsAuditNote(t *testing.T) {
	raw, err := composeBaselineFS.ReadFile("brokercompose.json")
	if err != nil {
		t.Fatal(err)
	}
	var f composeBaselineFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Comment) == 0 {
		t.Error("the file carries no _comment header; an author editing it has nothing to read")
	}
	for _, s := range f.Services {
		if len(s.Note) == 0 {
			t.Errorf("%s: no note — the entry freezes this service without recording why", s.Name)
		}
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

// A MISSPELLED KEY must be an error, and the top-level one is the case that matters:
// under a permissive decoder `{"servcies": [...]}` yields zero entries, zero entries
// mean NOT CONFIGURED, and the reports then say the comparison did not run — which is a
// line an operator reads past. A typo that turns the adjudicating check off is worse
// than any entry this file could get wrong.
func TestParseComposeBaseline_RefusesUnknownKeys(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{
			"services misspelled — would silently disable the check",
			`{"servcies": [{"name": "a", "block": ["restart: always"]}]}`,
		},
		{
			"block misspelled",
			`{"services": [{"name": "a", "blocks": ["restart: always"]}]}`,
		},
		{
			"an image rule key this format does not have",
			`{"services": [{"name": "a", "block": ["restart: always"], "image": {"repo": "x"}}]}`,
		},
		{
			"a service key this format does not have",
			`{"services": [{"name": "a", "block": ["restart: always"], "justification": "trust me"}]}`,
		},
		{
			// A Decoder would otherwise stop at the first value, leaving a second object —
			// and any edits in it — decoded by nothing.
			"a second object after the first",
			`{"services": []}{"services": [{"name": "a", "block": ["restart: always"]}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseComposeBaseline([]byte(tc.doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	// The two keys the file carries for humans are DECLARED, so hardening the decode did
	// not cost the format its ability to explain itself.
	got, err := ParseComposeBaseline([]byte(`{
	  "_comment": ["why this file exists"],
	  "services": [{"name": "a", "note": ["why this entry stands"], "block": ["restart: always"]}]
	}`))
	if err != nil {
		t.Fatalf("_comment or note was refused: %v", err)
	}
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("got %+v, want the one entry", got)
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
