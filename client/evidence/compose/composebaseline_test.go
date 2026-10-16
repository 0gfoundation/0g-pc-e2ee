package compose

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

// The deployment every single-deployment test records, and the provider it is checked
// as. Most tests here are about how ONE recorded deployment compares; the lookup by
// provider has tests of its own below.
const (
	testContract = "0x47340d900bdFec2BD393c626E12ea0656F938d84"
	testProvider = "0x4870CbC4D07d6Ac2EE5aA865588e5985FE77a4E9"
)

// deployment is one recorded deployment for the baseline JSON.
func deployment(name, contract string, providers []string, services ...map[string]any) map[string]any {
	return map[string]any{"name": name, "contract": contract, "providers": providers, "services": services}
}

// baselineJSON builds a baseline document recording one deployment for testProvider.
// Written as JSON rather than as Go structs so the tests exercise ParseComposeBaseline —
// including the line-array form, which is the part a human actually edits.
func baselineJSON(t *testing.T, services ...map[string]any) []byte {
	t.Helper()
	return deploymentsJSON(t, deployment("test", testContract, []string{testProvider}, services...))
}

func deploymentsJSON(t *testing.T, deps ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"deployments": deps})
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	return raw
}

func parseBaseline(t *testing.T, services ...map[string]any) ComposeBaseline {
	t.Helper()
	got, err := ParseComposeBaseline(baselineJSON(t, services...))
	if err != nil {
		t.Fatalf("ParseComposeBaseline: %v", err)
	}
	return got
}

// check compares blocks as testProvider, against testReleases.
func check(b ComposeBaseline, blocks []ServiceBlock) ComposeCheck {
	return CheckCompose(b, testReleases, testContract, testProvider, blocks, nil)
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
	for _, baseline := range []ComposeBaseline{{}, {Deployments: []Deployment{}}} {
		got := check(baseline, blocks)
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

// --- a provider nobody recorded is a state too -------------------------------------

// The reason the baseline is keyed by provider. A configured baseline that records no
// deployment for THIS provider did not compare anything, and must say so rather than
// compare the manifest against someone else's deployment and list every difference.
// On the 2026-10-10 sweep the flat baseline did exactly that: six providers out of seven
// exited 1, with twelve "mismatches" each, for the sole reason that nobody had recorded
// them. Not recorded is unverified, not refuted.
func TestCheckCompose_UnrecordedProviderIsNotCompared(t *testing.T) {
	b := parseBaseline(t, entry("a", nil, "image: mysql@"+mysqlDigestC))
	blocks := reviewOf(t, manifest("services:\n  b:\n    image: redis@"+digestB+"\n")).Blocks

	got := CheckCompose(b, testReleases, testContract, "0x"+strings.Repeat("9", 40), blocks, nil)
	if !got.Configured {
		t.Fatal("a baseline with a deployment reported as unconfigured")
	}
	if got.Recorded || got.Compared() {
		t.Fatal("a provider the baseline does not list was compared")
	}
	if !got.OK() {
		t.Fatal("an unrecorded provider reported as a failure")
	}
	if len(got.Mismatches) != 0 {
		t.Fatalf("mismatches from a comparison that did not run: %+v", got.Mismatches)
	}
}

// The contract is half the key. One operator key registered on testnet and on mainnet
// is one address running two deployments, and must not be compared against the wrong
// one.
func TestCheckCompose_TheContractIsPartOfTheKey(t *testing.T) {
	b := parseBaseline(t, entry("a", nil, "image: mysql@"+mysqlDigestC))
	blocks := reviewOf(t, manifest("services:\n  a:\n    image: mysql@"+mysqlDigestC+"\n")).Blocks

	if got := CheckCompose(b, testReleases, "0x"+strings.Repeat("1", 40), testProvider, blocks, nil); got.Recorded {
		t.Fatal("a provider recorded on one contract was looked up on another")
	}
	// Case does not matter: the chain and the operator spell addresses differently.
	got := CheckCompose(b, testReleases, "0x"+strings.ToUpper(testContract[2:]), strings.ToLower(testProvider), blocks, nil)
	if !got.Compared() || !got.OK() {
		t.Fatalf("an EIP-55 / lowercase spelling of the same addresses did not match: %+v", got)
	}
	if got.Deployment != "test" {
		t.Fatalf("deployment = %q", got.Deployment)
	}
}

// Several registrations can share one deployment — cn-39 and cn-40 are one CVM — and
// each must find it.
func TestComposeBaseline_SeveralProvidersShareADeployment(t *testing.T) {
	p2 := "0x" + strings.Repeat("2", 40)
	b, err := ParseComposeBaseline(deploymentsJSON(t,
		deployment("shared", testContract, []string{testProvider, p2}, entry("a", nil, "image: mysql@"+mysqlDigestC))))
	if err != nil {
		t.Fatal(err)
	}
	blocks := reviewOf(t, manifest("services:\n  a:\n    image: mysql@"+mysqlDigestC+"\n")).Blocks
	for _, p := range []string{testProvider, p2} {
		if got := CheckCompose(b, testReleases, testContract, p, blocks, nil); !got.Compared() || !got.OK() {
			t.Fatalf("%s: %+v", p, got)
		}
	}
}

// --- the shipped file ------------------------------------------------------------

const (
	mainnetContract = "0x47340d900bdFec2BD393c626E12ea0656F938d84"
	cn20Provider    = "0x4870CbC4D07d6Ac2EE5aA865588e5985FE77a4E9"
	testnetContract = "0xa79F4c8311FF93C06b8CfB403690cc987c93F91E"
	testnetProvider = "0x1cB95Eb66Cc67C62d4DE0CC96726C5A5d82e7C85"
)

// The embedded baseline records two deployments, and which providers run them. Asserted
// because a bad merge that drops one turns that provider back into "not recorded" — a
// quiet exit 3 that nobody investigates — rather than into a failure.
func TestBuiltinComposeBaseline_RecordsItsDeployments(t *testing.T) {
	b, err := BuiltinComposeBaseline()
	if err != nil {
		t.Fatalf("the embedded baseline does not parse: %v", err)
	}
	for _, tc := range []struct {
		contract, provider, name string
		services                 []string
	}{
		{mainnetContract, cn20Provider, "mainnet compute-network-20", []string{
			"broker-ingress", "0gm-sglang", "mysql", "broker-config-init",
			"0g-serving-provider-broker", "0g-serving-provider-event", "0g-controller",
			"prometheus-init", "prometheus", "grafana", "prometheus-node-exporter", "dcgm-exporter",
		}},
		{testnetContract, testnetProvider, "testnet compute-network-20-dev", []string{
			"broker-ingress", "0gm-sglang", "mysql", "broker-config-init",
			"0g-serving-provider-broker", "0g-serving-provider-event", "0g-controller",
			"prometheus-init", "prometheus", "grafana", "dcgm-exporter",
		}},
	} {
		dep, ok := b.For(tc.contract, tc.provider)
		if !ok {
			t.Errorf("no deployment recorded for %s on %s", tc.provider, tc.contract)
			continue
		}
		if dep.Name != tc.name {
			t.Errorf("%s: deployment %q, want %q", tc.provider, dep.Name, tc.name)
		}
		var got []string
		for _, s := range dep.Services {
			got = append(got, s.Name)
		}
		if strings.Join(got, ",") != strings.Join(tc.services, ",") {
			t.Errorf("%s services:\n got  %v\n want %v", tc.name, got, tc.services)
		}
	}
	if len(b.Deployments) != 2 {
		t.Errorf("%d deployments recorded, want 2", len(b.Deployments))
	}
}

// The likeliest transcription error in this file is pasting the WRONG one of the two
// forms `-blocks` prints, and it is silent in the worst direction: a repository rule
// compares against the image-held-out form, so an entry that recorded the full block
// would never match and the service would read as changed on a deployment that had not
// changed. The two are distinguishable without the manifest — a held-out block has no
// top-level image line — so check it here rather than waiting for a live run to say so.
func TestBuiltinComposeBaseline_EachEntryRecordsTheFormItsRuleCompares(t *testing.T) {
	b, err := BuiltinComposeBaseline()
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range b.Deployments {
		withRule := 0
		for _, s := range dep.Services {
			hasImageLine := false
			for _, line := range strings.Split(s.Block, "\n") {
				if strings.HasPrefix(line, "image:") {
					hasImageLine = true
					break
				}
			}
			if s.Image.pinsImageInBlock() {
				// Every service in these manifests names an image. A format where one did
				// not would be legal, so this is an assertion about the FILE, not the format.
				if !hasImageLine {
					t.Errorf("%s/%s: no image rule, so the block must pin the image — but it has no "+
						"image line. The image-held-out form was recorded by mistake", dep.Name, s.Name)
				}
				continue
			}
			withRule++
			if hasImageLine {
				t.Errorf("%s/%s: has a repository rule, which compares the image-held-out form — but "+
					"the recorded block still carries an image line, so it can never match", dep.Name, s.Name)
			}
			if s.Image.Repository != brokerRepo {
				t.Errorf("%s/%s: repository rule names %q; the only image meant to move is %q",
					dep.Name, s.Name, s.Image.Repository, brokerRepo)
			}
		}
		// Three services run 0G's own broker image. Guarding the count keeps the rule from
		// spreading by copy-paste to a service whose image has no release cadence to excuse it.
		if withRule != 3 {
			t.Errorf("%s: %d entries let their image move, want 3", dep.Name, withRule)
		}
	}
}

// The shipped baseline against the manifests it was recorded from, with the SHIPPED
// release verdicts — the only tests here that exercise the files rather than the mechanism.
// Everything else builds a tiny manifest and a baseline to match it, so all of it would
// still pass if a block in brokercompose.json were mistyped or a release were missing.
//
// The fixtures are not independent of the baseline — each comes from the same `-blocks`
// run — but they are independent in the dimension that can go wrong: they carry the FULL
// blocks with the real image references, while the baseline stores the image-held-out
// form for the broker services. So these runs show what the release rule actually does
// to a live digest.
func TestBuiltinComposeBaseline_AgainstTheManifestsItWasRecordedFrom(t *testing.T) {
	b, err := BuiltinComposeBaseline()
	if err != nil {
		t.Fatal(err)
	}
	rels := fleetReleases

	// testnet runs v0.5.4, an accepted release: every service matches.
	t.Run("testnet matches in full", func(t *testing.T) {
		got := CheckCompose(b, rels, testnetContract, testnetProvider, reviewTestnet(t).Blocks, reviewTestnet(t).TopLevel)
		if !got.Compared() || !got.OK() {
			t.Fatalf("the testnet deployment does not match its own record:\n%s", dumpMismatches(got))
		}
		if got.Matched != got.Expected || got.Expected != 11 {
			t.Fatalf("matched %d of %d", got.Matched, got.Expected)
		}
		if got.TopMatched != got.TopExpected || got.TopExpected != 2 {
			t.Fatalf("top-level sections matched %d of %d", got.TopMatched, got.TopExpected)
		}
	})

	// cn-20 runs v0.5.1: a real release, deliberately not a listed one. Its nine other
	// services match; exactly the three broker-image services fail, and on their IMAGE —
	// their blocks still match. That is the release rule doing its job, and pinning it here
	// means a verifier that started accepting v0.5.1 again would fail this test.
	t.Run("cn-20 fails only on its unlisted broker release", func(t *testing.T) {
		got := CheckCompose(b, rels, mainnetContract, cn20Provider, reviewCN20(t).Blocks, reviewCN20(t).TopLevel)
		if !got.Compared() {
			t.Fatal("cn-20 was not compared")
		}
		if got.Matched != 9 || len(got.Mismatches) != 3 {
			t.Fatalf("matched %d, %d mismatches; want 9 and 3:\n%s", got.Matched, len(got.Mismatches), dumpMismatches(got))
		}
		for _, svc := range []string{"0g-serving-provider-broker", "0g-serving-provider-event", "0g-controller"} {
			m := requireMismatch(t, got, svc, "not an accepted release")
			if !strings.Contains(m.Reason, "sha256:ec5df8347f91") {
				t.Errorf("%s: the reason does not name the running digest: %s", svc, m.Reason)
			}
		}
	})

	// And recording is not approval: the review still sees cn-20's runtime socket.
	t.Run("recording silences nothing", func(t *testing.T) {
		var found bool
		for _, f := range reviewCN20(t).Findings {
			if f.Severity == SeverityBlocking && f.Service == "0g-controller" && strings.Contains(f.Detail, "docker.sock") {
				found = true
			}
		}
		if !found {
			t.Error("cn-20's docker.sock mount is no longer reported as blocking")
		}
	})
}

// Every entry carries its audit note, and so does every deployment. The comparison never
// reads one, which is exactly why a test has to: a note is the only record of why a block
// with a blocking review finding in it was recorded anyway.
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
	for _, d := range f.Deployments {
		if len(d.Note) == 0 {
			t.Errorf("deployment %s: no note", d.Name)
		}
		for _, s := range d.Services {
			if len(s.Note) == 0 {
				t.Errorf("%s/%s: no note — the entry freezes this service without recording why", d.Name, s.Name)
			}
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
	got := check(baseline, blocks)
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
	if got := check(reformatted, blocks); !got.OK() {
		t.Fatalf("a reformatted baseline stopped matching:\n%s", dumpMismatches(got))
	}
}

// --- every direction is checked -------------------------------------------------

func TestCheckCompose_ChecksEveryDirection(t *testing.T) {
	pinned := "image: mysql@" + mysqlDigestC
	oneEntry := func() ComposeBaseline {
		return parseBaseline(t, entry("mysql", nil, pinned))
	}

	t.Run("a recorded service the manifest does not declare", func(t *testing.T) {
		blocks := reviewOf(t, manifest("services:\n  other:\n    image: redis@"+digestA+"\n")).Blocks
		got := check(oneEntry(), blocks)
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
		got := check(oneEntry(), reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("an unlisted service matched")
		}
		requireMismatch(t, got, "sneaky", "the baseline does not record it")
		// The listed one still matched, and the count says so.
		if got.Matched != 1 {
			t.Fatalf("Matched = %d, want 1 — the recorded service did match", got.Matched)
		}
	})

	// docker compose refuses a file that declares a service twice, and so does the review
	// (composeload.go), so no manifest produces this list any more. CheckCompose refuses
	// it on its own all the same, so the guarantee does not rest on its caller.
	t.Run("the same service declared twice", func(t *testing.T) {
		blocks := append(reviewOf(t, manifest("services:\n  mysql:\n    "+pinned+"\n")).Blocks,
			reviewOf(t, manifest("services:\n  mysql:\n    image: redis@"+digestA+"\n")).Blocks...)
		got := check(oneEntry(), blocks)
		if got.OK() {
			t.Fatal("a duplicate service name matched")
		}
		requireMismatch(t, got, "mysql", "more than once")
	})

	t.Run("the block differs, and the report names the line", func(t *testing.T) {
		doc := "services:\n  mysql:\n    " + pinned + "\n    privileged: true\n"
		got := check(oneEntry(), reviewOf(t, manifest(doc)).Blocks)
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
		// The one block docker compose loads that has no canonical form: it carries the
		// hold-out placeholder (blockOf).
		doc := "services:\n  mysql:\n    image: mysql:8.0\n    environment:\n      - X=" + imageHeldOut + "\n"
		got := check(oneEntry(), reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("an unreducible block matched")
		}
		requireMismatch(t, got, "mysql", "no canonical form")
	})

	t.Run("a manifest docker compose refuses cannot be compared", func(t *testing.T) {
		r := reviewOf(t, manifest("services:\n  mysql: notamapping\n"))
		got := CheckReview(oneEntry(), testReleases, testContract, testProvider, r)
		if got.OK() || len(got.Mismatches) != 1 {
			t.Fatalf("want exactly one mismatch, got %+v", got.Mismatches)
		}
		requireMismatch(t, got, "", "cannot be compared: docker compose refuses the compose text")
		// And it is still only a deployment that is recorded which fails: an unrecorded
		// provider's manifest is not compared, refused or not.
		if got := CheckReview(oneEntry(), testReleases, testContract, "0x"+strings.Repeat("9", 40), r); got.Recorded ||
			!got.OK() {
			t.Fatalf("an unrecorded provider: %+v", got)
		}
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
	if got := check(baseline, same); !got.OK() {
		t.Fatalf("the pinned image did not match:\n%s", dumpMismatches(got))
	}

	// A moved digest is caught, and the diff names the line — which is more actionable
	// than "the digest differs" would have been.
	moved := reviewOf(t, manifest("services:\n  mysql:\n    image: mysql@"+digestA+"\n")).Blocks
	got := check(baseline, moved)
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
	if got := check(tagBaseline, review.Blocks); !got.OK() {
		t.Fatalf("a recorded tag did not match:\n%s", dumpMismatches(got))
	}
	requireFinding(t, review, SeverityBlocking, "prometheus", "image")
	bumped := reviewOf(t, manifest(strings.Replace(tagged, "v2.45.2", "v2.46.0", 1))).Blocks
	if check(tagBaseline, bumped).OK() {
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
		if got := check(baseline, reviewOf(t, manifest(svc(digest))).Blocks); !got.OK() {
			t.Fatalf("digest %s did not match the repository rule:\n%s", digest[:14], dumpMismatches(got))
		}
	}

	t.Run("a different repository does not match", func(t *testing.T) {
		doc := strings.ReplaceAll(svc(digestA), brokerRepo, "evil.example.com/0gfoundation/0g-serving-broker")
		got := check(baseline, reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("another repository matched")
		}
		requireMismatch(t, got, "0g-controller", "accepts only "+brokerRepo)
	})

	// The rule accepts a release ONLY when pinned by content. A tag's contents can be
	// republished after the measurement, so "a release of our repository" would otherwise
	// mean "whatever is there now".
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
		got := check(plain, reviewOf(t, manifest(doc)).Blocks)
		if got.OK() {
			t.Fatal("an unpinned tag matched a repository rule")
		}
		requireMismatch(t, got, "0g-controller", "pinned by digest")
	})

	// The bound the release verifier adds, and the reason it exists: two of the broker
	// digests on the fleet are manual branch builds, and the rule as first written ("any
	// digest-pinned image in the repository") accepted them.
	t.Run("a digest-pinned image that is not an accepted release does not match", func(t *testing.T) {
		unreleased := "sha256:" + strings.Repeat("d", 64)
		got := check(baseline, reviewOf(t, manifest(svc(unreleased))).Blocks)
		if got.OK() {
			t.Fatal("an unreleased build matched")
		}
		m := requireMismatch(t, got, "0g-controller", "not an accepted release")
		if !strings.Contains(m.Reason, "no provenance from the release workflow") {
			t.Fatalf("the verifier's reason did not reach the report: %s", m.Reason)
		}
	})

	// A verifier that accepts nothing accepts nothing. It must never read as "any digest".
	t.Run("a verifier that accepts nothing", func(t *testing.T) {
		got := CheckCompose(baseline, fakeReleases{repo: brokerRepo}, testContract, testProvider,
			reviewOf(t, manifest(svc(digestA))).Blocks, nil)
		if got.OK() {
			t.Fatal("a verifier that accepts nothing accepted a build")
		}
		requireMismatch(t, got, "0g-controller", "not an accepted release")
	})

	// A verifier for some other repository cannot vouch for this one.
	t.Run("a verifier for another repository accepts nothing", func(t *testing.T) {
		got := CheckCompose(baseline, fakeReleases{repo: "ghcr.io/x/y", accepted: testReleases.accepted},
			testContract, testProvider, reviewOf(t, manifest(svc(digestA))).Blocks, nil)
		if got.OK() {
			t.Fatal("a verifier for another repository accepted a build")
		}
		requireMismatch(t, got, "0g-controller", "release verifier judges ghcr.io/x/y")
	})

	// A build nobody could check — the registry did not answer — is neither a match nor a
	// mismatch: the comparison is incomplete, which pcverify reports as exit 3. The block
	// itself still has to match; only the release question is left open.
	t.Run("a build that could not be checked leaves the comparison incomplete", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			rels evidence.ReleaseVerifier
		}{
			{"the verifier could not reach the registry", fakeReleases{repo: brokerRepo, unavailable: true}},
			{"no verifier", nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := CheckCompose(baseline, tc.rels, testContract, testProvider,
					reviewOf(t, manifest(svc(digestA))).Blocks, nil)
				if !got.OK() || len(got.Mismatches) != 0 {
					t.Fatalf("an unchecked build was reported as a mismatch: %+v", got.Mismatches)
				}
				if got.Complete() || len(got.Unverified) != 1 || got.Unverified[0].Service != "0g-controller" {
					t.Fatalf("an unchecked build was not reported as unverified: %+v", got)
				}
				if got.Matched != 0 {
					t.Fatalf("an unchecked build counted as matched (%d)", got.Matched)
				}
			})
		}
		// The block is still compared first: a differing block is a mismatch however the
		// release question would have come out.
		other := strings.Replace(svc(digestA), "/var/run/dstack.sock:/var/run/dstack.sock",
			"/var/run/dstack.sock:/var/run/dstack.sock\n      - /etc:/host-etc", 1)
		if other == svc(digestA) {
			t.Fatal("the edit did not apply")
		}
		got := CheckCompose(baseline, fakeReleases{repo: brokerRepo, unavailable: true}, testContract, testProvider,
			reviewOf(t, manifest(other)).Blocks, nil)
		if got.OK() {
			t.Fatal("a differing block passed because its release could not be checked")
		}
	})

	// A change OUTSIDE the image must still fail — the hold-out lets the image move, not
	// the deployment.
	t.Run("the rest of the block still has to hold", func(t *testing.T) {
		doc := strings.Replace(svc(digestA),
			"      - /var/run/dstack.sock:/var/run/dstack.sock\n",
			"      - /var/run/docker.sock:/var/run/docker.sock\n", 1)
		got := check(baseline, reviewOf(t, manifest(doc)).Blocks)
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
	if got := check(baseline, ok); !got.OK() {
		t.Fatalf("an imageless service did not match:\n%s", dumpMismatches(got))
	}

	withImage := reviewOf(t, manifest("services:\n  init:\n    image: mysql@"+mysqlDigestC+
		"\n    restart: 'no'\n    command: /bin/true\n")).Blocks
	got := check(baseline, withImage)
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
// under a permissive decoder `{"deploymnets": [...]}` yields zero deployments, zero means
// NOT CONFIGURED, and the reports then say the comparison did not run — which is a line
// an operator reads past. A typo that turns the adjudicating check off is worse than any
// entry this file could get wrong. Every level is tested, since each has its own keys.
func TestParseComposeBaseline_RefusesUnknownKeys(t *testing.T) {
	dep := func(extra, svc string) string {
		return `{"deployments": [{"name": "d", "contract": "` + testContract + `", "providers": ["` +
			testProvider + `"]` + extra + `, "services": [` + svc + `]}]}`
	}
	for _, tc := range []struct{ name, doc string }{
		{"deployments misspelled — would silently disable the check",
			`{"deploymnets": [{"name": "d"}]}`},
		{"a deployment key this format does not have",
			dep(`, "compose_hash": "aa"`, `{"name": "a", "block": ["restart: always"]}`)},
		{"block misspelled",
			dep("", `{"name": "a", "blocks": ["restart: always"]}`)},
		{"an image rule key this format does not have",
			dep("", `{"name": "a", "block": ["restart: always"], "image": {"repo": "x"}}`)},
		{"a service key this format does not have",
			dep("", `{"name": "a", "block": ["restart: always"], "justification": "trust me"}`)},
		// A Decoder would otherwise stop at the first value, leaving a second object — and
		// any edits in it — decoded by nothing.
		{"a second object after the first",
			`{"deployments": []}` + dep("", `{"name": "a", "block": ["restart: always"]}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseComposeBaseline([]byte(tc.doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	// The keys the file carries for humans are DECLARED, so hardening the decode did not
	// cost the format its ability to explain itself.
	got, err := ParseComposeBaseline([]byte(`{"_comment": ["why this file exists"], "deployments": [{
	  "name": "d", "note": ["why this deployment"], "contract": "` + testContract + `", "providers": ["` + testProvider + `"],
	  "services": [{"name": "a", "note": ["why this entry stands"], "block": ["restart: always"]}]}]}`))
	if err != nil {
		t.Fatalf("_comment or note was refused: %v", err)
	}
	if len(got.Deployments) != 1 || got.Deployments[0].Services[0].Name != "a" {
		t.Fatalf("got %+v, want the one entry", got)
	}
}

// The format before deployments existed — a top-level "services" list — is refused with
// directions rather than with "unknown field". Candidates in that shape are in people's
// hands (the broker team checked one against testnet), and the fix is mechanical once
// someone says what it is.
func TestParseComposeBaseline_TheFlatFormatGetsDirections(t *testing.T) {
	_, err := ParseComposeBaseline([]byte(`{"services": [{"name": "a", "block": ["restart: always"]}]}`))
	if err == nil {
		t.Fatal("a flat baseline was accepted")
	}
	for _, want := range []string{"deployments", "contract", "providers"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to say how to wrap the services (%q)", err, want)
		}
	}
}

// Deployment-level mistakes, each of which would make a lookup reach the wrong record or
// none.
func TestParseComposeBaseline_RefusesUnusableDeployments(t *testing.T) {
	svc := entry("a", nil, "restart: always")
	other := "0x" + strings.Repeat("3", 40)
	for _, tc := range []struct {
		name string
		deps []map[string]any
		says string
	}{
		{"no name", []map[string]any{deployment("", testContract, []string{testProvider}, svc)}, "name is required"},
		{"name twice", []map[string]any{
			deployment("d", testContract, []string{testProvider}, svc),
			deployment("d", testContract, []string{other}, svc),
		}, "listed twice"},
		{"contract not an address", []map[string]any{deployment("d", "0xcontract", []string{testProvider}, svc)}, "not a 0x-prefixed"},
		{"provider not an address", []map[string]any{deployment("d", testContract, []string{"0x12"}, svc)}, "not a 0x-prefixed"},
		{"no providers", []map[string]any{deployment("d", testContract, nil, svc)}, "providers is required"},
		{"no services", []map[string]any{deployment("d", testContract, []string{testProvider})}, "services is required"},
		// The same provider in two deployments would make the comparison depend on which
		// the lookup reached first. Case-insensitive, since that is how lookup compares.
		{"one provider in two deployments", []map[string]any{
			deployment("d1", testContract, []string{testProvider}, svc),
			deployment("d2", testContract, []string{strings.ToLower(testProvider)}, svc),
		}, "listed in both"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseComposeBaseline(deploymentsJSON(t, tc.deps...))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.says)
			}
		})
	}

	// One provider on two CONTRACTS is two keys, not a conflict: that is the testnet and
	// mainnet case the contract is in the key for.
	if _, err := ParseComposeBaseline(deploymentsJSON(t,
		deployment("main", testContract, []string{testProvider}, svc),
		deployment("test", other, []string{testProvider}, svc),
	)); err != nil {
		t.Fatalf("one provider on two contracts was refused: %v", err)
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

// The attack the top-level comparison exists for, on the real testnet manifest: every
// service block untouched, one volume declaration changed. The ingress's TLS key now lives
// on an NFS export the provider controls, and a baseline of service blocks alone matched
// all eleven services and passed.
func TestCheckCompose_TopLevelSections(t *testing.T) {
	b, err := BuiltinComposeBaseline()
	if err != nil {
		t.Fatal(err)
	}
	rels := fleetReleases
	var ac map[string]any
	raw, err := os.ReadFile(filepath.Join("testdata", "testnet-app-compose.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &ac); err != nil {
		t.Fatal(err)
	}
	real := ac["docker_compose_file"].(string)
	check := func(t *testing.T, doc string) ComposeCheck {
		t.Helper()
		r := reviewOf(t, manifest(doc))
		return CheckCompose(b, rels, testnetContract, testnetProvider, r.Blocks, r.TopLevel)
	}
	edit := func(t *testing.T, old, new string) string {
		t.Helper()
		if !strings.Contains(real, old) {
			t.Fatalf("the testnet manifest has no %q", old)
		}
		return strings.Replace(real, old, new, 1)
	}

	// The premise: the manifest, as it is, matches in full.
	if got := check(t, real); !got.OK() || got.TopMatched != 2 {
		t.Fatalf("the unedited manifest does not match:\n%s", dumpMismatches(got))
	}

	for _, tc := range []struct{ name, doc, where, says string }{
		{"a volume moved onto NFS",
			edit(t, "  testnet-cert-data:\n", "  testnet-cert-data:\n    driver_opts: {type: nfs, o: \"addr=203.0.113.7\", device: \":/x\"}\n"),
			"top-level volumes", "differs"},
		{"a volume made external",
			edit(t, "  testnet-mysql-data:\n", "  testnet-mysql-data:\n    external: true\n"),
			"top-level volumes", "differs"},
		{"the network made external",
			edit(t, "    external: false\n", "    external: true\n"),
			"top-level networks", "differs"},
		{"a section nobody recorded",
			edit(t, "\nnetworks:\n", "\nsecrets:\n  s: {file: /etc/shadow}\nnetworks:\n"),
			"top-level secrets", "does not record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := check(t, tc.doc)
			if got.OK() {
				t.Fatal("matched")
			}
			if got.Matched != 11 {
				t.Fatalf("the premise: every service block still matches (%d of 11)", got.Matched)
			}
			requireMismatch(t, got, tc.where, tc.says)
		})
	}

	t.Run("a recorded section removed", func(t *testing.T) {
		var top []TopLevelBlock
		for _, tl := range reviewTestnet(t).TopLevel {
			if tl.Key != "networks" {
				top = append(top, tl)
			}
		}
		got := CheckCompose(b, rels, testnetContract, testnetProvider, reviewTestnet(t).Blocks, top)
		requireMismatch(t, got, "top-level networks", "does not have it")
	})

	// Extension fields run nothing, and their anchors are already inside the services.
	t.Run("an x- section is not compared", func(t *testing.T) {
		if got := check(t, "x-note: {a: 1}\n"+real); !got.OK() {
			t.Fatalf("an extension field was compared:\n%s", dumpMismatches(got))
		}
	})
}

func TestParseComposeBaseline_TopLevel(t *testing.T) {
	svc := entry("a", nil, "restart: always")
	withTop := func(top ...map[string]any) []byte {
		d := deployment("d", testContract, []string{testProvider}, svc)
		d["top_level"] = top
		return deploymentsJSON(t, d)
	}
	got, err := ParseComposeBaseline(withTop(map[string]any{"key": "volumes", "block": []string{"data:", "logs: {}"}}))
	if err != nil {
		t.Fatal(err)
	}
	if tl := got.Deployments[0].TopLevel; len(tl) != 1 || tl[0].Key != "volumes" || !strings.Contains(tl[0].Block, "logs: {}") {
		t.Fatalf("top_level = %+v", tl)
	}
	for _, tc := range []struct {
		name string
		top  []map[string]any
		says string
	}{
		{"no key", []map[string]any{{"block": []string{"a:"}}}, "key is required"},
		{"services", []map[string]any{{"key": "services", "block": []string{"a:"}}}, "per service"},
		{"an extension field", []map[string]any{{"key": "x-a", "block": []string{"a:"}}}, "extension field"},
		{"twice", []map[string]any{{"key": "volumes", "block": []string{"a:"}}, {"key": "volumes", "block": []string{"b:"}}}, "listed twice"},
		{"no block", []map[string]any{{"key": "volumes"}}, "block is required"},
		{"a second document", []map[string]any{{"key": "volumes", "block": []string{"a:", "---", "b:"}}}, "does not reduce"},
		{"a key misspelled", []map[string]any{{"key": "volumes", "blocks": []string{"a:"}}}, "unknown field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseComposeBaseline(withTop(tc.top...))
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.says)
			}
		})
	}
}
