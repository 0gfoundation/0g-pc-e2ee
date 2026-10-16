package evidence

// composebaseline.go compares an authenticated manifest against the recorded
// per-service baseline. This is the check that ADJUDICATES — the one composereview.go
// exists to help write and deliberately is not.
//
// The difference matters enough to keep the two files apart. A review finding is a
// heuristic about a manifest we did not write, and wiring a heuristic to a refusal takes
// a provider offline for being unusual. A baseline mismatch is not a heuristic: it says
// the manifest is not the one that was reviewed and recorded, which is a fact, and the
// only thing a verifier can act on without second-guessing itself. So the two never share
// a type — ComposeMismatch is not a Finding, and no severity is attached to it, because
// there is nothing to rank: either the deployment is what we approved or it is not.
//
// The shape follows OSImageCheck (Configured / OK / an unconfigured check is OK but must
// be disclosed), because it answers the same question one layer down and an operator
// reading a report should not have to learn a second vocabulary for it — with one layer
// OSImageCheck does not need. A fleet runs several deployments, so a baseline records
// several, each keyed by the providers that run it; and a provider with NO recorded
// deployment is a third state beside "matches" and "differs". It is reported as not
// compared, never as a failure: a deployment nobody reviewed is unverified, not refuted,
// and treating the two alike made six healthy providers out of seven exit 1 on the
// 2026-10-10 sweep for the sole reason that nobody had recorded them yet.

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
)

// brokercompose.json holds the per-service baseline. EMBEDDED rather than read from a
// path, for the reason osimages.json states: a verifier needs no configuration and
// cannot be pointed at a friendlier baseline by accident. Reviewing the values is
// reviewing this repository.
//
//go:embed brokercompose.json
var composeBaselineFS embed.FS

// BaselineService is one service a provider's manifest must contain, exactly as
// recorded.
type BaselineService struct {
	// Name is the compose service key. The baseline is keyed by it, which is why a
	// renamed service is a mismatch rather than a silent pass.
	Name string
	// Block is the recorded canonical text, already reduced. Compared against the
	// observed block's image-held-out form when Image allows the image to move, and
	// against its full form otherwise — see CheckCompose.
	Block string
	// Image is how much the image is allowed to move. A ZERO VALUE means the recorded
	// Block above pins it as written — a digest, a bare tag, or no image at all,
	// whichever the recorded text says — which is how every service stands except the
	// ones running 0G's own broker image, whose release cadence is the one case a
	// recorded text cannot express. See ImageRule.
	Image ImageRule
}

// Deployment is one recorded deployment: the services its manifest must contain, and
// the providers that run it.
//
// Keyed by provider ADDRESS and the CONTRACT that registers it, not by compose_hash.
// compose_hash moves on any edit to the app-compose, including ones that change nothing
// about what runs (cn-1 and cn-4 differ only in the app-compose `name`, and their
// service blocks are byte-identical), and a key that moves on every edit would make the
// baseline describe the edit history rather than the deployment. The contract is part
// of the key because an operator may reuse one key on testnet and mainnet, and the same
// address can then run two different deployments.
type Deployment struct {
	// Name labels the deployment in reports. Unique within a baseline.
	Name string
	// Contract is the InferenceServing contract the providers are registered on,
	// lowercased.
	Contract string
	// Providers are the provider addresses that run this deployment, lowercased. More
	// than one when several registrations share an enclave (cn-39 and cn-40 are one
	// CVM) or share an identical manifest.
	Providers []string
	// Services is the recorded manifest, one entry per compose service.
	Services []BaselineService
	// TopLevel is the recorded top-level sections — volumes, networks, and any other key
	// besides services and `x-` extensions — each compared byte-exact like a service with
	// no image rule. Empty means the manifest may have none: a section nobody recorded is
	// a mismatch, never a pass (see TopLevelBlock for why the sections matter).
	TopLevel []BaselineTopLevel
}

// BaselineTopLevel is one recorded top-level section.
type BaselineTopLevel struct {
	// Key is the top-level key.
	Key string
	// Block is the recorded canonical text of its value.
	Block string
}

// ComposeBaseline is every recorded deployment.
type ComposeBaseline struct {
	Deployments []Deployment
}

// For returns the deployment recorded for a provider on a contract. Addresses compare
// case-insensitively, since the chain and the operator may spell them in EIP-55 or in
// lowercase.
func (b ComposeBaseline) For(contract, provider string) (Deployment, bool) {
	c, p := normAddr(contract), normAddr(provider)
	for _, d := range b.Deployments {
		if d.Contract != c {
			continue
		}
		for _, x := range d.Providers {
			if x == p {
				return d, true
			}
		}
	}
	return Deployment{}, false
}

// ImageRule is how much an image is allowed to move, and it has exactly one setting
// because the recorded block does the rest of the work.
//
// The first draft had three — an exact digest, a repository, and a literal reference —
// and writing the tests showed two of them did nothing. The block a `digest` or
// `reference` rule is compared against is the FULL canonical form, image line included,
// so the reference is already pinned exactly by the text; the rule could only restate
// it. Worse, it could restate it WRONGLY: nothing stopped an entry from recording a
// block naming one digest and a rule naming another, and the block comparison would fail
// first with a message about the wrong thing. A redundancy that can disagree with itself
// is not documentation.
//
// So: an unset rule means the block pins the image exactly as written — a digest, a bare
// tag, or no image at all, whichever the recorded text says. Repository is the one case
// the text cannot express.
type ImageRule struct {
	// Repository accepts any RELEASED build of this repository — a digest the caller's
	// ReleaseVerifier accepts (brokerrelease.go) — and switches the block comparison to
	// the image-held-out form so the reference is not pinned twice.
	//
	// It exists for one case: an image whose release cadence would otherwise force a
	// gateway release per broker release. Every deployment runs 0G's own broker image in
	// three services, and it moves on every broker ship. It first accepted any
	// digest-pinned image in the repository, which turned out to be no bound at all: of the
	// four broker digests the 2026-10-10 sweep found, two were pointed at by no release tag
	// when the registry was checked on 2026-10-15. The release verifier is the bound.
	Repository string
}

// pinsImageInBlock reports whether the recorded block is the one that pins the image,
// which is every case except a repository rule.
func (r ImageRule) pinsImageInBlock() bool { return r.Repository == "" }

// composeBaselineFile is the on-disk shape of brokercompose.json. Block arrives as an
// array of lines because a JSON string with embedded newlines is unreadable and
// undiffable, and the entire argument for storing text rather than a digest was that a
// human can review it.
//
// Every key the file may carry is declared here, INCLUDING the two this code never reads,
// because the decode rejects unknown fields (see ParseComposeBaseline). Prose lives in the
// file itself rather than only in this package: an author editing a baseline is reading
// JSON, not Go.
type composeBaselineFile struct {
	// Comment is the file's own header. Declared so the decode can reject unknown keys
	// while the file keeps explaining itself; never read.
	Comment     []string         `json:"_comment"`
	Deployments []deploymentFile `json:"deployments"`
	// Services at the TOP level is the format before deployments existed. Declared only
	// so a file in that shape is refused with directions rather than with "unknown
	// field": candidates written against the old format are in people's hands, and the
	// fix is mechanical once someone says what it is.
	Services json.RawMessage `json:"services"`
}

type deploymentFile struct {
	Name string `json:"name"`
	// Note is the audit record for the deployment as a whole; never read.
	Note      []string              `json:"note"`
	Contract  string                `json:"contract"`
	Providers []string              `json:"providers"`
	Services  []baselineServiceFile `json:"services"`
	TopLevel  []topLevelFile        `json:"top_level"`
}

type topLevelFile struct {
	Key string `json:"key"`
	// Note is the audit record for the section; never read.
	Note  []string `json:"note"`
	Block []string `json:"block"`
}

type baselineServiceFile struct {
	Name string `json:"name"`
	// Note is the audit record for one entry — why it is recorded as it stands, and
	// what the review says about it. Declared, never read: a justification that
	// changed the comparison would be a rule, and rules belong in code where they can
	// be tested. It sits next to the entry rather than in the header so a renamed or
	// deleted service takes its justification with it.
	Note  []string `json:"note"`
	Block []string `json:"block"`
	Image *struct {
		Repository string `json:"repository"`
		// Accepted only to be REJECTED with an explanation. An author reaching for
		// these has a reasonable model of the format that this one does not use, and
		// silently ignoring an unknown key would give them a baseline that pins less
		// than they wrote.
		Digest    string `json:"digest"`
		Reference string `json:"reference"`
	} `json:"image"`
}

// BuiltinComposeBaseline returns the embedded baseline. An error means the embedded file
// is malformed, which is a build-time mistake in this repository rather than anything
// about the deployment being verified — callers must surface it rather than degrade to
// "not configured", which would silently drop the check.
func BuiltinComposeBaseline() (ComposeBaseline, error) {
	const file = "brokercompose.json"
	raw, err := composeBaselineFS.ReadFile(file)
	if err != nil {
		return ComposeBaseline{}, fmt.Errorf("read embedded compose baseline: %w", err)
	}
	b, err := ParseComposeBaseline(raw)
	if err != nil {
		return ComposeBaseline{}, fmt.Errorf("%s: %w", file, err)
	}
	return b, nil
}

// ParseComposeBaseline decodes a baseline, REDUCING each recorded block through the same
// canonicalizer the observed side goes through.
//
// Reducing at load is what makes the stored text immune to the linked yaml.v3's
// formatting preferences: both sides pass through CanonicalizeServiceBlock in the same
// process, so whatever that library's indent or quoting choices are, they apply equally.
// It is also what lets an entry be hand-edited — re-indented, re-quoted, a comment added
// — without breaking the match.
//
// UNKNOWN KEYS ARE REFUSED, which matters most for the one that is easiest to mistype.
// A file whose top-level key reads "servcies" decodes cleanly into zero entries under a
// permissive decoder, and zero entries means NOT CONFIGURED — so a typo would silently
// turn the adjudicating check off and every report would say the comparison did not run,
// which is a sentence nobody reads twice. The same holds one level down: "blocks" for
// "block", or an image rule spelled "repo". A baseline that pins less than its author
// wrote is the one failure mode this format cannot tolerate, since the whole file exists
// to be trusted without being re-derived.
func ParseComposeBaseline(raw []byte) (ComposeBaseline, error) {
	var f composeBaselineFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return ComposeBaseline{}, fmt.Errorf("compose baseline is not valid JSON: %w", err)
	}
	// A Decoder stops at the end of the first value, where json.Unmarshal would have
	// rejected what followed. Restore that: a second object in the file means the
	// author's edits may be sitting in the half nothing decoded.
	if dec.More() {
		return ComposeBaseline{}, fmt.Errorf("compose baseline is not valid JSON: trailing content after the first object")
	}
	if f.Services != nil {
		return ComposeBaseline{}, fmt.Errorf("compose baseline has a top-level \"services\" list, which is " +
			"the format before deployments existed. Wrap it: {\"deployments\": [{\"name\": ..., " +
			"\"contract\": \"0x...\", \"providers\": [\"0x...\"], \"services\": [...]}]} — a recorded " +
			"manifest has to say which providers run it")
	}

	var out ComposeBaseline
	names := map[string]bool{}
	owner := map[string]string{} // contract/provider -> deployment name
	for i, d := range f.Deployments {
		label := strings.TrimSpace(d.Name)
		if label == "" {
			return ComposeBaseline{}, fmt.Errorf("compose baseline deployment %d: name is required", i+1)
		}
		if names[label] {
			return ComposeBaseline{}, fmt.Errorf("compose baseline: deployment %q is listed twice", label)
		}
		names[label] = true

		dep := Deployment{Name: label}
		if !isAddress(d.Contract) {
			return ComposeBaseline{}, fmt.Errorf("compose baseline deployment %q: contract %q is not a "+
				"0x-prefixed 20-byte address", label, d.Contract)
		}
		dep.Contract = normAddr(d.Contract)
		if len(d.Providers) == 0 {
			return ComposeBaseline{}, fmt.Errorf("compose baseline deployment %q: providers is required; a "+
				"deployment no provider runs can never be compared", label)
		}
		for _, p := range d.Providers {
			if !isAddress(p) {
				return ComposeBaseline{}, fmt.Errorf("compose baseline deployment %q: provider %q is not a "+
					"0x-prefixed 20-byte address", label, p)
			}
			key := dep.Contract + "/" + normAddr(p)
			if prev, ok := owner[key]; ok {
				// One provider in two deployments would make the comparison depend on
				// which one the lookup reached first.
				return ComposeBaseline{}, fmt.Errorf("compose baseline: provider %s on contract %s is listed "+
					"in both %q and %q", p, d.Contract, prev, label)
			}
			owner[key] = label
			dep.Providers = append(dep.Providers, normAddr(p))
		}
		if len(d.Services) == 0 {
			return ComposeBaseline{}, fmt.Errorf("compose baseline deployment %q: services is required", label)
		}
		svcs, err := parseServices(label, d.Services)
		if err != nil {
			return ComposeBaseline{}, err
		}
		dep.Services = svcs
		if dep.TopLevel, err = parseTopLevel(label, d.TopLevel); err != nil {
			return ComposeBaseline{}, err
		}
		out.Deployments = append(out.Deployments, dep)
	}
	return out, nil
}

// parseServices validates and reduces one deployment's services.
func parseServices(deployment string, entries []baselineServiceFile) ([]BaselineService, error) {
	out := make([]BaselineService, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for i, e := range entries {
		label := e.Name
		if label == "" {
			label = fmt.Sprintf("entry %d", i+1)
		}
		label = deployment + "/" + label
		if strings.TrimSpace(e.Name) == "" {
			return nil, fmt.Errorf("compose baseline %s: name is required", label)
		}
		if seen[e.Name] {
			// Two entries for one service would make the match depend on which one the
			// comparison happened to reach.
			return nil, fmt.Errorf("compose baseline: %s is listed twice", label)
		}
		seen[e.Name] = true

		svc := BaselineService{Name: e.Name}
		if len(e.Block) == 0 {
			return nil, fmt.Errorf("compose baseline %s: block is required; an entry with no "+
				"recorded text would accept any body for this service", label)
		}
		block, err := CanonicalizeServiceBlock([]byte(strings.Join(e.Block, "\n") + "\n"))
		if err != nil {
			return nil, fmt.Errorf("compose baseline %s: block does not reduce: %w", label, err)
		}
		svc.Block = block

		if e.Image != nil {
			svc.Image = ImageRule{Repository: strings.TrimSpace(e.Image.Repository)}
			switch {
			case strings.TrimSpace(e.Image.Digest) != "" || strings.TrimSpace(e.Image.Reference) != "":
				return nil, fmt.Errorf("compose baseline %s: image sets digest or reference, which this "+
					"format does not have — the recorded block already contains the image line and pins "+
					"the reference exactly. Use image.repository only to let the image MOVE between "+
					"released builds, and record the image-held-out block for it", label)
			case svc.Image.Repository == "":
				return nil, fmt.Errorf("compose baseline %s: image is present but states no repository; "+
					"omit it entirely to let the block pin the image", label)
			}
		}
		out = append(out, svc)
	}
	return out, nil
}

// parseTopLevel validates and reduces one deployment's top-level sections.
func parseTopLevel(deployment string, entries []topLevelFile) ([]BaselineTopLevel, error) {
	out := make([]BaselineTopLevel, 0, len(entries))
	seen := map[string]bool{}
	for i, e := range entries {
		key := strings.TrimSpace(e.Key)
		label := fmt.Sprintf("%s/top_level %d", deployment, i+1)
		switch {
		case key == "":
			return nil, fmt.Errorf("compose baseline %s: key is required", label)
		case key == "services":
			return nil, fmt.Errorf("compose baseline %s: services is recorded per service, under services", label)
		case strings.HasPrefix(key, "x-"):
			return nil, fmt.Errorf("compose baseline %s: %s is an extension field, which is not compared — "+
				"its anchors are already expanded into the services that use them", label, key)
		case seen[key]:
			return nil, fmt.Errorf("compose baseline %s: %s is listed twice", label, key)
		case len(e.Block) == 0:
			return nil, fmt.Errorf("compose baseline %s: block is required; a section with no recorded text "+
				"would accept any declaration", label)
		}
		seen[key] = true
		block, err := canonicalizeText([]byte(strings.Join(e.Block, "\n")+"\n"), "the top-level "+key+" section")
		if err != nil {
			return nil, fmt.Errorf("compose baseline %s: block does not reduce: %w", label, err)
		}
		out = append(out, BaselineTopLevel{Key: key, Block: block})
	}
	return out, nil
}

// isAddress reports whether s is a 0x-prefixed 20-byte hex address, in any case.
func isAddress(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// normAddr is the comparison form of an address.
func normAddr(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ComposeMismatch is one reason a manifest is not the baseline.
type ComposeMismatch struct {
	// Service is the compose service, or "" for a mismatch about the manifest as a
	// whole.
	Service string
	// Reason says what differs, in terms of what an operator would change.
	Reason string
	// Diff names the first differing line when a recorded block did not match, since
	// "the block differs" is unactionable on a twenty-line block.
	Diff string
}

// ComposeCheck is the result of comparing an authenticated manifest against the baseline.
type ComposeCheck struct {
	// Configured reports whether the baseline held any deployment. When false the
	// comparison did not run: the claim it grounds is unavailable, not refuted — so it
	// does not fail a report, but every summary must say so. Enforce mode treats it as a
	// refusal naming the unfinished configuration, the same way an unconfigured
	// boot-chain allowlist does.
	Configured bool
	// Recorded reports whether a deployment is recorded for this provider. When false
	// (with Configured) the comparison did not run either, for the same reason and with
	// the same consequence: nobody reviewed this deployment, which is not the same claim
	// as "this deployment differs from the one we reviewed".
	Recorded bool
	// Deployment names the recorded deployment the manifest was compared against.
	Deployment string
	// Expected counts the services that deployment records.
	Expected int
	// Mismatches is why the manifest is not the recorded deployment. Empty, with
	// Compared, means it is.
	Mismatches []ComposeMismatch
	// Matched counts the services that matched, so a report can say "9 of 12" rather
	// than only listing what went wrong.
	Matched int
	// TopExpected and TopMatched are the same two counts for the top-level sections.
	TopExpected, TopMatched int
	// Unverified lists the services whose block matched but whose broker build could not
	// be checked against the release verifier (ReleaseUnavailable). Neither a match nor a
	// mismatch: the comparison is incomplete, which a report must say and a gate must not
	// read as a pass.
	Unverified []ComposeMismatch
}

// Compared reports whether a comparison actually ran.
func (c ComposeCheck) Compared() bool { return c.Configured && c.Recorded }

// Complete reports whether every recorded service could be judged — false when a broker
// build's release status could not be checked.
func (c ComposeCheck) Complete() bool { return len(c.Unverified) == 0 }

// OK reports whether the manifest is acceptable. A comparison that did not run is OK:
// the check is unavailable, and the caller's summary is where that is disclosed.
func (c ComposeCheck) OK() bool { return !c.Compared() || len(c.Mismatches) == 0 }

// CheckCompose compares an authenticated manifest's blocks against the baseline.
//
// blocks must come from ComposeReview.Blocks — i.e. from bytes that passed the
// compose_hash gate. Comparing provider-chosen YAML against a baseline would be
// theatre.
//
// EVERY DIRECTION IS CHECKED, and the third one is the one worth stating: a service the
// baseline does not mention is a mismatch, not an omission. An unlisted container runs in
// the same guest as the reviewed ones, with whatever the manifest gives it, so "ignore
// what we did not think of" is how a baseline becomes decoration. The other two are
// symmetric — a listed service that is absent is a different deployment (dropping the
// controller that holds the guest-agent socket changes what the CVM does), and a service
// present twice makes what runs depend on how the runtime resolves a duplicate key.
//
// The provider's deployment is looked up by contract and provider address first. None
// recorded is reported as not compared rather than as a mismatch against some other
// deployment: comparing cn-1 against cn-20's record would list twelve differences that
// say nothing except that nobody recorded cn-1.
//
// rels bounds the `repository` rule: a service under it matches only when rels accepts
// its digest as a release. A build rels could not check lands in Unverified, not in
// Mismatches; a nil rels is a verifier that can check nothing.
//
// top is ComposeReview.TopLevel, compared the same way in every direction: a recorded
// section must be present and identical, and a section the deployment does not record is
// a mismatch — it is where a service's volumes and networks get their meaning.
func CheckCompose(b ComposeBaseline, rels ReleaseVerifier, contract, provider string, blocks []ServiceBlock,
	top []TopLevelBlock) ComposeCheck {
	out := ComposeCheck{Configured: len(b.Deployments) > 0}
	if !out.Configured {
		return out
	}
	dep, ok := b.For(contract, provider)
	if !ok {
		return out
	}
	out.Recorded, out.Deployment, out.Expected = true, dep.Name, len(dep.Services)
	baseline := dep.Services

	// Observed services by name, and the duplicates, in one pass. Blocks from a manifest
	// cannot repeat a name — docker compose's decoder refuses a duplicate key, and so does
	// the review, which then produces no blocks at all. The check stays because blocks is
	// this function's input, not the review's output: a caller assembling it some other
	// way gets a mismatch rather than a lookup that silently keeps one of the two.
	observed := make(map[string]ServiceBlock, len(blocks))
	dupes := map[string]bool{}
	for _, b := range blocks {
		if _, ok := observed[b.Name]; ok {
			dupes[b.Name] = true
			continue
		}
		observed[b.Name] = b
	}
	for _, name := range sortedBoolKeys(dupes) {
		out.add(name, "the manifest declares this service more than once, so what runs depends on "+
			"how the runtime resolves a duplicate key rather than on the manifest", "")
	}

	inBaseline := make(map[string]bool, len(baseline))
	for _, want := range baseline {
		inBaseline[want.Name] = true
		got, present := observed[want.Name]
		if !present {
			out.add(want.Name, "the baseline records this service but the manifest does not declare it", "")
			continue
		}
		before, unverified := len(out.Mismatches), len(out.Unverified)
		out.checkService(want, got, rels)
		if len(out.Mismatches) == before && len(out.Unverified) == unverified {
			out.Matched++
		}
	}

	for _, b := range blocks {
		if !inBaseline[b.Name] {
			out.add(b.Name, "the manifest declares this service but the baseline does not record it, "+
				"so it runs in the same guest as the reviewed containers without having been reviewed", "")
		}
	}
	out.checkTopLevel(dep.TopLevel, top)
	return out
}

// checkTopLevel compares the top-level sections, in every direction.
func (c *ComposeCheck) checkTopLevel(want []BaselineTopLevel, got []TopLevelBlock) {
	c.TopExpected = len(want)
	observed := make(map[string]TopLevelBlock, len(got))
	for _, g := range got {
		observed[g.Key] = g
	}
	recorded := make(map[string]bool, len(want))
	for _, w := range want {
		recorded[w.Key] = true
		where := "top-level " + w.Key
		g, ok := observed[w.Key]
		switch {
		case !ok:
			c.add(where, "the baseline records this section but the manifest does not have it", "")
		case g.Err != nil:
			c.add(where, fmt.Sprintf("the section has no canonical form, so it cannot be compared: %v", g.Err), "")
		case g.Canonical != w.Block:
			c.add(where, "the section differs from the baseline, so what the services' volumes or networks "+
				"resolve to is not what was reviewed", firstDiff(w.Block, g.Canonical))
		default:
			c.TopMatched++
		}
	}
	for _, g := range got {
		if !recorded[g.Key] {
			c.add("top-level "+g.Key, "the manifest has this section but the baseline does not record it, so "+
				"what it declares was never reviewed", "")
		}
	}
}

// checkService compares one observed block against its baseline entry.
func (c *ComposeCheck) checkService(want BaselineService, got ServiceBlock, rels ReleaseVerifier) {
	if !got.Pinnable() {
		c.add(want.Name, fmt.Sprintf("the service has no canonical form, so it cannot be compared: %v", got.Err), "")
		return
	}

	// Which observed form the recorded text is compared against follows from the image
	// rule, and the two must agree: a repository rule lets the image move, so the block
	// it pins is the image-held-out one; a digest rule pins the image exactly, so the
	// whole block including the reference is the thing recorded.
	observed := got.Canonical
	if !want.Image.pinsImageInBlock() {
		observed = got.CanonicalNoImage
	}
	if observed != want.Block {
		c.add(want.Name, "the service block differs from the baseline", firstDiff(want.Block, observed))
		return
	}
	c.checkImage(want, got, rels)
}

// checkImage applies the image rule, which only a repository rule has: every other case
// is already settled by the block comparison, which included the image line.
func (c *ComposeCheck) checkImage(want BaselineService, got ServiceBlock, rels ReleaseVerifier) {
	if want.Image.pinsImageInBlock() {
		return
	}
	repo, _, digest := compose.SplitImageRef(got.ImageRef)
	switch {
	case !isDigestShaped(digest):
		// The rule accepts a release ONLY when it is pinned by content. Without that it
		// accepts a tag, whose contents the registry can republish after the measurement,
		// so "a release of our repository" would mean "whatever is there now".
		c.add(want.Name, fmt.Sprintf("the image is %s; the baseline accepts a released build of %s, "+
			"which has to be pinned by digest", describeRef(got.ImageRef), want.Image.Repository), "")
	case repo != want.Image.Repository:
		c.add(want.Name, fmt.Sprintf("the image is in %s; the baseline accepts only %s",
			repo, want.Image.Repository), "")
	case rels != nil && rels.Repository() != want.Image.Repository:
		c.add(want.Name, fmt.Sprintf("the baseline accepts released builds of %s, but the release verifier "+
			"judges %s, so no build of it can be accepted", want.Image.Repository, describeRepo(rels.Repository())), "")
	default:
		switch v := verifyRelease(rels, repo, digest); v.Status {
		case ReleaseAccepted:
		case ReleaseUnavailable:
			c.Unverified = append(c.Unverified, ComposeMismatch{Service: want.Name, Reason: fmt.Sprintf(
				"whether %s@%s is a release could not be checked: %s", repo, shortDigest(digest), v.Reason)})
		default:
			c.add(want.Name, fmt.Sprintf("the image is %s@%s, which is not an accepted release of %s: %s",
				repo, shortDigest(digest), repo, v.Reason), "")
		}
	}
}

// describeRepo names a repository for a mismatch line, saying plainly when there is none.
func describeRepo(r string) string {
	if r == "" {
		return "no repository"
	}
	return r
}

// shortDigest abbreviates a digest for a report line; the full value is in the
// fingerprint section of the same report.
func shortDigest(d string) string {
	if len(d) > len("sha256:")+12 {
		return d[:len("sha256:")+12] + "…"
	}
	return d
}

func (c *ComposeCheck) add(service, reason, diff string) {
	c.Mismatches = append(c.Mismatches, ComposeMismatch{Service: service, Reason: reason, Diff: diff})
}

// describeRef renders a reference for a mismatch line, saying plainly when there is none.
func describeRef(ref string) string {
	if strings.TrimSpace(ref) == "" {
		return "absent"
	}
	return ref
}

// firstDiff names the first line where the recorded and observed blocks differ, plus the
// line counts. Same shape diffComposeFile produces for the gateway's own manifest, and
// for the same reason: "the block differs" is unactionable on a twenty-line block.
func firstDiff(want, got string) string {
	w, g := strings.Split(strings.TrimRight(want, "\n"), "\n"), strings.Split(strings.TrimRight(got, "\n"), "\n")
	for i := 0; i < len(w) && i < len(g); i++ {
		if w[i] != g[i] {
			return fmt.Sprintf("line %d:\n      deployed: %s\n      baseline: %s", i+1, truncate(g[i]), truncate(w[i]))
		}
	}
	switch {
	case len(g) > len(w):
		return fmt.Sprintf("deployed has %d extra line(s) after line %d, first: %s",
			len(g)-len(w), len(w), truncate(g[len(w)]))
	case len(w) > len(g):
		return fmt.Sprintf("deployed is missing %d line(s) after line %d, first expected: %s",
			len(w)-len(g), len(g), truncate(w[len(g)]))
	}
	return "" // equal line by line; unreachable when the texts differ
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
