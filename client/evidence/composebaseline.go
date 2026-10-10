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
// The shape follows OSImageCheck exactly (Configured / OK / an unconfigured check is OK
// but must be disclosed), because it answers the same question one layer down and an
// operator reading a report should not have to learn a second vocabulary for it.

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
	// whichever the recorded text says — which is how nine of the twelve recorded
	// services stand; the other three run 0G's own broker image, whose release cadence
	// is the one case a recorded text cannot express. See ImageRule.
	Image ImageRule
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
	// Repository accepts any DIGEST-PINNED image in this repository, and switches the
	// block comparison to the image-held-out form so the reference is not pinned twice.
	//
	// It exists for one case: an image whose release cadence would otherwise force a
	// gateway release per broker release. cn-20 runs 0G's own broker image in three
	// services, and it moves on every broker ship. It knowingly accepts an older official
	// build — a risk taken deliberately, to be closed by a denylist later.
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
	Comment  []string `json:"_comment"`
	Services []struct {
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
	} `json:"services"`
}

// BuiltinComposeBaseline returns the embedded baseline. An error means the embedded file
// is malformed, which is a build-time mistake in this repository rather than anything
// about the deployment being verified — callers must surface it rather than degrade to
// "not configured", which would silently drop the check.
func BuiltinComposeBaseline() ([]BaselineService, error) {
	const file = "brokercompose.json"
	raw, err := composeBaselineFS.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read embedded compose baseline: %w", err)
	}
	svcs, err := ParseComposeBaseline(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return svcs, nil
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
func ParseComposeBaseline(raw []byte) ([]BaselineService, error) {
	var f composeBaselineFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("compose baseline is not valid JSON: %w", err)
	}
	// A Decoder stops at the end of the first value, where json.Unmarshal would have
	// rejected what followed. Restore that: a second object in the file means the
	// author's edits may be sitting in the half nothing decoded.
	if dec.More() {
		return nil, fmt.Errorf("compose baseline is not valid JSON: trailing content after the first object")
	}
	out := make([]BaselineService, 0, len(f.Services))
	seen := make(map[string]bool, len(f.Services))
	for i, e := range f.Services {
		label := e.Name
		if label == "" {
			label = fmt.Sprintf("entry %d", i+1)
		}
		if strings.TrimSpace(e.Name) == "" {
			return nil, fmt.Errorf("compose baseline %s: name is required", label)
		}
		if seen[e.Name] {
			// Two entries for one service would make the match depend on which one the
			// comparison happened to reach.
			return nil, fmt.Errorf("compose baseline: %s is listed twice", e.Name)
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
					"the reference exactly. Use image.repository only to let the image MOVE within a "+
					"repository, and record the image-held-out block for it", label)
			case svc.Image.Repository == "":
				return nil, fmt.Errorf("compose baseline %s: image is present but states no repository; "+
					"omit it entirely to let the block pin the image", label)
			}
		}
		out = append(out, svc)
	}
	return out, nil
}

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
	// Configured reports whether the baseline held any entry. When false the comparison
	// did not run: the claim it grounds is unavailable, not refuted — so it does not fail
	// a report, but every summary must say so. Enforce mode treats it as a refusal
	// naming the unfinished configuration, the same way an unconfigured boot-chain
	// allowlist does.
	Configured bool
	// Mismatches is why the manifest is not the baseline. Empty, with Configured, means
	// it is.
	Mismatches []ComposeMismatch
	// Matched counts the services that matched, so a report can say "9 of 12" rather
	// than only listing what went wrong.
	Matched int
}

// OK reports whether the manifest is acceptable. An unconfigured baseline is OK: the
// check is unavailable, and the caller's summary is where that is disclosed.
func (c ComposeCheck) OK() bool { return !c.Configured || len(c.Mismatches) == 0 }

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
func CheckCompose(baseline []BaselineService, blocks []ServiceBlock) ComposeCheck {
	out := ComposeCheck{Configured: len(baseline) > 0}
	if !out.Configured {
		return out
	}

	// Observed services by name, and the duplicates, in one pass. Blocks arrive in file
	// order and a name may repeat, which is itself a mismatch rather than a lookup
	// problem to be papered over.
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
		before := len(out.Mismatches)
		out.checkService(want, got)
		if len(out.Mismatches) == before {
			out.Matched++
		}
	}

	for _, b := range blocks {
		if !inBaseline[b.Name] {
			out.add(b.Name, "the manifest declares this service but the baseline does not record it, "+
				"so it runs in the same guest as the reviewed containers without having been reviewed", "")
		}
	}
	return out
}

// checkService compares one observed block against its baseline entry.
func (c *ComposeCheck) checkService(want BaselineService, got ServiceBlock) {
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
	c.checkImage(want, got)
}

// checkImage applies the image rule, which only a repository rule has: every other case
// is already settled by the block comparison, which included the image line.
func (c *ComposeCheck) checkImage(want BaselineService, got ServiceBlock) {
	if want.Image.pinsImageInBlock() {
		return
	}
	repo, _, digest := compose.SplitImageRef(got.ImageRef)
	switch {
	case !isDigestShaped(digest):
		// The rule accepts any image in the repository ONLY when it is pinned by content.
		// Without that it accepts a tag, whose contents the registry can republish after
		// the measurement, so "any image in our repository" would mean "whatever is there
		// now".
		c.add(want.Name, fmt.Sprintf("the image is %s; the baseline accepts any image in %s but "+
			"only pinned by digest", describeRef(got.ImageRef), want.Image.Repository), "")
	case repo != want.Image.Repository:
		c.add(want.Name, fmt.Sprintf("the image is in %s; the baseline accepts only %s",
			repo, want.Image.Repository), "")
	}
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
