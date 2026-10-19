package route

// runtimerelease.go judges the broker build a provider's CVM runs NOW, as the RTMR3
// event log records it, against the broker's release policy — the same judgement
// pcverify -provider makes (evidence.CheckRuntime), made here for every provider this
// process verifies a quote from.
//
// WHY. The quote's boot chain (hop 3) pins the OS, and the compose hash pins what
// BOOTED; neither says what runs after boot. On v0.5.4 the controller can swap the
// broker image at runtime, and records each swap in RTMR3 (zg-image-update). Replaying
// the reply's event log to the verified quote's RTMR3 makes those records as good as the
// quote, and the last one names the build serving now.
//
// OBSERVE ONLY. Nothing here changes which provider is used or whether a request is
// sealed: the verdict is recorded (ProviderIdentity.RuntimeRelease), counted, and logged.
// An enforce switch waits on the compose baseline reaching this path too: a provider
// that never swapped has no runtime record, and only the baseline judges what it booted,
// so enforcing this check alone would pass exactly the providers it says nothing about.
//
// OFF THE REQUEST PATH. Reading the runtime state is local and cheap (verifyQuoteAt does
// it with the quote). Judging a build is not — it fetches the build's provenance from
// the registry and verifies it with Sigstore — so it runs in the background, once per
// digest, and a verification that finds no verdict yet records the check as unavailable.
// Records are read through the judge (Router.ProviderIdentity), so a verdict that lands
// after the quote was verified is reported without waiting for the next verification.

import (
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
)

// WithReleaseVerifier makes the Router judge, for every provider whose quote it verifies,
// the broker build the provider's CVM runs now against rels (in the binaries,
// client/provenance). It is meaningful only with WithQuoteVerification: the runtime
// records are read from the quote reply and anchored to the verified quote's RTMR3.
//
// rels is called off the request path, at most maxReleaseChecks at a time and once per
// build until its answer can change (see releaseJudge). nil leaves the check off, and
// every record then reports it as VerdictNotChecked.
func WithReleaseVerifier(rels evidence.ReleaseVerifier, logger *slog.Logger) Option {
	return func(r *Router) {
		if rels == nil {
			return
		}
		if logger == nil {
			logger = slog.Default()
		}
		r.releases = newReleaseJudge(rels, logger)
	}
}

// runtimeFacts is what one quote verification read about the CVM's runtime, kept with
// the other quote facts so a record — and a cache hit — can be judged again later.
type runtimeFacts struct {
	// state is the event log's runtime records, read only after the log replayed to the
	// verified quote's RTMR3; err is set instead when it did not (evidence.ErrNoEventLog
	// for a reply without a log).
	state evidence.RuntimeState
	err   error
	// signer and encPub are the verified report_data's: the running image's record must
	// name the same keys.
	signer string
	encPub []byte
}

// runtimeVerdict is the judgement of one runtimeFacts.
type runtimeVerdict struct {
	verdict Verdict
	// running is repository@digest of the build the last zg-image-update names, or ""
	// when there is none (the manifest's pin runs). release is its version when the
	// build is an accepted release.
	running, release string
	// why says what decided a verdict other than a pass, for the log.
	why []string
}

// judgeRuntime judges f. start says whether a build with no verdict yet may be sent for
// one: true on a verification, false on a read, which never starts work.
//
//   - no_match: a contradiction — the log does not replay to the quote's RTMR3, the build
//     is not an accepted release, its keys are not report_data's, or the controller
//     created containers after launch.
//   - unavailable: a check that did not run — no event log in the reply, records this
//     reader does not know, an upstream set or instance state the controller could not
//     state, or a build whose provenance has not been (or could not be) fetched.
//   - not_checked: nothing to judge here — no runtime image record, so the image the
//     manifest pins is what runs and the compose baseline is what judges it; or this
//     process was not given a release verifier.
//   - pass: the last runtime image record names an accepted release whose keys are
//     report_data's, and nothing above applies.
func (r *Router) judgeRuntime(f runtimeFacts, start bool) runtimeVerdict {
	switch {
	case r.releases == nil:
		v := runtimeVerdict{verdict: VerdictNotChecked}
		if f.err == nil && f.state.Image != nil {
			v.running = f.state.Image.Repository + "@" + f.state.Image.Digest
		}
		return v
	case errors.Is(f.err, evidence.ErrNoEventLog):
		return runtimeVerdict{verdict: VerdictUnavailable, why: []string{"the quote reply carries no event log"}}
	case f.err != nil:
		return runtimeVerdict{verdict: VerdictNoMatch, why: []string{f.err.Error()}}
	}
	c := evidence.CheckRuntime(f.state, judgedReleases{j: r.releases, start: start}, f.signer, f.encPub)
	v := runtimeVerdict{}
	if im := f.state.Image; im != nil {
		v.running = im.Repository + "@" + im.Digest
	}
	switch {
	case len(c.Failures) > 0:
		v.verdict, v.why = VerdictNoMatch, c.Failures
	case len(c.Unverified) > 0:
		v.verdict, v.why = VerdictUnavailable, c.Unverified
	case c.Release == nil:
		v.verdict = VerdictNotChecked
		v.why = []string{"no runtime image record: the image the manifest pins runs, which the compose baseline judges"}
	default:
		v.verdict, v.release = VerdictPass, c.Release.Release.Version
	}
	return v
}

// observeRuntime judges a verification's runtime facts, sending a build with no verdict
// for one, and counts and logs the outcome. It returns nothing: the record is judged
// again when it is read.
func (r *Router) observeRuntime(quoteURL string, f runtimeFacts) {
	v := r.judgeRuntime(f, true)
	metrics.RuntimeRelease(string(v.verdict))
	switch v.verdict {
	case VerdictNoMatch:
		r.logger.Warn("provider's CVM runs a broker build that is not an accepted release, or its runtime records "+
			"contradict its quote (observed, not enforced)",
			"quote_url", quoteURL, "running", v.running, "signer_addr", f.signer, "why", strings.Join(v.why, "; "))
	case VerdictUnavailable:
		r.logger.Debug("provider's runtime release could not be checked",
			"quote_url", quoteURL, "running", v.running, "why", strings.Join(v.why, "; "))
	}
}

// judgedReleases is the evidence.ReleaseVerifier CheckRuntime is handed: it answers from
// the judge's verdicts and never waits for one.
type judgedReleases struct {
	j     *releaseJudge
	start bool
}

func (a judgedReleases) Repository() string { return a.j.rels.Repository() }

// verifier is a as an evidence.ReleaseVerifier, or nil when there is no judge — never an
// interface holding a nil judge, which evidence.VerifyRelease could not tell from one.
func (a judgedReleases) verifier() evidence.ReleaseVerifier {
	if a.j == nil {
		return nil
	}
	return a
}

func (a judgedReleases) Verify(repository, digest string) evidence.ReleaseVerdict {
	if v, ok := a.j.verdict(repository, digest, a.start); ok {
		return v
	}
	return evidence.ReleaseVerdict{Status: evidence.ReleaseUnavailable,
		Reason: "its release provenance has not been checked yet (it is checked in the background)"}
}

// Bounds on the judge, which a provider can exercise: its runtime record names whatever
// digest it writes.
const (
	// maxReleaseChecks is how many builds are judged at once. A build that finds every
	// slot taken is simply asked for again at the next verification.
	maxReleaseChecks = 4
	// maxJudgedReleases bounds the verdicts held. At the bound, verdicts other than
	// acceptances are dropped first; a build that still finds no room is reported
	// unavailable until there is.
	maxJudgedReleases = 1024
	// releaseRecheck is how long a verdict other than an acceptance is reported before it
	// is asked for again. The verifier decides whether asking goes back to the registry
	// (client/provenance keeps a rejection an hour and an outage five minutes); this only
	// bounds how stale a verdict this process reports can be once the verifier's has moved.
	releaseRecheck = time.Minute
)

// releaseJudge holds a verdict per build and fetches the missing ones in the background.
// Safe for concurrent use.
type releaseJudge struct {
	rels   evidence.ReleaseVerifier
	logger *slog.Logger
	now    func() time.Time
	slots  chan struct{}

	mu sync.Mutex
	m  map[string]*judgedRelease
}

type judgedRelease struct {
	verdict evidence.ReleaseVerdict
	have    bool      // verdict holds an answer
	at      time.Time // when it was answered
	running bool      // a check is in flight
}

func newReleaseJudge(rels evidence.ReleaseVerifier, logger *slog.Logger) *releaseJudge {
	return &releaseJudge{rels: rels, logger: logger, now: time.Now,
		slots: make(chan struct{}, maxReleaseChecks), m: map[string]*judgedRelease{}}
}

// verdict returns the verdict held for repository@digest, if any. With start, a build
// that has none, or whose verdict is due to be asked for again, is sent for one in the
// background; what is returned is still what is held now.
func (j *releaseJudge) verdict(repository, digest string, start bool) (evidence.ReleaseVerdict, bool) {
	key := repository + "@" + digest
	j.mu.Lock()
	defer j.mu.Unlock()
	e := j.m[key]
	due := e == nil || !e.have ||
		e.verdict.Status != evidence.ReleaseAccepted && j.now().Sub(e.at) >= releaseRecheck
	if start && due && (e == nil || !e.running) {
		if e == nil {
			if !j.makeRoomLocked() {
				return evidence.ReleaseVerdict{}, false
			}
			e = &judgedRelease{}
			j.m[key] = e
		}
		select {
		case j.slots <- struct{}{}:
			e.running = true
			go j.check(key, e, repository, digest)
		default:
		}
	}
	if e == nil || !e.have {
		return evidence.ReleaseVerdict{}, false
	}
	return e.verdict, true
}

// check asks the verifier about one build and stores the answer.
func (j *releaseJudge) check(key string, e *judgedRelease, repository, digest string) {
	defer func() { <-j.slots }()
	v := j.rels.Verify(repository, digest)
	j.mu.Lock()
	e.verdict, e.have, e.at, e.running = v, true, j.now(), false
	j.mu.Unlock()
	j.logger.Debug("broker build judged against the release policy", "build", key,
		"accepted", v.Status == evidence.ReleaseAccepted, "version", v.Release.Version, "reason", v.Reason)
}

// makeRoomLocked frees a slot for a new build at the bound, dropping verdicts other than
// acceptances that are not being checked. It reports whether there is room.
func (j *releaseJudge) makeRoomLocked() bool {
	if len(j.m) < maxJudgedReleases {
		return true
	}
	for k, e := range j.m {
		if !e.running && (!e.have || e.verdict.Status != evidence.ReleaseAccepted) {
			delete(j.m, k)
		}
	}
	return len(j.m) < maxJudgedReleases
}
