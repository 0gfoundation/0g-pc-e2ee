package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/compose"
	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/release"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
)

// identityPath is the public route this serves.
const identityPath = "/v1/gateway/identity"

// defaultIdentityReleases is how many published releases the deployed compose text
// is compared against when nothing says otherwise. It matches pcverify's own
// default (client/cmd/pcverify's defaultReleases): enough to cover a rollback or a
// lagging side of a blue/green pair, few enough that "matches none of them" stays a
// strong signal.
const defaultIdentityReleases = 5

// identityLookupTimeout bounds each outbound lookup the assembly makes — the
// GitHub release listing and the fallback platform app-compose fetch. It is
// generous because nothing waits on it: the work happens in the background and a
// slow lookup costs a later answer, never a slower request.
const identityLookupTimeout = 20 * time.Second

// THIS ENDPOINT IS NOT EVIDENCE. It is the gateway describing ITSELF: values it
// read out of its own quote file and its own manifest, with no signature of its
// own over any of it and no independent verification behind it. A caller that
// believes it because the gateway said so has verified nothing — a compromised
// gateway would serve whatever it liked here, and every byte of that would be
// well-formed.
//
// What makes it worth serving anyway is that every value is INDEPENDENTLY
// REDERIVABLE: `pcverify -gateway <domain>` reaches the same app_id, compose_hash,
// OS image and release from the published evidence bundle plus a DCAP verification
// this process does not perform, and it does the one step a browser cannot do at
// all (endpoint binding — comparing the served TLS certificate against the one the
// quote commits to; JS cannot see its own connection's peer certificate). So this
// is the panel's *display* source, and pcverify remains the *proof*. The response
// carries no "verified": true of any shape, and never should — see verifyNote.
//
// It is also why the gateway still has no /quote route (see the package comment):
// publishing a parsed description of an attestation is a different act from
// signing one, and this endpoint must not drift into the second.
//
// Everything it reports is already public: the quote is served under /evidences/,
// and the compose text is published as a GitHub release asset. There is nothing
// here to authorize, which is why the route needs no credential.

// verifyNote rides in the response so the value cannot travel without the caveat.
// A UI is free to render it or not; what it must not do is present these values as
// verified without an accompanying path to verifying them.
const verifyNote = "self-reported by this gateway; verify independently with: pcverify -gateway <domain>"

// identityDoc is the response body. Every field a lookup can fail to produce is a
// pointer or a slice so it marshals to null rather than to a zero value — "" and
// null are different claims, and a UI that cannot tell "no release matched" from
// "we never asked" will state the wrong one.
type identityDoc struct {
	// InstanceID names the serving replica, the same value as the
	// X-0G-Gateway-Instance header. Empty (not null) when the CVM identity was
	// unavailable, matching the header's absence.
	InstanceID string `json:"instance_id"`
	// AppID and ComposeHash come from the quote's mr_config_id.
	AppID       *string `json:"app_id"`
	ComposeHash *string `json:"compose_hash"`
	// OSImage is the name of the allowlist entry this CVM's boot chain matched, or
	// null.
	//
	// Null carries TWO cases that this shape cannot distinguish: the boot chain
	// matched nothing in the allowlist (a real finding — an unrecognized OS image),
	// and the allowlist was empty so nothing was checked. That was a deliberate
	// simplification when the field was added; the distinction lives in the server's
	// evidence.OSImageCheck and in the startup log, and re-exposing it is an
	// output-layer change (a status enum) rather than a data-path one. Until then a
	// UI must not read a non-null value as "verified".
	OSImage *string `json:"os_image"`
	// MatchedRelease is the published release whose docker-compose.release.yml the
	// deployed compose text equals byte-for-byte, or null. Null when nothing
	// matched, when the lookup could not be made, or when there was no compose text
	// to compare — never an approximate match.
	MatchedRelease *releaseRef `json:"matched_release"`
	// Containers is the container list from the AUTHENTICATED compose text, or null
	// when there is none to report. Null rather than [] on purpose: an empty array
	// says "this deployment runs no containers", which is never true.
	Containers []containerRef `json:"containers"`
	// EvidenceURL is where the attestation bundle lives, RELATIVE to this gateway.
	// Deliberately not an absolute URL: the only thing this process knows about its
	// own public name is the Host header, which the caller controls, so building one
	// would mean echoing a caller-supplied hostname back as if it were ours.
	EvidenceURL string `json:"evidence_url"`
	// Verify is verifyNote. See the file comment.
	Verify string `json:"verify"`
}

// releaseRef names a published release.
type releaseRef struct {
	Tag string `json:"tag"`
	URL string `json:"url"`
}

// containerRef is one container of the deployment.
type containerRef struct {
	// Name is the compose service name.
	Name string `json:"name"`
	// Image is the repository, without tag or digest.
	Image string `json:"image"`
	// Digest is the "sha256:…" the compose text pins, or "" when the reference
	// carries none. Empty is worth rendering rather than hiding: an unpinned image
	// in an attested deployment means compose_hash commits to a NAME whose contents
	// can change under it.
	Digest string `json:"digest"`
	// Source is "0g-release" for images 0G published and "third-party" for everything
	// else. All of them are covered by compose_hash; what differs is who answers for
	// the contents. A third-party image must never be given a release link — see
	// classifySource.
	Source string `json:"source"`
}

const (
	// sourceOwn marks an image 0G PUBLISHED: our namespace on a registry we publish
	// through. Despite the name it is not on its own a claim that some GitHub release
	// commits to this exact image — on this endpoint matched_release is what
	// establishes that, and on the provider endpoint nothing does, because no
	// per-provider manifest is published. The name is kept because one vocabulary
	// across both container lists is worth more to a panel than a more literal word on
	// one of them.
	sourceOwn = "0g-release"
	// sourceThirdParty marks everything else, including our namespace on a registry we
	// do not publish through — see classifySource.
	sourceThirdParty = "third-party"
)

// identityConfig is where the assembled values come from. Every source is
// optional: whatever is missing turns into a null field rather than a failure.
type identityConfig struct {
	// InstanceID is this replica's id, already resolved at startup.
	InstanceID string
	// AppID is this CVM's app_id as the RUNTIME reports it (cmd/cvmid read it from the
	// guest agent). Empty falls back to compose_hash's leading bytes, which is a guess:
	// dstack fixes an app's id when the app is created and keeps it across upgrades, so
	// the two agree only until the first redeploy. The difference is not cosmetic — it
	// is the address the platform routes by, so the fallback lookup in loadAppCompose
	// asks about an app that does not exist and hangs until its timeout.
	AppID string
	// QuotePath is the cert-binding quote in the evidence bundle. It is the source
	// of app_id, compose_hash and the boot chain. Empty disables all three.
	QuotePath string
	// AppComposePath is the manifest cmd/cvmid published on the shared volume.
	AppComposePath string
	// BaseDomain enables the fallback app-compose lookup against the platform's
	// per-app guest-agent host when the file is unavailable. Empty disables it.
	BaseDomain string
	// Releases is how many published releases the compose text is compared against.
	// 0 disables the GitHub lookup entirely.
	Releases int
	// ReleaseRepo / ReleaseAsset / ReleaseAPIBase locate those releases; zero values
	// mean the client/release defaults.
	ReleaseRepo    string
	ReleaseAsset   string
	ReleaseAPIBase string
	// OSImages is the allowlist the boot chain is compared against. Callers pass
	// evidence.BuiltinOSImages(); tests pass their own.
	OSImages []evidence.OSImage
	// Timeout bounds each outbound lookup (the platform app-compose fetch, GitHub).
	Timeout time.Duration
}

// buildResult is one assembly pass: the document, plus whether anything is still
// worth retrying. A value that is simply absent — no release matched, no quote is
// published by this deployment — is settled, not pending; retrying it forever
// would be a background loop that never ends and never changes anything.
type buildResult struct {
	doc     identityDoc
	pending []string // human-readable reasons a retry might do better; empty = settled
}

// buildIdentity assembles the document from whatever is available right now.
//
// It never returns an error. Every step degrades to a null field, because the
// alternative — one unavailable lookup taking down the whole endpoint — turns a
// partial answer into no answer, and this endpoint's entire job is to have
// something to show.
func buildIdentity(ctx context.Context, cfg identityConfig, logger *slog.Logger) buildResult {
	res := buildResult{doc: identityDoc{
		InstanceID:  cfg.InstanceID,
		EvidenceURL: evidencePrefix,
		Verify:      verifyNote,
	}}

	// Step 1 — the quote. app_id, compose_hash and the OS image all hang off it, so
	// nothing below runs without it.
	//
	// The quote is parsed STRUCTURALLY and not DCAP-verified. Verifying our own
	// quote would prove nothing to the caller (a gateway that would lie about these
	// values would equally happily lie about having verified them), while adding an
	// Intel PCS round trip and a failure mode to the startup path. The verification
	// that counts is the one pcverify performs from outside.
	var composeHash [attest.ComposeHashLen]byte
	haveHash := false
	if cfg.QuotePath != "" {
		switch body, err := readQuoteBody(cfg.QuotePath); {
		case err != nil:
			// The bundle is written by dstack-ingress after its first ACME run, so an
			// absent quote is the normal state for the first minute of a fresh CVM's life,
			// not a misconfiguration. Retry rather than settle.
			res.pending = append(res.pending, "quote: "+err.Error())
			logger.Debug("identity: quote unavailable", "path", cfg.QuotePath, "err", err)
		default:
			hash, err := attest.ComposeHashFromMRConfigID(body.MRConfigID)
			if err != nil {
				// A V2/V3 mr_config_id does not carry the hash in the clear. Re-reading the
				// same file will not change that, so this is settled, not pending.
				logger.Warn("identity: cannot read compose_hash from this quote", "err", err)
			} else {
				composeHash, haveHash = hash, true
				// The runtime's own app_id when there is one; otherwise the derivation, which
				// holds only for an app still running the compose it was created with (see
				// identityConfig.AppID). Both are self-reported and neither is evidence — what
				// differs is which one a reader can look the deployment up by.
				appID := cfg.AppID
				if appID == "" {
					appID = attest.AppIDFromComposeHash(hash)
				}
				hexHash := hex.EncodeToString(hash[:])
				res.doc.AppID, res.doc.ComposeHash = &appID, &hexHash
			}
			// The OS image is independent of the compose hash: it comes from the boot-chain
			// registers, which every quote carries.
			if check := evidence.CheckOSImage(cfg.OSImages, body.Measurement); check.Configured && check.Err == nil {
				matched := check.Matched
				res.doc.OSImage = &matched
			} else {
				// Both remaining cases publish null. Only the log distinguishes them, and the
				// unrecognized-image case is a real finding, so it is not a Debug line.
				if check.Configured {
					logger.Warn("identity: this CVM's boot chain matches no allowlisted OS image",
						"err", check.Err, "mrtd", hex.EncodeToString(check.Observed.MRTD[:]))
				} else {
					logger.Warn("identity: no OS-image allowlist is configured, so os_image is reported as null")
				}
			}
		}
	}

	// Step 2 — the manifest, and the container list inside it.
	//
	// The bytes are authenticated against the quote's compose_hash before anything
	// is read out of them. Without a hash there is nothing to authenticate them
	// with, so the whole step is skipped: publishing a container list taken from
	// unverified bytes would be exactly the "gateway vouching for itself" this
	// endpoint is careful not to do — worse than publishing null.
	var composeText []byte
	if haveHash {
		raw, source, err := loadAppCompose(ctx, cfg, deref(res.doc.AppID))
		switch {
		// Configured but not readable yet — nothing orders cvm-identity before this
		// process, so retry.
		case err != nil && !errors.Is(err, errNoAppComposeSource):
			res.pending = append(res.pending, "app-compose: "+err.Error())
			logger.Warn("identity: app-compose unavailable, reporting no container list", "err", err)
		// Not configured at all: a settled answer, not a gap. See errNoAppComposeSource.
		case err != nil:
			logger.Info("identity: no app-compose source configured, reporting no container list")
		default:
			ac, err := evidence.VerifyAppCompose(raw, composeHash)
			if err != nil {
				// A mismatch means the file is from another deployment (a stale volume, a
				// redeploy the init container did not re-run for). Re-reading it will not fix
				// that, so it is settled — and loud, because it is a real inconsistency.
				logger.Error("identity: app-compose does not match the quote's compose_hash; reporting no container list",
					"source", source, "err", err)
				break
			}
			composeText = []byte(ac.DockerComposeFile)
			services, err := compose.ParseServices(composeText)
			if err != nil {
				logger.Error("identity: cannot read the services out of the authenticated compose text",
					"source", source, "err", err)
				break
			}
			res.doc.Containers = containersOf(services)
			logger.Info("identity: container list resolved", "source", source, "containers", len(services))
		}
	}

	// Step 3 — which published release this compose text is, if any.
	if cfg.Releases > 0 && len(composeText) > 0 {
		assets, err := release.FetchComposeAssets(ctx, release.Config{
			HTTP:    release.NewHTTPClient(cfg.Timeout),
			Repo:    cfg.ReleaseRepo,
			Asset:   cfg.ReleaseAsset,
			APIBase: cfg.ReleaseAPIBase,
		}, cfg.Releases, nil)
		switch {
		case err != nil:
			// GitHub being unreachable or rate-limited (60/hour per IP unauthenticated)
			// says nothing about the deployment. Retry later; report null meanwhile.
			res.pending = append(res.pending, "releases: "+err.Error())
			logger.Warn("identity: release lookup failed, reporting no matched release", "err", err)
		default:
			candidates := make([]evidence.ExpectedCompose, 0, len(assets))
			byTag := make(map[string]string, len(assets))
			for _, a := range assets {
				candidates = append(candidates, evidence.ExpectedCompose{Label: a.Tag, Content: a.Content})
				byTag[a.Tag] = a.URL
			}
			tag, err := evidence.MatchCompose(composeText, candidates)
			if err != nil {
				// A settled answer: this deployment is not any of the releases looked at. The
				// checked-in compose carries `:latest` and is EXPECTED not to match — only the
				// release asset is digest-pinned (deploy/phala/README.md) — so this is
				// unremarkable for a development deployment and a finding for a production one.
				logger.Info("identity: compose text matches no published release", "err", err)
				break
			}
			res.doc.MatchedRelease = &releaseRef{Tag: tag, URL: byTag[tag]}
		}
	}
	return res
}

// containersOf turns the parsed services into the response's container list.
func containersOf(services []compose.Service) []containerRef {
	out := make([]containerRef, 0, len(services))
	for _, s := range services {
		out = append(out, containerRef{
			Name:   s.Name,
			Image:  s.Image,
			Digest: s.Digest,
			Source: classifySource(s.Image),
		})
	}
	return out
}

// classifySource says whether an image was PUBLISHED BY 0G. It is the label on both
// identity endpoints' container lists, so the word means the same thing on each.
//
// It reads the reference's registry and namespace (evidence.ClassifyImageOrigin), and
// that choice is what lets the provider endpoint carry the label at all. The rule this
// replaces was repo-scoped — does the reference start with ghcr.io/<owner>/<repo>-,
// the namespace .github/workflows/release.yml publishes to — which answers
// "third-party" for ghcr.io/0gfoundation/0g-serving-broker: 0G's own broker image,
// stamped as someone else's for the sole reason that it ships from a different
// repository. On the gateway's own four containers the two rules agree; on a
// provider's they do not, and the repo-scoped one is simply wrong there.
//
// It stays a fact about the image reference in the authenticated compose text, never
// about whether a release lookup succeeded. matched_release is a property of the
// DEPLOYMENT, source is a property of each IMAGE, and collapsing them would either
// drop the label when GitHub is unreachable or, far worse, imply that a third-party
// image is traceable to one of our releases.
//
// Everything that is not first-party collapses to sourceThirdParty, our namespace on a
// registry we do not publish through (evidence.OriginForeignRegistry) included. That
// collapse only ever states LESS than the classifier knows, which is the safe direction
// for a two-value label: it can fail to flag a lookalike, never bless one. The
// distinction survives where a reader can act on it — `pcverify`'s origin column, and
// the justify-severity finding the compose review raises for exactly that shape.
func classifySource(image string) string {
	if evidence.ClassifyImageOrigin(image) == evidence.OriginFirstParty {
		return sourceOwn
	}
	return sourceThirdParty
}

// deref reads an optional string field, "" when it is null.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// readQuoteBody reads and structurally parses the bundle's quote.json. See
// buildIdentity on why this does not DCAP-verify.
func readQuoteBody(path string) (attest.QuoteBody, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return attest.QuoteBody{}, err
	}
	raw, err := attest.DecodeQuoteResponse(body)
	if err != nil {
		return attest.QuoteBody{}, err
	}
	return attest.ParseTDXQuoteBody(raw)
}

// loadAppCompose returns the raw app-compose bytes and where they came from.
//
// The file cmd/cvmid published wins: it needs no network, no third-party host and
// no DNS, and it is there from boot. The platform's per-app guest-agent host is
// the fallback for a replica whose init container predates -out-app-compose (a
// rolling blue/green upgrade has exactly that shape) — its TLS terminates in the
// PLATFORM's gateway rather than in this CVM, which is acceptable only because
// the caller checks these bytes against the quote's compose_hash. Neither source
// is trusted; both are checked.
//
// appID is the value the document reports, which is the RUNTIME's app_id whenever
// cmd/cvmid supplied one (see identityConfig.AppID). That matters here and nowhere
// else in this file: it is the name the platform routes by, and the derivation from
// compose_hash stops being that name the first time the app is upgraded.
func loadAppCompose(ctx context.Context, cfg identityConfig, appID string) ([]byte, string, error) {
	var errs []error
	if cfg.AppComposePath != "" {
		raw, err := os.ReadFile(cfg.AppComposePath)
		if err == nil {
			return raw, "file:" + cfg.AppComposePath, nil
		}
		errs = append(errs, fmt.Errorf("file %s: %w", cfg.AppComposePath, err))
	}
	if cfg.BaseDomain != "" && appID != "" {
		hc := &http.Client{Timeout: cfg.Timeout}
		raw, err := evidence.FetchAppCompose(ctx, hc, appID, cfg.BaseDomain)
		if err == nil {
			return raw, "platform:" + cfg.BaseDomain, nil
		}
		errs = append(errs, fmt.Errorf("platform %s: %w", cfg.BaseDomain, err))
	}
	if len(errs) == 0 {
		return nil, "", errNoAppComposeSource
	}
	return nil, "", errors.Join(errs...)
}

// errNoAppComposeSource means neither manifest source was configured, as opposed
// to being configured and unavailable.
//
// The difference decides whether the assembly retries. Both paths are fixed at
// startup, so "nothing configured" cannot become true later — recording it as
// pending would leave the builder looping at its backoff cap for the life of the
// process, warning every pass, and would keep the document permanently marked
// incomplete (and so served no-cache) over a configuration choice that was
// deliberate. A configured-but-unreadable source is the opposite: cvm-identity may
// simply not have written the file yet, since nothing orders it before the gateway.
var errNoAppComposeSource = errors.New("no app-compose source configured")

// identityCache holds the assembled document. It is rebuilt in the background
// until nothing is pending, then never again: every value in it is fixed for the
// life of a replica (the quote, the manifest and the release it matches all
// change only by redeploying, which replaces this process).
type identityCache struct {
	// state is swapped atomically so readers never block on the builder.
	state atomic.Pointer[identityState]
}

type identityState struct {
	body     []byte // pre-marshalled response
	complete bool
}

// Doc returns the response body and whether the assembly finished.
func (c *identityCache) Doc() ([]byte, bool) {
	if s := c.state.Load(); s != nil {
		return s.body, s.complete
	}
	return nil, false
}

func (c *identityCache) store(res buildResult) {
	body, err := json.MarshalIndent(res.doc, "", "  ")
	if err != nil {
		// Nothing in the document can fail to marshal; treat it as a lost update
		// rather than a reason to lose the previous one.
		return
	}
	c.state.Store(&identityState{body: append(body, '\n'), complete: len(res.pending) == 0})
}

// identityRetryStart and identityRetryMax bound the rebuild backoff. The first
// gap is short because the common pending case is "dstack-ingress has not
// finished its first ACME run yet", which resolves in tens of seconds; the cap
// keeps a permanently unavailable source (a rate-limited GitHub) down to a few
// requests an hour.
// identityRetryStart is a var, not a const, for one reason: the test that pins
// the loop's whole point — that a source appearing after boot is picked up —
// would otherwise have to wait the real 15 seconds to observe one iteration.
var identityRetryStart = 15 * time.Second

const identityRetryMax = 10 * time.Minute

// startIdentity assembles the document in the background and returns the cache
// plus a stop function for shutdown.
//
// It never blocks startup. The first pass usually completes in milliseconds (two
// file reads) plus one GitHub call, but it runs off the serving path regardless:
// a slow or hanging lookup must delay nothing, and a request that arrives before
// the first pass finishes is answered with what is known so far rather than made
// to wait.
func startIdentity(cfg identityConfig, logger *slog.Logger) (*identityCache, func()) {
	cache := &identityCache{}
	// Publish the minimal document immediately, so the route answers with the
	// instance id from the very first request rather than 503ing or serving "{}".
	cache.store(buildResult{doc: identityDoc{
		InstanceID:  cfg.InstanceID,
		EvidenceURL: evidencePrefix,
		Verify:      verifyNote,
	}, pending: []string{"not assembled yet"}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		delay := identityRetryStart
		for {
			res := buildIdentity(ctx, cfg, logger)
			cache.store(res)
			if len(res.pending) == 0 {
				logger.Info("identity: assembled", "path", identityPath)
				return
			}
			logger.Info("identity: incomplete, will retry", "pending", res.pending, "retry_in", delay.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			if delay *= 2; delay > identityRetryMax {
				delay = identityRetryMax
			}
		}
	}()
	return cache, func() {
		cancel()
		<-done
	}
}

// identityCompleteMaxAge is how long a finished document may be reused. Its values
// cannot change without a redeploy, which replaces the process and the CVM behind
// it, so this could be far longer; five minutes keeps a blue/green switch from
// leaving a stale panel open for an hour.
const identityCompleteMaxAge = "public, max-age=300"

// identityHandler serves the cached document.
//
// It answers 200 with whatever is assembled — never 500 and never 503. A field
// that could not be resolved is null, which a UI can render ("unknown") in a way
// it cannot render an error page. The one thing it will not do is make a caller
// wait for a lookup.
func identityHandler(cache *identityCache) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, complete := cache.Doc()
		if body == nil {
			openaiproxy.WriteError(w, http.StatusServiceUnavailable, "gateway", "gateway identity is not available yet")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// This response DOES vary by Origin — the CORS middleware reflects the
		// request's Origin into Access-Control-Allow-Origin — but that middleware only
		// SAYS so when the request carried one. Cacheable-and-unmarked is the dangerous
		// combination: a shared cache would store the no-Origin variant (a curl, an
		// uptime probe, a warmer) and replay it, header-less, to the browser panel,
		// which then blocks it for the whole max-age. /evidences/ sidesteps this by
		// pairing `no-cache` with a request-independent `*`; this route caches, so it
		// has to declare the variance itself. Add, not Set: Vary is a list, other
		// middleware contributes to it, and a duplicated entry is harmless where a
		// missing one is not.
		w.Header().Add("Vary", "Origin")
		if complete {
			w.Header().Set("Cache-Control", identityCompleteMaxAge)
		} else {
			// Still filling in. Caching this would pin a half-answer in front of the
			// finished one for as long as the max-age lasts.
			w.Header().Set("Cache-Control", "no-cache")
		}
		_, _ = w.Write(body)
	})
}
