package main

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Short-TTL caching for the router's public catalog reads, on the cleartext
// passthrough.
//
// # Why this exists
//
// The router rate-limits several public endpoints PER CLIENT IP
// (rate_limit.catalog_ip_rpm = 120 and rate_limit.system_ip_rpm = 120 in
// mainnet today, plus the public-stats and top-apps groups). The gateway does
// not forward client IPs to the router — it must not, the router is untrusted
// and an IP plus timing plus response size reconstructs a user profile the seal
// is there to deny — so once the gateway is the router's only public hostname,
// every one of those per-IP budgets collapses into ONE bucket shared by every
// user on earth. 120 requests a minute, globally, for the model catalog.
//
// Caching is the fix that does not require choosing between those two. The
// catalog is public, unauthenticated, and identical for everybody, so N users
// asking for it is N copies of one answer. Collapsing them here takes the
// router's budget from "120 users/min" to "6 gateway requests/min" and leaves
// the router's own scraping defense fully armed — whereas simply raising or
// disabling the router's limit would fix the sharing and remove the defense.
//
// It is also worth having on its own: today every browser page load crosses
// this gateway and hits the router for a catalog that changed in neither.
//
// See 0g-router docs/e2ee-global-entry-design.zh.md §3.6.
//
// # What it must never touch
//
// Only the paths in cacheableCatalogPaths, only GET, only 200. The allowlist is
// explicit rather than a rule like "cache GETs" on purpose: the passthrough is a
// catch-all, so a heuristic would automatically start caching whatever the
// router mounts next — including an authenticated per-user GET, whose first
// reader's response would then be served to the second. Every path below was
// read in the router (handler.ListModels / ListProviders / ListServiceTypes /
// GetStatus / …) and confirmed to derive its response from the query string
// alone, with no user, key, or session input. Adding a path here means making
// that check, not guessing from the name.
//
// This wrapper is also mounted ONLY on the catch-all, never on the per-surface
// `namespace` handler — that one carries prompts under
// -unsealed-subtree=passthrough, and those are POSTs to paths not on this list,
// so they would be rejected twice over. Keeping the mount narrow means the
// question never depends on the list being right.
var cacheableCatalogPaths = map[string]bool{
	// rate_limit.catalog_ip_rpm (120/min/IP in mainnet)
	"/v1/models":        true,
	"/v1/providers":     true,
	"/v1/service-types": true,
	// rate_limit.system_ip_rpm (120/min/IP). /readyz is in the router's same
	// group but is absent here deliberately: the gateway mounts its own, so a
	// request for it never reaches this passthrough at all.
	"/status":            true,
	"/status/blockchain": true,
	// public_stats.rate_limit_rpm and the top-apps group — both live in mainnet,
	// both DB-backed aggregations, so caching them is worth more per hit than the
	// catalog is.
	"/v1/stats/usage":    true,
	"/v1/stats/summary":  true,
	"/v1/stats/activity": true,
	"/v1/apps/top":       true,
	// A third-party integration artifact polled on a schedule (tkx.org), which is
	// exactly the shape a shared cache serves best.
	"/tkx-usage.json": true,
}

const (
	// defaultCatalogCacheTTL is short on purpose. The point is to collapse
	// concurrent readers, not to serve old data: at 10s a newly-registered
	// provider shows up within one poll of when it would have anyway, while a
	// thousand browsers still cost the router six requests a minute. Long TTLs
	// would buy little more (the herd is already gone after the first second) and
	// start making the catalog visibly lag the network.
	defaultCatalogCacheTTL = 10 * time.Second
	// catalogCacheMaxEntries bounds memory against query-string cardinality:
	// /v1/models takes repeatable filters, so the key space is effectively
	// unbounded and an attacker could otherwise mint a fresh entry per request.
	//
	// It is a bound on LIVE entries, which takes the sweep in acquire to be true.
	// Without it the cap counts corpses: entries are otherwise only deleted when
	// their own key is asked for again, so 256 one-shot keys would fill the map
	// and disable caching for every new key until the process restarted — for
	// 256 requests, permanently, on purpose. Reaching the cap for real (that many
	// distinct keys live inside one TTL) still only stops new keys being STORED;
	// they are served and shared in flight, and the state ends when they expire.
	catalogCacheMaxEntries = 256
	// catalogCacheMaxBody bounds a single cached response. Comfortably above a
	// real catalog; a response past it is streamed through uncached.
	catalogCacheMaxBody = 8 << 20
	// catalogUpstreamTimeout bounds the SHARED upstream request, which is
	// deliberately detached from the leader's client context (see wrap). Something
	// has to stop a hung router from holding an entry — and its waiters — open
	// forever, and it can no longer be the client hanging up. Generous: these are
	// small reads from our own router, so anything near this is already an
	// incident.
	catalogUpstreamTimeout = 30 * time.Second
)

// catalogCache is a tiny single-flight TTL cache over the passthrough.
//
// The single-flight half is load-bearing, not an optimization. Without it, the
// moment an entry expires every waiting reader misses at once and they all go
// upstream together — so a thousand pollers would still send a thousand
// requests every TTL, which is the exact number the router's one shared bucket
// cannot take. Collapsing concurrent misses onto one upstream request is what
// makes the global budget survive; the caching is almost the side effect.
type catalogCache struct {
	ttl time.Duration

	mu      sync.Mutex
	entries map[string]*catalogEntry

	// now is swappable so tests can expire an entry without sleeping.
	now func() time.Time
}

type catalogEntry struct {
	// ready is closed when the leader has finished its upstream request. Readers
	// that arrive meanwhile wait on it instead of issuing their own.
	ready chan struct{}

	status int
	header http.Header
	body   []byte
	// bypass means the leader's response cannot be replayed, so waiters fall
	// through and fetch their own rather than being served something we do not
	// hold. Three ways to get here, and only the first is benign: the response
	// outgrew catalogCacheMaxBody and was streamed straight out; the upstream died
	// mid-body so the buffer stops in the middle of the JSON; or the leader
	// produced no status at all, which replayed would be WriteHeader(0) inside
	// every waiter. See settle.
	bypass  bool
	expires time.Time
}

func newCatalogCache(ttl time.Duration) *catalogCache {
	if ttl <= 0 {
		return nil
	}
	return &catalogCache{ttl: ttl, entries: map[string]*catalogEntry{}, now: time.Now}
}

// wrap returns next with catalog caching in front of it. A nil cache (TTL <= 0,
// i.e. the feature turned off) returns next unchanged, so the disabled path
// costs nothing at all rather than a per-request branch.
func (c *catalogCache) wrap(next http.Handler) http.Handler {
	if c == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !cacheableCatalogPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Normalize what we ask the router for, so one cached body serves every
		// client that can read it.
		//
		// A cached response is bytes, and compressed bytes are only usable by a
		// client that accepts that coding — so the coding is part of the key, or the
		// cache hands gzip to a client that cannot read it. Rather than key on the
		// raw header (every browser spells it differently: "gzip, deflate",
		// "gzip, deflate, br, zstd", …, which would shard one answer into a dozen
		// entries and a dozen upstream fetches), collapse it to the only distinction
		// that affects correctness: does this client take gzip or not. A br/zstd
		// client gets gzip, which it also accepts — slightly larger than its best
		// coding, and still far better than identity.
		gzipOK := acceptsGzip(r.Header.Get("Accept-Encoding"))
		key := r.URL.Path + "?" + r.URL.RawQuery
		r2 := *r
		r2.Header = r.Header.Clone()
		if gzipOK {
			key += "\x00gzip"
			r2.Header.Set("Accept-Encoding", "gzip")
		} else {
			// Deleting it (rather than setting "identity") lets Go's Transport add
			// its own gzip and transparently decode, so we cache plain bytes.
			r2.Header.Del("Accept-Encoding")
		}

		entry, leader := c.acquire(key)
		if leader {
			// The leader's upstream request is SHARED, so it must not die with the
			// leader's client. Left on r.Context() it does: one caller pressing stop,
			// or a phone changing networks, cancels the round trip that four other
			// callers are parked on and they all get 502 — responses they would have
			// received fine with no cache at all. Because errors are not retained,
			// an attacker who connects and immediately aborts wins the leader slot
			// almost every time and can hold the endpoint there.
			//
			// WithoutCancel keeps the request's values and drops only the
			// cancellation; the timeout below puts back a bound, since something has
			// to stop a hung router from holding an entry open forever. Detaching
			// also means an abandoned leader still finishes and still fills the
			// cache, which is the useful outcome rather than a wasted round trip.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), catalogUpstreamTimeout)
			defer cancel()
			c.fill(key, entry, next, w, r2.WithContext(ctx))
			return
		}
		select {
		case <-entry.ready:
		case <-r.Context().Done():
			// The client gave up while we waited on the leader. Nothing to write.
			return
		}
		if entry.bypass {
			next.ServeHTTP(w, &r2)
			return
		}
		replayCatalog(w, entry)
	})
}

// acquire returns the entry for key and whether the caller is the leader (the
// one that must go upstream). A fresh, ready entry is returned with leader
// false and its ready channel already closed, so the caller's select falls
// straight through.
func (c *catalogCache) acquire(key string) (*catalogEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		select {
		case <-e.ready:
			// Settled. Serve it while it is fresh; otherwise drop it and lead a refill.
			if c.now().Before(e.expires) {
				return e, false
			}
			delete(c.entries, key)
		default:
			// Still in flight — join it rather than issuing a second identical request.
			return e, false
		}
	}
	e := &catalogEntry{ready: make(chan struct{})}
	// Reclaim before deciding the map is full. An entry is otherwise only ever
	// deleted when its OWN key is asked for again, so a flood of keys asked for
	// exactly once — `?junk=0` … `?junk=255` — leaves the map permanently full of
	// corpses and makes the test below false for every new key from then on.
	//
	// That is not the graceful degradation this cap was meant to be: it hands back
	// the single shared per-IP budget this whole cache exists to avoid, it costs
	// an attacker 256 requests, and it lasts until the process restarts. Sweeping
	// here makes the cap what it claimed to be — a bound on LIVE entries — and
	// costs one pass over at most 256 map entries, on the miss path only.
	if len(c.entries) >= catalogCacheMaxEntries {
		c.evictExpiredLocked()
	}
	// Still full means the cap is doing its job: that many distinct keys really
	// are live inside one TTL. Then we create the entry (so concurrent readers of
	// this key still share one upstream request) without publishing it, so it
	// cannot grow the map. Unlike before, this state now ends on its own.
	if len(c.entries) < catalogCacheMaxEntries {
		c.entries[key] = e
	}
	return e, true
}

// evictExpiredLocked drops every settled entry past its TTL. Entries still in
// flight are left alone: their leader will either publish an expiry or delete
// them in settle, and removing one here would only orphan it from the waiters
// already holding it. Caller holds c.mu.
func (c *catalogCache) evictExpiredLocked() {
	now := c.now()
	for k, e := range c.entries {
		select {
		case <-e.ready:
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		default:
		}
	}
}

// fill runs the upstream request, answers this client, and settles the entry
// for everyone waiting on it.
func (c *catalogCache) fill(key string, e *catalogEntry, next http.Handler, w http.ResponseWriter, r *http.Request) {
	rec := &catalogRecorder{w: w, limit: catalogCacheMaxBody}
	// completed is set only after next returns NORMALLY and the buffer is out.
	// It is how a truncated response is told from a whole one, and it has to be a
	// flag rather than a check afterwards because the failure arrives as a PANIC:
	// when the upstream connection dies mid-body, ReverseProxy's copy fails and it
	// panics with http.ErrAbortHandler (that is its documented way of aborting a
	// response it has already begun). The panic unwinds through this defer with
	// rec.status already 200 and rec.overflow false, so every after-the-fact test
	// says "a fine 200" about bytes that stop in the middle of a JSON object.
	//
	// That is strictly worse than the 500 the "only cache 200" rule was written
	// for. A 500 is visibly an error; `{"data":[{"id":"model-a"` is a plausible
	// catalog, and it would be served to everyone for a full TTL.
	//
	// The defer itself must stay unconditional: a leader that died with ready
	// still open would park every waiter until its own context expired, turning
	// one failed request into a stalled endpoint. It does NOT recover — the panic
	// keeps propagating to net/http, which is what closes the connection and tells
	// this client its response was cut short.
	completed := false
	defer func() {
		c.settle(key, e, rec, completed)
		close(e.ready)
	}()
	next.ServeHTTP(rec, r)
	rec.flush()
	completed = true
}

// settle records the leader's result into the entry.
//
// Two separate questions, and conflating them is what made a truncated response
// cacheable. REPLAYABLE asks whether we hold a whole response at all, and gates
// what the waiters already parked on this entry receive. CACHEABLE asks whether
// it should also be kept, and additionally requires a 200 — so a transient
// router error is shared with the current waiters and then forgotten rather than
// pinned in front of the catalog for a whole TTL.
func (c *catalogCache) settle(key string, e *catalogEntry, rec *catalogRecorder, completed bool) {
	// rec.status == 0 means the leader panicked before writing anything at all
	// (the round trip never produced a response). Replaying that calls
	// WriteHeader(0), which panics inside EVERY waiter's own handler — one failed
	// upstream request becoming N broken client connections.
	replayable := completed && !rec.overflow && rec.status != 0 && rec.bodyIsWhole()
	if !replayable {
		e.bypass = true
	} else {
		e.status = rec.status
		e.header = snapshotCatalogHeader(rec.Header())
		e.body = rec.buf.Bytes()
	}
	cacheable := replayable && rec.status == http.StatusOK
	c.mu.Lock()
	defer c.mu.Unlock()
	if !cacheable {
		delete(c.entries, key)
		return
	}
	e.expires = c.now().Add(c.ttl)
}

// replayableCatalogHeaders is what a cached response carries forward. It is an
// allowlist because most of what an HTTP response header holds describes the
// exchange rather than the body — Date, Set-Cookie, a request id, the E2EE
// marker set per-request by MarkE2EE outside this wrapper — and replaying those
// would attach one client's exchange to another's response.
var replayableCatalogHeaders = []string{
	"Content-Type",
	"Content-Encoding",
	"Vary",
	"Cache-Control",
	"ETag",
	"Last-Modified",
}

func snapshotCatalogHeader(h http.Header) http.Header {
	out := http.Header{}
	for _, name := range replayableCatalogHeaders {
		if v := h.Values(name); len(v) > 0 {
			out[name] = append([]string(nil), v...)
		}
	}
	return out
}

func replayCatalog(w http.ResponseWriter, e *catalogEntry) {
	dst := w.Header()
	for name, values := range e.header {
		dst[name] = append([]string(nil), values...)
	}
	w.WriteHeader(e.status)
	_, _ = w.Write(e.body)
}

// acceptsGzip reports whether the client's Accept-Encoding permits gzip.
//
// The q value has to be PARSED, not pattern-matched: "q=0" means "not
// acceptable" (RFC 9110 §12.5.3), but it is also a prefix of "q=0.5", which
// means the opposite. A substring test reads `deflate, gzip;q=0.5` as a refusal
// and sends that client identity — a silent bandwidth regression that nothing
// would ever report.
func acceptsGzip(accept string) bool {
	for _, part := range strings.Split(accept, ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
			continue
		}
		for _, param := range strings.Split(params, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			q, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			// An unparseable q is not a refusal; only an explicit zero is.
			return err != nil || q > 0
		}
		return true
	}
	return false
}

// catalogRecorder buffers a response so it can be both served and cached.
//
// Header() hands back the real ResponseWriter's map, so the proxy's own header
// writes (and ModifyResponse's edits, e.g. StripCORSHeaders) land where they
// would have without this wrapper; only the status line and body are deferred.
// If the body outgrows limit we stop buffering, emit what we have, and stream
// the rest — the response still reaches its client, it just is not cacheable.
type catalogRecorder struct {
	w     http.ResponseWriter
	limit int

	status   int
	buf      bytes.Buffer
	overflow bool
	flushed  bool
}

func (rc *catalogRecorder) Header() http.Header { return rc.w.Header() }

// bodyIsWhole cross-checks the buffered body against a Content-Length the
// upstream declared. Independent of the panic flag on purpose: that flag relies
// on ReverseProxy choosing to panic, which it only does when it can tell it is
// running under an http.Server (shouldPanicOnCopyError), so a short body must
// also be catchable from the bytes themselves.
//
// Absent or unparseable Content-Length means "no claim to check" and passes:
// the header is genuinely missing on a chunked response, and on the identity
// path where Go's Transport decompressed the body and dropped the length.
func (rc *catalogRecorder) bodyIsWhole() bool {
	declared := rc.Header().Get("Content-Length")
	if declared == "" {
		return true
	}
	n, err := strconv.ParseInt(declared, 10, 64)
	if err != nil {
		return true
	}
	return n == int64(rc.buf.Len())
}

func (rc *catalogRecorder) WriteHeader(status int) {
	if rc.status == 0 {
		rc.status = status
	}
}

func (rc *catalogRecorder) Write(p []byte) (int, error) {
	if rc.status == 0 {
		rc.status = http.StatusOK
	}
	if rc.overflow {
		return rc.w.Write(p)
	}
	if rc.buf.Len()+len(p) > rc.limit {
		// Too big to hold. Commit what we have and become a pass-through.
		rc.overflow = true
		rc.w.WriteHeader(rc.status)
		rc.flushed = true
		if _, err := rc.w.Write(rc.buf.Bytes()); err != nil {
			return 0, err
		}
		rc.buf.Reset()
		return rc.w.Write(p)
	}
	return rc.buf.Write(p)
}

// flush writes the buffered response out. Separate from Write so the status
// line is emitted exactly once, and after the handler has finished setting
// headers.
func (rc *catalogRecorder) flush() {
	if rc.flushed {
		return
	}
	rc.flushed = true
	if rc.status == 0 {
		rc.status = http.StatusOK
	}
	rc.w.WriteHeader(rc.status)
	_, _ = rc.w.Write(rc.buf.Bytes())
}
