package main

import (
	"bytes"
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
	// Past the cap we stop STORING but still serve and still share in flight, so
	// exceeding it degrades to today's behavior rather than to an error.
	catalogCacheMaxEntries = 256
	// catalogCacheMaxBody bounds a single cached response. Comfortably above a
	// real catalog; a response past it is streamed through uncached.
	catalogCacheMaxBody = 8 << 20
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
	// bypass means the leader's response could not be replayed (it outgrew
	// catalogCacheMaxBody and was streamed straight out). Waiters fall through and
	// fetch their own rather than being served something we do not have.
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
			c.fill(key, entry, next, w, &r2)
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
	// Past the cap we still create the entry (so concurrent readers of this key
	// share one upstream request) but do not publish it, so it cannot be reused
	// later and cannot grow the map.
	if len(c.entries) < catalogCacheMaxEntries {
		c.entries[key] = e
	}
	return e, true
}

// fill runs the upstream request, answers this client, and settles the entry
// for everyone waiting on it.
func (c *catalogCache) fill(key string, e *catalogEntry, next http.Handler, w http.ResponseWriter, r *http.Request) {
	rec := &catalogRecorder{w: w, limit: catalogCacheMaxBody}
	// Settle the entry no matter how next returns, panic included: a leader that
	// died with ready still open would park every waiter until its context
	// expired, turning one failed request into a stalled endpoint.
	defer func() {
		c.settle(key, e, rec)
		close(e.ready)
	}()
	next.ServeHTTP(rec, r)
	rec.flush()
}

// settle records the leader's result into the entry. Only a complete 200 is
// retained; anything else is served to the current waiters and then forgotten,
// so a transient router error cannot be pinned in front of the catalog for a
// whole TTL.
func (c *catalogCache) settle(key string, e *catalogEntry, rec *catalogRecorder) {
	if rec.overflow {
		e.bypass = true
	} else {
		e.status = rec.status
		e.header = snapshotCatalogHeader(rec.Header())
		e.body = rec.buf.Bytes()
	}
	cacheable := !rec.overflow && rec.status == http.StatusOK
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
