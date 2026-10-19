package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/evidence"
)

const imageName = "0gfoundation/0g-serving-broker"

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// fakeRegistry serves one image's referrers the way ghcr.io does: no referrers API, a
// fallback index under the sha256-<hex> tag, artifact manifests, and blobs — all behind
// an anonymous bearer-token challenge.
type fakeRegistry struct {
	subject   string
	objects   map[string][]byte // path under /v2/<name>/ -> body
	status    map[string]int    // path -> forced status
	requests  atomic.Int32
	tokenSeen atomic.Bool
}

func newFakeRegistry(subject string) *fakeRegistry {
	return &fakeRegistry{subject: subject, objects: map[string][]byte{}, status: map[string]int{}}
}

// attach adds an artifact manifest for bundle, listed in the fallback index.
func (f *fakeRegistry) attach(t *testing.T, bundle []byte, subject string) {
	t.Helper()
	f.objects["blobs/"+sha(bundle)] = bundle
	m, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaManifest,
		"subject": map[string]any{"mediaType": mediaManifest, "digest": subject, "size": 1},
		"layers":  []map[string]any{{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "digest": sha(bundle), "size": len(bundle)}},
	})
	f.objects["manifests/"+sha(m)] = m
	f.list(sha(m))
}

// list adds a descriptor to the fallback index, whether or not the manifest exists.
func (f *fakeRegistry) list(digest string) {
	tag := "manifests/sha256-" + strings.TrimPrefix(f.subject, "sha256:")
	var idx index
	if raw, ok := f.objects[tag]; ok {
		_ = json.Unmarshal(raw, &idx)
	}
	idx.Manifests = append(idx.Manifests, descriptor{MediaType: mediaManifest, Digest: digest})
	raw, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaIndex, "manifests": idx.Manifests})
	f.objects[tag] = raw
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	if r.URL.Path == "/token" {
		if r.URL.Query().Get("scope") != "repository:"+imageName+":pull" {
			http.Error(w, "bad scope", http.StatusBadRequest)
			return
		}
		f.tokenSeen.Store(true)
		_, _ = w.Write([]byte(`{"token":"t0k"}`))
		return
	}
	if r.Header.Get("Authorization") != "Bearer t0k" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token",service="%s",scope="repository:%s:pull"`,
			r.Host, r.Host, imageName))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v2/"+imageName+"/")
	if st, ok := f.status[path]; ok {
		w.WriteHeader(st)
		return
	}
	body, ok := f.objects[path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = w.Write(body)
}

// serve starts the registry and returns a Verifier pointed at it.
func serve(t *testing.T, f *fakeRegistry) *Verifier {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "https://")
	v := withPolicy(t, func(p map[string]any) { p["repository"] = host + "/" + imageName })
	v.registry = newRegistry(srv.Client(), 10*time.Second)
	return v
}

func TestVerify_ThroughTheRegistry(t *testing.T) {
	t.Run("ghcr's shape: fallback tag, a stale entry, a signature and the provenance", func(t *testing.T) {
		f := newFakeRegistry(digestV054)
		f.list("sha256:" + strings.Repeat("0", 64)) // listed, gone — as v0.5.1's index is
		f.attach(t, fixture(t, "v0.5.4.cosign-sign.json"), digestV054)
		f.attach(t, fixture(t, "v0.5.4.slsa.json"), digestV054)
		v := serve(t, f)
		got := v.Verify(v.Repository(), digestV054)
		if got.Status != evidence.ReleaseAccepted || got.Release.Version != "v0.5.4" {
			t.Fatalf("got %+v", got)
		}
		if !f.tokenSeen.Load() {
			t.Fatal("the token challenge was not answered")
		}
		// Judged once per run.
		n := f.requests.Load()
		if again := v.Verify(v.Repository(), digestV054); again.Status != evidence.ReleaseAccepted || f.requests.Load() != n {
			t.Fatalf("the second check went back to the registry (%d -> %d requests)", n, f.requests.Load())
		}
	})

	t.Run("no referrers at all is a rejection, not an outage", func(t *testing.T) {
		v := serve(t, newFakeRegistry(digestV054))
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseRejected ||
			!strings.Contains(got.Reason, "no Sigstore bundle") {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("an attachment to another image is ignored", func(t *testing.T) {
		f := newFakeRegistry(digestV054)
		f.attach(t, fixture(t, "v0.5.4.slsa.json"), digestV052)
		v := serve(t, f)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseRejected {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("a blob that does not match its digest is ignored", func(t *testing.T) {
		f := newFakeRegistry(digestV054)
		b := fixture(t, "v0.5.4.slsa.json")
		f.attach(t, b, digestV054)
		f.objects["blobs/"+sha(b)] = []byte(`{"swapped": true}`)
		v := serve(t, f)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseRejected {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("a registry error is unavailable, not a rejection", func(t *testing.T) {
		for _, path := range []string{"referrers/" + digestV054, "manifests/sha256-" + strings.TrimPrefix(digestV054, "sha256:")} {
			f := newFakeRegistry(digestV054)
			f.attach(t, fixture(t, "v0.5.4.slsa.json"), digestV054)
			f.status[path] = http.StatusServiceUnavailable
			v := serve(t, f)
			if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseUnavailable {
				t.Fatalf("%s 503: got %+v", path, got)
			}
		}
		f := newFakeRegistry(digestV054)
		b := fixture(t, "v0.5.4.slsa.json")
		f.attach(t, b, digestV054)
		f.status["blobs/"+sha(b)] = http.StatusTooManyRequests
		v := serve(t, f)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseUnavailable {
			t.Fatalf("a throttled blob: got %+v", got)
		}
	})

	t.Run("an unreachable registry is unavailable", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.NotFoundHandler())
		host := strings.TrimPrefix(srv.URL, "https://")
		client := srv.Client()
		srv.Close()
		v := withPolicy(t, func(p map[string]any) { p["repository"] = host + "/" + imageName })
		v.registry = newRegistry(client, 2*time.Second)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseUnavailable {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestParseChallenge(t *testing.T) {
	got := parseChallenge(`realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull"`)
	if got["realm"] != "https://ghcr.io/token" || got["service"] != "ghcr.io" || got["scope"] != "repository:a/b:pull" {
		t.Fatalf("got %v", got)
	}
}

// A process holds one Verifier for days, so a verdict is reused only as long as what it
// says can hold: an acceptance for good, a rejection for an hour (the attestation may not
// be uploaded yet), an outage for minutes.
func TestVerify_CacheLifetimes(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)}

	t.Run("an outage is asked again after unavailableTTL", func(t *testing.T) {
		f := newFakeRegistry(digestV054)
		f.attach(t, fixture(t, "v0.5.4.slsa.json"), digestV054)
		f.status["referrers/"+digestV054] = http.StatusServiceUnavailable
		v := serve(t, f)
		v.now = clock.now
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseUnavailable {
			t.Fatalf("503: got %+v", got)
		}
		delete(f.status, "referrers/"+digestV054)
		clock.advance(unavailableTTL - time.Second)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseUnavailable {
			t.Fatalf("within unavailableTTL: got %+v", got)
		}
		clock.advance(time.Second)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseAccepted {
			t.Fatalf("after unavailableTTL: got %+v", got)
		}
		n := f.requests.Load()
		clock.advance(365 * 24 * time.Hour)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseAccepted || f.requests.Load() != n {
			t.Fatalf("an acceptance went back to the registry a year on (%d -> %d requests): %+v", n, f.requests.Load(), got)
		}
	})

	t.Run("a digest seen before its attestation is asked again after rejectedTTL", func(t *testing.T) {
		f := newFakeRegistry(digestV054)
		v := serve(t, f)
		v.now = clock.now
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseRejected {
			t.Fatalf("no bundle yet: got %+v", got)
		}
		f.attach(t, fixture(t, "v0.5.4.slsa.json"), digestV054)
		clock.advance(rejectedTTL - time.Second)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseRejected {
			t.Fatalf("within rejectedTTL: got %+v", got)
		}
		clock.advance(time.Second)
		if got := v.Verify(v.Repository(), digestV054); got.Status != evidence.ReleaseAccepted {
			t.Fatalf("after rejectedTTL: got %+v", got)
		}
	})
}

// The cache is bounded, since a provider picks the digest its runtime record names: at the
// bound, expired verdicts go first, then everything but acceptances; an acceptance is
// never pushed out by a stream of rejections.
func TestVerify_CacheIsBounded(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)}
	v := embedded(t)
	v.now = clock.now
	digest := func(i int) string { return fmt.Sprintf("sha256:%064x", i) }
	v.remember(digestV054, evidence.ReleaseVerdict{Status: evidence.ReleaseAccepted})
	for i := 0; i < 3*maxCachedVerdicts; i++ {
		v.remember(digest(i), evidence.ReleaseVerdict{Reason: "a branch build"})
	}
	if len(v.cache) > maxCachedVerdicts {
		t.Fatalf("the cache holds %d verdicts, over %d", len(v.cache), maxCachedVerdicts)
	}
	if got, ok := v.cache[digestV054]; !ok || got.verdict.Status != evidence.ReleaseAccepted {
		t.Fatal("rejections pushed an acceptance out of the cache")
	}
}
