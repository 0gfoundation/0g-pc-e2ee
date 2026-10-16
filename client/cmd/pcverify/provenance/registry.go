package provenance

// registry.go fetches the Sigstore bundles attached to an image in an OCI registry.
//
// Attachments are OCI referrers: artifact manifests whose `subject` is the image. A
// registry that implements the referrers API answers GET /v2/<name>/referrers/<digest>;
// ghcr.io does not (404), and clients there fall back to the referrers TAG schema — an
// index tagged sha256-<hex> listing the artifacts. Both are read.
//
// WHAT IS TRUSTED HERE: nothing. The registry chooses what it returns, so every byte is
// either checked by digest (manifests and blobs against the descriptors that name them)
// or verified later by Sigstore (the bundles). The registry can withhold bundles — the
// build is then rejected or the check reported unavailable — but it cannot make a build
// pass.
//
// AN ABSENT ARTIFACT IS NOT AN OUTAGE. The fallback index is maintained by the clients
// that push to it, and entries in it can outlive the manifests they name: v0.5.1's lists
// a provenance manifest the registry no longer has. A 404 on a listed manifest is skipped,
// not reported as "registry unavailable" — otherwise one stale entry would block a
// verdict on that build forever. Only transport failures, server errors, throttling and
// refused credentials make a check unavailable.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	mediaIndex    = "application/vnd.oci.image.index.v1+json"
	mediaManifest = "application/vnd.oci.image.manifest.v1+json"
	// sigstoreBundlePrefix covers every Sigstore bundle version's media type.
	sigstoreBundlePrefix = "application/vnd.dev.sigstore.bundle"

	maxIndexBytes    = 4 << 20
	maxManifestBytes = 4 << 20
	maxBundleBytes   = 1 << 20
	// maxReferrers bounds the work one image can ask of a verifier.
	maxReferrers = 32
)

// unavailableError marks a failure that says nothing about the build: the registry did
// not answer. The verdict is then evidence.ReleaseUnavailable, never a rejection.
type unavailableError struct{ err error }

func (e *unavailableError) Error() string {
	return "the registry could not be read: " + e.err.Error()
}

func unavailable(format string, args ...any) error {
	return &unavailableError{fmt.Errorf(format, args...)}
}

type registry struct {
	client  *http.Client
	timeout time.Duration

	mu     sync.Mutex
	tokens map[string]string // auth challenge (realm+service+scope) -> bearer token
}

func newRegistry(client *http.Client, timeout time.Duration) *registry {
	if client == nil {
		client = http.DefaultClient
	}
	return &registry{client: client, timeout: timeout, tokens: map[string]string{}}
}

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType"`
	Annotations  map[string]string `json:"annotations"`
}

type index struct {
	Manifests []descriptor `json:"manifests"`
}

type manifest struct {
	Subject *descriptor  `json:"subject"`
	Layers  []descriptor `json:"layers"`
}

// bundles returns every Sigstore bundle attached to repository@digest. No referrers at
// all is (nil, nil): a statement about the build, which judge turns into a rejection.
func (r *registry) bundles(repository, digest string) ([][]byte, error) {
	host, name, ok := strings.Cut(repository, "/")
	if !ok || name == "" {
		return nil, fmt.Errorf("%q names no registry host", repository)
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	idx, err := r.referrers(ctx, host, name, digest)
	if err != nil || idx == nil {
		return nil, err
	}
	if len(idx.Manifests) > maxReferrers {
		idx.Manifests = idx.Manifests[:maxReferrers]
	}
	var out [][]byte
	for _, d := range idx.Manifests {
		if !isSHA256Digest(d.Digest) {
			continue
		}
		raw, status, err := r.get(ctx, host, name, "manifests/"+d.Digest, mediaManifest, maxManifestBytes)
		switch {
		case err != nil:
			return nil, err
		case status == http.StatusNotFound:
			continue // a stale entry; see the file comment
		case status != http.StatusOK:
			return nil, unavailable("manifest %s: HTTP %d", d.Digest, status)
		case !digestMatches(raw, d.Digest):
			continue
		}
		var m manifest
		if json.Unmarshal(raw, &m) != nil || m.Subject == nil || m.Subject.Digest != digest {
			continue // not an attachment to this image
		}
		for _, l := range m.Layers {
			if !strings.HasPrefix(l.MediaType, sigstoreBundlePrefix) || !isSHA256Digest(l.Digest) {
				continue
			}
			blob, status, err := r.get(ctx, host, name, "blobs/"+l.Digest, "", maxBundleBytes)
			switch {
			case err != nil:
				return nil, err
			case status == http.StatusNotFound:
				continue
			case status != http.StatusOK:
				return nil, unavailable("blob %s: HTTP %d", l.Digest, status)
			case digestMatches(blob, l.Digest):
				out = append(out, blob)
			}
		}
	}
	return out, nil
}

// referrers returns the image's referrers index, from the referrers API or the fallback
// tag, or nil when the registry has none.
func (r *registry) referrers(ctx context.Context, host, name, digest string) (*index, error) {
	raw, status, err := r.get(ctx, host, name, "referrers/"+digest, mediaIndex, maxIndexBytes)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound || status == http.StatusBadRequest {
		tag := "sha256-" + strings.TrimPrefix(digest, "sha256:")
		raw, status, err = r.get(ctx, host, name, "manifests/"+tag, mediaIndex+", "+mediaManifest, maxIndexBytes)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound {
			return nil, nil
		}
	}
	if status != http.StatusOK {
		return nil, unavailable("referrers of %s: HTTP %d", digest, status)
	}
	var idx index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("the registry's referrers index for %s does not parse: %v", digest, err)
	}
	return &idx, nil
}

// get fetches /v2/<name>/<path>, answering one bearer-token challenge if the registry
// asks. It returns the body only for 200; a transport failure, throttling or a server
// error is an unavailableError.
func (r *registry) get(ctx context.Context, host, name, path, accept string, limit int64) ([]byte, int, error) {
	u := "https://" + host + "/v2/" + name + "/" + path
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, 0, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if tok := r.token(host); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := r.client.Do(req)
		if err != nil {
			return nil, 0, unavailable("%s: %v", path, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		switch {
		case err != nil:
			return nil, 0, unavailable("%s: %v", path, err)
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			if err := r.authorize(ctx, host, resp.Header.Get("WWW-Authenticate")); err != nil {
				return nil, 0, err
			}
			continue
		case resp.StatusCode == http.StatusOK && int64(len(body)) > limit:
			return nil, 0, fmt.Errorf("%s is larger than %d bytes", path, limit)
		case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusNotFound,
			resp.StatusCode == http.StatusBadRequest:
			return body, resp.StatusCode, nil
		}
		return nil, 0, unavailable("%s: HTTP %d", path, resp.StatusCode)
	}
	return nil, 0, unavailable("%s: the registry refused the credentials it issued", path)
}

func (r *registry) token(host string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tokens[host]
}

// authorize answers a Bearer challenge anonymously: fetch a pull token from the realm it
// names. The realm must be HTTPS; the token only authorizes reads of a public image.
func (r *registry) authorize(ctx context.Context, host, challenge string) error {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return unavailable("the registry asked for %q authentication", scheme)
	}
	p := parseChallenge(params)
	realm, err := url.Parse(p["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" {
		return unavailable("the registry's token realm %q is not an HTTPS URL", p["realm"])
	}
	q := realm.Query()
	for _, k := range []string{"service", "scope"} {
		if p[k] != "" {
			q.Set(k, p[k])
		}
	}
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return unavailable("token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return unavailable("token: HTTP %d", resp.StatusCode)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&t); err != nil {
		return unavailable("token: %v", err)
	}
	tok := t.Token
	if tok == "" {
		tok = t.AccessToken
	}
	if tok == "" {
		return unavailable("token: the registry issued none")
	}
	r.mu.Lock()
	r.tokens[host] = tok
	r.mu.Unlock()
	return nil
}

// parseChallenge reads key="value" pairs from a WWW-Authenticate parameter list.
func parseChallenge(s string) map[string]string {
	out := map[string]string{}
	for s != "" {
		s = strings.TrimLeft(s, " ,")
		k, rest, ok := strings.Cut(s, "=")
		if !ok {
			break
		}
		var v string
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end < 0 {
				break
			}
			v, s = rest[1:1+end], rest[2+end:]
		} else {
			v, s, _ = strings.Cut(rest, ",")
		}
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}

func digestMatches(b []byte, digest string) bool {
	sum := sha256.Sum256(b)
	return "sha256:"+hex.EncodeToString(sum[:]) == digest
}
