package route

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/metrics"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
)

// maxSignatureBytes bounds the §8 signature response read; a ChatSignature is a
// few hundred bytes, so this defends against a hostile/misconfigured endpoint.
const maxSignatureBytes = 64 << 10

// Bounded retry for the fetch only (never for a verification mismatch, which
// does not reach this package). It absorbs the benign race where the broker has
// not yet cached the signature (a 404, since the cache is written at
// end-of-response) or a transient transport / 5xx hiccup. Total added latency is
// capped at sigFetchBackoff·(1+2) ≈ 600ms, and every wait honors ctx.
const (
	sigFetchAttempts = 3
	sigFetchBackoff  = 200 * time.Millisecond
)

// validChatKey mirrors the broker's allowlist (image_store.go): a chatKey is a
// UUID-shaped identifier. The value arrives in a response header from an
// untrusted hop, so it is validated before being placed in a URL path — a proven
// [A-Za-z0-9_-]{1,64} cannot traverse or inject.
var validChatKey = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// SignatureFetcher fetches the §8 ChatSignature DIRECTLY from the provider's
// broker endpoint. The router does not proxy /v1/proxy/signature/{chatKey}, so
// this bypasses it and talks to provider.Endpoint (the provider's own serving
// URL, ultimately the on-chain Service.url). It implements core.SignatureFetcher.
//
// Fetching over this (untrusted) path is safe: the signature is content-bound
// and anchored to the on-chain signer, so a tampered or forged reply simply
// fails verification fail-closed.
type SignatureFetcher struct {
	http *http.Client
}

// NewSignatureFetcher builds a fetcher. A nil client gets a bounded-timeout
// default over a server-sized connection pool: with verification on, this fetch
// runs once per RESPONSE against the provider's endpoint, so it is on the hot
// path and must not fall back to http.DefaultTransport's 2-idle-conns-per-host
// (see core.NewPooledTransport).
func NewSignatureFetcher(hc *http.Client) *SignatureFetcher {
	if hc == nil {
		hc = &http.Client{
			Timeout:   15 * time.Second,
			Transport: core.NewPooledTransport(),
		}
	}
	return &SignatureFetcher{http: hc}
}

var _ core.SignatureFetcher = (*SignatureFetcher)(nil)

// FetchSignature GETs <endpoint>/v1/proxy/signature/{chatKey} and decodes the
// ChatSignature, with a bounded retry on transient failures (transport error,
// 404-not-yet-cached, 5xx). A definitive failure (other 4xx, decode error, or the
// last retry) is returned, so verification fails closed rather than silently
// skipping.
func (f *SignatureFetcher) FetchSignature(ctx context.Context, provider core.Provider, chatKey string) (proof.ChatSignature, error) {
	// One observation per fetch on every exit path, recorded by a defer so no return
	// escapes it. This fetch is serial with the response — every verified completion
	// waits for it — so its latency is added to each of them, and "ok_retried" is
	// how the expected 404 race (the broker caches the signature at end-of-response)
	// shows up before it becomes a per-response backoff.
	//
	// Installed BEFORE the two checks below, which used to return ahead of it. Both
	// are real fail-closed verification failures — a candidate with no endpoint, or
	// an endpoint/chatKey (both from untrusted hops) that will not form a URL — and
	// skipping them left exactly the blind spot this counter exists to close: the
	// response goes unverified while the §8 panel reads zero.
	start := time.Now()
	outcome := "failed"
	defer func() { metrics.SignatureFetch(outcome, time.Since(start)) }()

	if provider.Endpoint == "" {
		return proof.ChatSignature{}, fmt.Errorf("no provider endpoint to fetch the response signature from")
	}
	u, err := deriveSignatureURL(provider.Endpoint, chatKey)
	if err != nil {
		return proof.ChatSignature{}, err
	}

	var lastErr error
	for attempt := 0; attempt < sigFetchAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				outcome = endedBy(ctx)
				return proof.ChatSignature{}, ctx.Err()
			case <-time.After(sigFetchBackoff << (attempt - 1)):
			}
		}
		sig, retryable, err := f.fetchOnce(ctx, u)
		if err == nil {
			outcome = "ok"
			if attempt > 0 {
				outcome = "ok_retried"
			}
			return sig, nil
		}
		lastErr = err
		// Only a RETRYABLE failure may be re-attributed. fetchOnce's other three
		// conclusions are the broker ANSWERING definitively — a non-404 4xx, or a body
		// that will not decode — and relabelling those because the context happened to
		// be done files a corrupt signature from a provider under "canceled", the one
		// bucket every alert deliberately ignores. That is the same blind spot the
		// relocated defers were installed to close, and the same guard preview
		// (res == previewRetryable) and verifyOutcome (concluded != unverifiable)
		// already carry. This site was written without it.
		if retryable && ctx.Err() != nil {
			// Something other than the broker ended this; that says nothing about it.
			outcome = endedBy(ctx)
			return proof.ChatSignature{}, err
		}
		if !retryable {
			return proof.ChatSignature{}, err
		}
	}
	return proof.ChatSignature{}, fmt.Errorf("after %d attempts: %w", sigFetchAttempts, lastErr)
}

// fetchOnce performs a single GET. retryable is true only for a transient failure
// worth another attempt — a transport error, a 404 (the broker caches the
// signature at end-of-response, so a just-finished response can momentarily miss),
// or a 5xx — and false for a definitive one (other 4xx, decode error).
func (f *SignatureFetcher) fetchOnce(ctx context.Context, url string) (proof.ChatSignature, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return proof.ChatSignature{}, false, err
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return proof.ChatSignature{}, true, fmt.Errorf("get signature: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusNotFound || (resp.StatusCode >= 500 && resp.StatusCode <= 599)
		return proof.ChatSignature{}, retryable, fmt.Errorf("signature endpoint %s returned %d", url, resp.StatusCode)
	}
	var sig proof.ChatSignature
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSignatureBytes)).Decode(&sig); err != nil {
		return proof.ChatSignature{}, false, fmt.Errorf("decode signature: %w", err)
	}
	return sig, false, nil
}

// deriveSignatureURL builds <v1-base>/proxy/signature/{chatKey} from a provider
// endpoint, mirroring derivePubkeyURL (the broker serves it under ServicePrefix
// "/v1/proxy").
func deriveSignatureURL(endpoint, chatKey string) (string, error) {
	if !validChatKey.MatchString(chatKey) {
		return "", fmt.Errorf("invalid chatKey %q", chatKey)
	}
	base, err := deriveV1Base(endpoint)
	if err != nil {
		return "", err
	}
	return base + "/proxy/signature/" + chatKey, nil
}

// endedBy names who ended a fetch whose context is done, which is NOT always the
// caller: core hands this fetcher a context derived from the attempt, so the
// buffered path's providerTimeout expiring mid-fetch arrives here indistinguishable
// from a disconnect unless the error kind is read. It was all counted "canceled",
// which put our own deadline in the bucket every alert ignores.
//
// context.Canceled means somebody called cancel — in practice the caller going
// away. context.DeadlineExceeded means a deadline fired, and the only deadlines on
// this path are ours (providerTimeout) plus the fetcher's own client timeout.
//
// Two residual ambiguities, stated because they are real: a CALLER that set its own
// deadline reads as timeout, and a stream whose idle watchdog fires (a cancel, not
// a deadline) reads as canceled. Both are narrower than lumping everything into one
// bucket, and neither can be resolved without threading the parent context through
// core.SignatureFetcher — which is not worth an interface change for this.
func endedBy(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	return "canceled"
}
