package route

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
)

// maxSignatureBytes bounds the §8 signature response read; a ChatSignature is a
// few hundred bytes, so this defends against a hostile/misconfigured endpoint.
const maxSignatureBytes = 64 << 10

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

// NewSignatureFetcher builds a fetcher. A nil client gets a bounded-timeout default.
func NewSignatureFetcher(hc *http.Client) *SignatureFetcher {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &SignatureFetcher{http: hc}
}

var _ core.SignatureFetcher = (*SignatureFetcher)(nil)

// FetchSignature GETs <endpoint>/v1/proxy/signature/{chatKey} and decodes the
// ChatSignature. A non-200 (e.g. 404 when nothing was cached) is an error, so
// verification fails closed rather than silently skipping.
func (f *SignatureFetcher) FetchSignature(ctx context.Context, provider core.Provider, chatKey string) (proof.ChatSignature, error) {
	if provider.Endpoint == "" {
		return proof.ChatSignature{}, fmt.Errorf("no provider endpoint to fetch the response signature from")
	}
	u, err := deriveSignatureURL(provider.Endpoint, chatKey)
	if err != nil {
		return proof.ChatSignature{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return proof.ChatSignature{}, err
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return proof.ChatSignature{}, fmt.Errorf("get signature: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return proof.ChatSignature{}, fmt.Errorf("signature endpoint returned %d", resp.StatusCode)
	}
	var sig proof.ChatSignature
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSignatureBytes)).Decode(&sig); err != nil {
		return proof.ChatSignature{}, fmt.Errorf("decode signature: %w", err)
	}
	return sig, nil
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
