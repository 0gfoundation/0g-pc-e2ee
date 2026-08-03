package core

import (
	"context"
	"fmt"
	"net/http"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// headerResKey is the response header carrying the broker's chatKey (a UUID).
// The client uses it to fetch the §8 signature for the just-received response
// (SPEC §8; broker sets it as ZG-Res-Key). Verification is a second, deferred
// step: the signature is produced at end-of-response, so it is fetched after the
// body (or, for streaming, after the final frame).
const headerResKey = "ZG-Res-Key"

// SignatureFetcher retrieves the §8 ChatSignature the broker cached for a
// response, keyed by the chatKey from the ZG-Res-Key header. The transport
// (through the router on /v1/proxy/signature/{chatKey}, or direct to the broker)
// lives entirely behind this interface — an open question tracked in
// 0g-pc-e2ee#48 — so the client core stays indifferent to it. It is content-
// bound and on-chain-anchored, so an untrusted fetch path cannot forge it.
type SignatureFetcher interface {
	FetchSignature(ctx context.Context, provider Provider, chatKey string) (proof.ChatSignature, error)
}

// WithResponseVerification enables §8 response-signature verification (trust-chain
// hop 11). Both a fetcher and a recover function are required; omitting either
// (the default) leaves verification off, so existing callers are unchanged.
//
// recover is the secp256k1/keccak EIP-191 recovery (client/sig.Recover). Keeping
// it injected keeps protocol/proof dependency-light.
func WithResponseVerification(fetch SignatureFetcher, recover proof.RecoverFunc) Option {
	return func(c *Client) {
		c.sigFetcher = fetch
		c.recover = recover
	}
}

// verifyEnabled reports whether response verification is configured.
func (c *Client) verifyEnabled() bool {
	return c.sigFetcher != nil && c.recover != nil
}

// verifyNonStream verifies a buffered (non-stream) E2EE response, fail-closed. It
// anchors on provider.SignerAddr — the on-chain TEE signer the resolver already
// grounded (hop 5) — never the signature's self-reported address.
func (c *Client) verifyNonStream(ctx context.Context, provider Provider, header http.Header, reqEnv wire.Request, respFrame wire.Response) error {
	sig, err := c.fetchSig(ctx, provider, header)
	if err != nil {
		return err
	}
	if err := sig.VerifyE2EE(reqEnv, respFrame, provider.SignerAddr, c.recover); err != nil {
		return fmt.Errorf("response signature: %w", err)
	}
	return nil
}

// verifyStream verifies a streamed E2EE response after the final frame, using the
// binder the receive loop folded each sealed frame into (no full-response buffer).
func (c *Client) verifyStream(ctx context.Context, provider Provider, header http.Header, binder *proof.StreamBinder) error {
	want, err := binder.Text()
	if err != nil {
		return err
	}
	sig, err := c.fetchSig(ctx, provider, header)
	if err != nil {
		return err
	}
	if err := sig.VerifyBoundText(want, proof.SchemeE2EECiphertextStream, provider.SignerAddr, c.recover); err != nil {
		return fmt.Errorf("response signature: %w", err)
	}
	return nil
}

// fetchSig reads the chatKey handle and fetches the signature. A missing header
// with verification enabled is fail-closed: a response we were asked to verify
// carries no way to fetch its proof.
func (c *Client) fetchSig(ctx context.Context, provider Provider, header http.Header) (proof.ChatSignature, error) {
	chatKey := header.Get(headerResKey)
	if chatKey == "" {
		return proof.ChatSignature{}, fmt.Errorf("response verification enabled but no %s header", headerResKey)
	}
	sig, err := c.sigFetcher.FetchSignature(ctx, provider, chatKey)
	if err != nil {
		return proof.ChatSignature{}, fmt.Errorf("fetch signature: %w", err)
	}
	return sig, nil
}
