package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// transitCands is a candidate list carrying the router's encrypted_transit.
// With p unset every candidate fails to materialize (nothing is ever sent); with
// block set each one waits for its context instead; with p set every candidate
// is p.
type transitCands struct {
	transit string
	n       int
	p       *Provider
	block   bool
}

func (t transitCands) Len() int                 { return t.n }
func (t transitCands) EncryptedTransit() string { return t.transit }
func (t transitCands) Provider(ctx context.Context, _ int) (Provider, error) {
	switch {
	case t.p != nil:
		return *t.p, nil
	case t.block:
		<-ctx.Done()
		return Provider{}, ctx.Err()
	}
	return Provider{}, errors.New("no key to seal to")
}

func transitChatReq() wire.Request {
	return wire.Request{
		"model":    json.RawMessage(`"glm-5"`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}
}

// The caller permitted plaintext and nothing was sent: hand the request back to
// go out in the clear, on all three walks, whatever the router said short of
// required — the router can veto, never grant.
func TestNoEncryptedProvider_CallerPermitsAndNothingSent(t *testing.T) {
	ctx := WithPlaintextPermitted(context.Background())
	for _, routerSays := range []string{TransitPreferred, "", TransitOff} {
		cands := transitCands{transit: routerSays, n: 3}
		c := NewWithResolver(fixedResolver{cands})
		if _, err := c.Complete(ctx, transitChatReq()); !errors.Is(err, ErrNoEncryptedProvider) {
			t.Errorf("router %q: Complete err = %v, want ErrNoEncryptedProvider", routerSays, err)
		}
		stream := transitChatReq()
		stream["stream"] = json.RawMessage(`true`)
		if err := c.CompleteStream(ctx, stream, func(wire.Response) error { return nil }); !errors.Is(err, ErrNoEncryptedProvider) {
			t.Errorf("router %q: CompleteStream err = %v, want ErrNoEncryptedProvider", routerSays, err)
		}
		async := NewWithResolver(fixedResolver{cands}, WithEndpoint(endpoint.AsyncImage))
		if _, _, err := async.SubmitAsync(ctx, wire.Request{"model": json.RawMessage(`"z-image"`), "prompt": json.RawMessage(`"p"`)}); !errors.Is(err, ErrNoEncryptedProvider) {
			t.Errorf("router %q: SubmitAsync err = %v, want ErrNoEncryptedProvider", routerSays, err)
		}
	}
}

// The router alone can never make the request go out in the clear: without the
// caller's permission its preferred (or off) keeps the walk's own error. With
// the permission, its required vetoes; so does a caller that went away.
func TestNoEncryptedProvider_RouterCannotGrant(t *testing.T) {
	for name, tc := range map[string]struct {
		ctx     context.Context
		transit string
	}{
		"router preferred, no permission": {context.Background(), TransitPreferred},
		"router off, no permission":       {context.Background(), TransitOff},
		"permission, router required":     {WithPlaintextPermitted(context.Background()), TransitRequired},
	} {
		c := NewWithResolver(fixedResolver{transitCands{transit: tc.transit, n: 2}})
		if _, err := c.Complete(tc.ctx, transitChatReq()); err == nil || errors.Is(err, ErrNoEncryptedProvider) {
			t.Errorf("%s: err = %v, want the walk's own error", name, err)
		}
	}
	ctx, cancel := context.WithCancel(WithPlaintextPermitted(context.Background()))
	cancel()
	c := NewWithResolver(fixedResolver{transitCands{transit: TransitPreferred, n: 2}})
	if _, err := c.Complete(ctx, transitChatReq()); errors.Is(err, ErrNoEncryptedProvider) {
		t.Error("a caller that went away must not be downgraded")
	}
}

// A walk the budget cut short is not downgraded: the caller has already waited
// all of it.
func TestNoEncryptedProvider_NotAfterTheBudget(t *testing.T) {
	c := NewWithResolver(fixedResolver{transitCands{transit: TransitPreferred, n: 3, block: true}})
	c.resolveBudgetTO = 50 * time.Millisecond
	if _, err := c.Complete(WithPlaintextPermitted(context.Background()), transitChatReq()); err == nil || errors.Is(err, ErrNoEncryptedProvider) {
		t.Errorf("err = %v, want the budget error", err)
	}
}

// A walk that SENT a sealed request is never downgraded: a provider may already
// be serving it, and sending it again in the clear would run it twice.
func TestNoEncryptedProvider_NotAfterASend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{URL: srv.URL, EncPubKey: encPub, Address: "0xC0FFEE0000000000000000000000000000000001",
		SignerAddr: "0xd45b4301940B297F76d6e622c1CeA2AE660617d4"}
	c := NewWithResolver(fixedResolver{transitCands{transit: TransitPreferred, n: 2, p: p}})
	_, err = c.Complete(WithPlaintextPermitted(context.Background()), transitChatReq())
	var e *Error
	if errors.Is(err, ErrNoEncryptedProvider) || !errors.As(err, &e) || e.Status != http.StatusServiceUnavailable {
		t.Errorf("err = %v, want the provider's 503", err)
	}
}
