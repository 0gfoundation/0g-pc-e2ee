package core_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// rotatedEnclave is a broker that has rotated its enc key: a request sealed to any
// other key gets the broker's stale-key 409, and one sealed to the current key is
// opened and answered by the wrapped bindEnclave.
type rotatedEnclave struct {
	*bindEnclave
	keyID string
	hits  int32
}

func (e *rotatedEnclave) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&e.hits, 1)
	body, _ := io.ReadAll(r.Body)
	if !bytes.Contains(body, []byte(`"key_id":"`+e.keyID+`"`)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":"e2ee_key_mismatch: sealed request key_id is not the enclave's current enc key; re-fetch the enc key and re-seal"}`)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	e.bindEnclave.ServeHTTP(w, r)
}

// rekeyCandidates is one candidate materialized from a stale cache entry, whose
// re-read returns the rotated key.
type rekeyCandidates struct {
	stale, current core.Provider
}

func (c rekeyCandidates) Len() int { return 1 }
func (c rekeyCandidates) Provider(context.Context, int) (core.Provider, error) {
	return c.stale, nil
}
func (c rekeyCandidates) RefreshProvider(context.Context, int, crypto.PublicKey) (core.Provider, error) {
	return c.current, nil
}

type rekeyResolver struct{ rekeyCandidates }

func (r rekeyResolver) Resolve(context.Context, endpoint.Endpoint, wire.Request) (core.Candidates, error) {
	return r.rekeyCandidates, nil
}

func newRotatedEnclave(t *testing.T) (*rotatedEnclave, rekeyCandidates) {
	t.Helper()
	encPriv, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encPub)
	e := &rotatedEnclave{
		bindEnclave: &bindEnclave{encPriv: encPriv},
		keyID:       base64.RawURLEncoding.EncodeToString(sum[:8]),
	}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	current := core.Provider{
		URL:          srv.URL + "/v1/chat/completions",
		EncPubKey:    encPub,
		SignerAddr:   "0x0000000000000000000000000000000000000001",
		BindResponse: true,
	}
	_, oldPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	stale := current
	stale.EncPubKey = oldPub
	return e, rekeyCandidates{stale: stale, current: current}
}

// Through the real seal and open: the request rejected for the old key is re-sealed
// to the rotated one, the enclave opens it, and the caller gets the answer — on
// both the buffered and the streamed path.
func TestE2E_RotatedKeyIsResealed(t *testing.T) {
	t.Run("buffered", func(t *testing.T) {
		e, cands := newRotatedEnclave(t)
		out, err := core.NewWithResolver(rekeyResolver{cands}).Complete(context.Background(), chatReq(false))
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if !strings.Contains(string(out["choices"]), "genuine") {
			t.Fatalf("choices = %s", out["choices"])
		}
		if got := atomic.LoadInt32(&e.hits); got != 2 {
			t.Errorf("enclave hits = %d, want 2", got)
		}
	})
	t.Run("stream", func(t *testing.T) {
		e, cands := newRotatedEnclave(t)
		got, err := collect(t, core.NewWithResolver(rekeyResolver{cands}))
		if err != nil {
			t.Fatalf("CompleteStream: %v", err)
		}
		if strings.Count(got, "genuine") != 3 {
			t.Fatalf("delivered %q, want three genuine frames", got)
		}
		if got := atomic.LoadInt32(&e.hits); got != 2 {
			t.Errorf("enclave hits = %d, want 2", got)
		}
	})
}
