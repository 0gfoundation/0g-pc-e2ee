package route

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

func TestQuoteAdvertisesRespBind(t *testing.T) {
	for _, tc := range []struct {
		reply string
		want  bool
	}{
		{`{"quote":"00","e2ee_features":["resp-bind"]}`, true},
		{`{"quote":"00","e2ee_features":["other","resp-bind"]}`, true},
		{`{"quote":"00","e2ee_features":[]}`, false},
		{`{"quote":"00"}`, false},
		{`{"quote":"00","e2ee_features":"resp-bind"}`, false},
		{`not json`, false},
	} {
		if got := quoteAdvertisesRespBind([]byte(tc.reply)); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.reply, got, tc.want)
		}
	}
}

func TestRespBindStore(t *testing.T) {
	s := newRespBindStore(2)
	s.observe("0xAbC", true)
	if !s.supports("0xabc") {
		t.Fatal("addresses must compare case-insensitively")
	}
	// A verified reply without the feature turns it off (a broker rolled back).
	s.observe("0xabc", false)
	if s.supports("0xABC") {
		t.Fatal("a reply without the feature did not turn it off")
	}
	s.observe("0x1", true)
	s.observe("0x2", true)
	s.observe("0x3", true) // over the cap
	if s.supports("0x3") {
		t.Fatal("the store grew past its cap")
	}
	if !s.supports("0x1") || !s.supports("0x2") {
		t.Fatal("entries under the cap were lost")
	}
}

// featureServer is warmerServer whose /v1/quote reply advertises the response
// binding while advertise is set.
func featureServer(t *testing.T, addrs []string, advertise *atomic.Bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/providers", func(w http.ResponseWriter, r *http.Request) {
		data := make([]map[string]string, 0, len(addrs))
		for _, a := range addrs {
			data = append(data, map[string]string{"address": a})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		if advertise.Load() {
			_, _ = w.Write([]byte(`{"quote":"00","e2ee_features":["resp-bind"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"quote":"00"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// The warmer — and only the warmer — decides: a sweep that reads the feature at
// the on-chain URL turns it on, and the next one that reads its absence turns it
// off again.
func TestWarmer_DecidesTheResponseBinding(t *testing.T) {
	var advertise atomic.Bool
	advertise.Store(true)
	srv := featureServer(t, []string{"0xa"}, &advertise)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()), WithResponseBinding())

	if r.bindsResponse("0xa") {
		t.Fatal("bound before any sweep")
	}
	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	if !r.bindsResponse("0xa") {
		t.Fatal("a sweep that read the feature did not turn the binding on")
	}
	advertise.Store(false)
	r.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	if r.bindsResponse("0xa") {
		t.Fatal("a sweep that read its absence did not turn the binding off")
	}
}

// The request path's quote comes from a URL the router chose, so what it reads
// is never acted on: a stripped field there cannot downgrade a provider, and an
// added one cannot turn the binding on.
func TestRequestPathQuoteDoesNotDecideTheResponseBinding(t *testing.T) {
	var advertise atomic.Bool
	advertise.Store(true)
	srv := featureServer(t, nil, &advertise)
	r := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()), WithResponseBinding())
	res, _, err := r.verifiedProviderCached(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !res.facts.respBind {
		t.Fatal("precondition: the reply's feature should be read")
	}
	if r.bindsResponse("0xa") {
		t.Fatal("a request-path quote turned the binding on")
	}
}

// Nothing binds without the option, or without quote verification.
func TestResponseBindingNeedsTheOptionAndAVerifier(t *testing.T) {
	var advertise atomic.Bool
	advertise.Store(true)
	srv := featureServer(t, []string{"0xa"}, &advertise)

	off := New(srv.URL, WithQuoteVerification(qvVerifier(t), discardLogger()))
	off.WarmOnce(context.Background(), fakeResolver{url: srv.URL})
	if off.bindsResponse("0xa") {
		t.Fatal("bound without WithResponseBinding")
	}

	noVerifier := New(srv.URL, WithResponseBinding())
	noVerifier.respBind.observe("0xa", true)
	if noVerifier.bindsResponse("0xa") {
		t.Fatal("bound without quote verification")
	}
}

// The materialized candidate carries the warmer's decision for its address.
func TestProviderCarriesTheResponseBinding(t *testing.T) {
	srv := qvServer(t, 0)
	m := qvMeasurement(0xaa)
	v := attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(m)}},
		attest.WithQuoteParser(qvParser(m, qvReportData(t))))
	r := New(srv.URL, WithQuoteVerification(v, discardLogger()), WithResponseBinding())

	materialize := func() bool {
		t.Helper()
		cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		prov, err := cands.Provider(context.Background(), 0)
		if err != nil {
			t.Fatalf("Provider: %v", err)
		}
		return prov.BindResponse
	}
	if materialize() {
		t.Fatal("BindResponse set before the warmer saw the provider advertise it")
	}
	r.respBind.observe(testProviderAddr, true)
	if !materialize() {
		t.Fatal("BindResponse not set for a provider the warmer saw advertise it")
	}
}
