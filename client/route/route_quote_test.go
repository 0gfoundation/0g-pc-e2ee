package route

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/attest"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Known report_data contents (SPEC §4.2) for the fake quote parser.
const (
	qvEncPubHex = "4b2ca0d43e4c6a25ebe0995a65ead819e78c6db879a609309804f1dc4e09894d"
	qvSignerHex = "d45b4301940b297f76d6e622c1cea2ae660617d4"
	qvSignerStr = "0x" + qvSignerHex
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func qvReportData(t *testing.T) [64]byte {
	t.Helper()
	var rd [64]byte
	copy(rd[0:32], mustHex(t, qvEncPubHex))
	copy(rd[32:52], mustHex(t, qvSignerHex))
	rd[55] = 1 // version = 1, big-endian; reserved [56:64] stays zero
	return rd
}

func qvMeasurement(fill byte) attest.Measurement {
	var m attest.Measurement
	for i := range m.MRTD {
		m.MRTD[i] = fill
		m.RTMR0[i] = fill
		m.RTMR1[i] = fill
		m.RTMR2[i] = fill
		m.RTMR3[i] = fill
	}
	return m
}

// qvParser is a fake quoteParser returning fixed values, so the route path is
// exercised without real go-tdx-guest / collateral.
func qvParser(m attest.Measurement, rd [64]byte) func([]byte) (attest.Measurement, [64]byte, error) {
	return func([]byte) (attest.Measurement, [64]byte, error) { return m, rd, nil }
}

// qvServer serves the route-preview (one candidate whose endpoint is this same
// server) and a /v1/quote reply. quoteStatus overrides the quote status (0=200).
func qvServer(t *testing.T, quoteStatus int) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(previewResponse{
			Object:      "routing.preview",
			ServiceType: "chatbot",
			Providers: []previewProvider{{
				Address:     testProviderAddr,
				CanonicalID: "canon-1",
				Endpoint:    srv.URL,
				ModelID:     "gpt-4o@v1",
			}},
		})
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		if quoteStatus != 0 {
			http.Error(w, "boom", quoteStatus)
			return
		}
		_, _ = w.Write([]byte(`{"quote":"00"}`)) // bytes are ignored by the fake parser
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestProvider_QuoteVerification_EnforceSuccess(t *testing.T) {
	srv := qvServer(t, 0)
	m := qvMeasurement(0xaa)
	v := attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(m)}},
		attest.WithQuoteParser(qvParser(m, qvReportData(t))))
	r := New(srv.URL, WithQuoteVerification(v, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))

	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	prov, err := cands.Provider(context.Background(), 0)
	if err != nil {
		t.Fatalf("Provider: %v", err)
	}
	if got := hex.EncodeToString(prov.EncPubKey); got != qvEncPubHex {
		t.Errorf("EncPubKey = %s, want %s", got, qvEncPubHex)
	}
	if prov.SignerAddr != qvSignerStr {
		t.Errorf("SignerAddr = %s, want %s", prov.SignerAddr, qvSignerStr)
	}
	if prov.Address != testProviderAddr || prov.Model != "canon-1" {
		t.Errorf("Address/Model = %s/%s", prov.Address, prov.Model)
	}
	want, _ := r.upstreamURL(endpoint.Chat)
	if prov.URL != want {
		t.Errorf("URL = %s, want completions %s", prov.URL, want)
	}
}

func TestProvider_QuoteVerification_EnforceRejectsUntrusted(t *testing.T) {
	srv := qvServer(t, 0)
	served := qvMeasurement(0xbb)
	allowed := qvMeasurement(0xaa)
	v := attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(allowed)}},
		attest.WithQuoteParser(qvParser(served, qvReportData(t)))) // ModeEnforce (default)
	r := New(srv.URL, WithQuoteVerification(v, nil))

	cands, err := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := cands.Provider(context.Background(), 0); err == nil {
		t.Fatal("expected candidate to be rejected (measurement not allowlisted), got nil")
	}
}

func TestProvider_QuoteVerification_WarnAcceptsAndLogs(t *testing.T) {
	srv := qvServer(t, 0)
	served := qvMeasurement(0xbb) // not in allowlist
	var logbuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	v := attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(qvMeasurement(0xaa))}},
		attest.WithQuoteParser(qvParser(served, qvReportData(t))),
		attest.WithMeasurementMode(attest.ModeWarn))
	r := New(srv.URL, WithQuoteVerification(v, logger))

	cands, _ := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	prov, err := cands.Provider(context.Background(), 0)
	if err != nil {
		t.Fatalf("warn mode should accept: %v", err)
	}
	if hex.EncodeToString(prov.EncPubKey) != qvEncPubHex {
		t.Errorf("EncPubKey not bound: %x", prov.EncPubKey)
	}
	if s := logbuf.String(); !strings.Contains(s, "warn mode") || !strings.Contains(s, "level=WARN") {
		t.Errorf("expected a WARN log about the measurement, got: %q", s)
	}
}

func TestProvider_QuoteVerification_QuoteEndpointError(t *testing.T) {
	srv := qvServer(t, http.StatusServiceUnavailable)
	m := qvMeasurement(0xaa)
	v := attest.New(attest.BootChainPolicy{Allowed: []attest.BootChain{attest.BootChainOf(m)}},
		attest.WithQuoteParser(qvParser(m, qvReportData(t))))
	r := New(srv.URL, WithQuoteVerification(v, nil))

	cands, _ := r.Resolve(context.Background(), endpoint.Chat, wire.Request{})
	if _, err := cands.Provider(context.Background(), 0); err == nil {
		t.Fatal("expected error when the quote endpoint fails, got nil")
	}
}

func TestDeriveQuoteURL(t *testing.T) {
	cases := map[string]string{
		"https://h":                     "https://h/v1/quote?legacy=false",
		"https://h/v1":                  "https://h/v1/quote?legacy=false",
		"https://h/v1/chat/completions": "https://h/v1/quote?legacy=false",
		"https://h:8443/api/v1":         "https://h:8443/api/v1/quote?legacy=false",
	}
	for in, want := range cases {
		got, err := deriveQuoteURL(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("deriveQuoteURL(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := deriveQuoteURL("not-a-url"); err == nil {
		t.Error("expected error for non-absolute URL")
	}
}
