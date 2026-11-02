// Command quoter mints the nonce-bound quote behind the gateway's GET /evidence
// (client/freshquote). It is the only long-running container besides dstack-ingress
// that holds the dstack guest-agent socket, and it holds it so the gateway does not:
// the gateway handles user prompts, and with the socket it could get a quote over any
// report_data. Here the report_data is fixed — the caller supplies only a nonce, and
// the public key comes from the certificate file this process reads itself.
//
// It listens on the compose network only (no published port); the gateway is its
// one client.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/dstack"
	"github.com/0gfoundation/0g-pc-e2ee/client/freshquote"
)

// quotePath is the one route. The gateway calls it as quotePath+"?nonce=<hex>".
const quotePath = "/quote"

// quoteTimeout bounds one GetQuote call. A quote takes tens of milliseconds; this
// only keeps a wedged agent from holding a slot.
const quoteTimeout = 10 * time.Second

func main() {
	listen := flag.String("listen", ":8090", "address to listen on (compose network only)")
	certFile := flag.String("cert", "", "PEM certificate whose leaf public key is bound into each quote "+
		"(the dstack-ingress evidences/cert-<domain>.pem)")
	socket := flag.String("dstack-socket", dstack.DefaultSocket, "dstack guest-agent unix socket")
	maxConcurrent := flag.Int("max-concurrent", 4, "quotes minted at once; further requests get 429")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if *certFile == "" || *maxConcurrent < 1 {
		logger.Error("quoter: -cert is required and -max-concurrent must be >= 1")
		os.Exit(2)
	}
	getQuote := func(ctx context.Context, rd [64]byte) ([]byte, error) {
		return dstack.GetQuote(ctx, *socket, rd)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(*certFile, getQuote, *maxConcurrent, logger),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      quoteTimeout + 5*time.Second,
	}
	logger.Info("quoter listening", "listen", *listen, "cert", *certFile)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("quoter", "err", err)
		os.Exit(1)
	}
}

type quoteFunc func(ctx context.Context, reportData [64]byte) ([]byte, error)

func newHandler(certFile string, getQuote quoteFunc, maxConcurrent int, logger *slog.Logger) http.Handler {
	slots := make(chan struct{}, maxConcurrent)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+quotePath, func(w http.ResponseWriter, r *http.Request) {
		nonce, err := freshquote.ParseNonce(r.URL.Query().Get("nonce"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		// Read per request: a renewal may replace the key, and the quote must bind
		// the certificate being served now.
		pemBytes, err := os.ReadFile(certFile)
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "certificate not issued yet", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			logger.Error("read certificate", "err", err)
			http.Error(w, "certificate unreadable", http.StatusInternalServerError)
			return
		}
		pub, err := freshquote.SPKIBase64(pemBytes)
		if err != nil {
			logger.Error("parse certificate", "err", err)
			http.Error(w, "certificate unparseable", http.StatusInternalServerError)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), quoteTimeout)
		defer cancel()
		quote, err := getQuote(ctx, freshquote.ReportData(nonce, pub))
		if err != nil {
			logger.Error("GetQuote", "err", err)
			http.Error(w, "quote unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(freshquote.Response{
			Quote:     base64.StdEncoding.EncodeToString(quote),
			E2EPubkey: pub,
		})
	})
	return mux
}
