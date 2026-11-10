// Package clientip tells the router who the client is, in a form only the gateway
// can produce.
//
// The router sees every request that comes through the gateway from the gateway's
// egress address, so its per-IP rate limits and quotas put every gateway user in
// one bucket. This package lets the gateway name the client's address (which it
// learns from the PROXY protocol header, see cmd/internal/proxyproto) in three
// request headers, authenticated with an HMAC key the gateway and the router
// share:
//
//	X-0G-Client-IP:     203.0.113.7
//	X-0G-Client-IP-Ts:  1762790000                       (unix seconds)
//	X-0G-Client-IP-Sig: hex(HMAC-SHA256(key, Message(ip, ts)))
//
// The router believes the address only when the signature verifies with one of its
// keys and the timestamp is within its window; anything else is ignored, so a
// caller who sends these headers itself — to the gateway or straight to the router
// — gains nothing. The source address alone could not serve: the gateway's egress
// is a cloud node's, shared with other tenants and changing when the CVM moves.
//
// What the address is worth. It comes from the dstack gateway, an L4 relay outside
// the TEE, by way of dstack-ingress. It is good enough to rate-limit and block on;
// it is not something the attestation vouches for.
//
// Where it goes. Only to the router: Stamp signs a request only when its target is
// the router host the Signer was built with, so a provider's broker — a third party
// — never receives a client's address, whichever call site Stamp is used at. And
// never into logs or metric labels: this CVM's logs are public.
package clientip

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Header names. The router reads exactly these; keep them in step with its
// verifier (0g-router backend/internal/middleware/client_ip_header.go).
const (
	HeaderIP  = "X-0G-Client-IP"
	HeaderTs  = "X-0G-Client-IP-Ts"
	HeaderSig = "X-0G-Client-IP-Sig"
)

// version prefixes the signed message so a future format cannot be confused with
// this one.
const version = "0g-client-ip/v1"

// MinKeyBytes is the shortest key accepted: HMAC-SHA256's block-size-independent
// security is bounded by the key, and 32 bytes matches the hash.
const MinKeyBytes = 32

// Message is the byte string the signature covers. The router builds the same
// bytes from the received headers.
func Message(ip string, ts int64) []byte {
	return []byte(version + "\n" + ip + "\n" + strconv.FormatInt(ts, 10))
}

// Sign returns hex(HMAC-SHA256(key, Message(ip, ts))).
func Sign(key []byte, ip string, ts int64) string {
	m := hmac.New(sha256.New, key)
	m.Write(Message(ip, ts))
	return hex.EncodeToString(m.Sum(nil))
}

// Signer stamps router-bound requests with the client's address.
type Signer struct {
	key        []byte
	routerHost string // canonicalHost of the router URL: scheme://host[:port]
	now        func() time.Time
}

// NewSigner returns a Signer for requests to router. hexKey is the shared key,
// hex-encoded, at least MinKeyBytes long.
func NewSigner(hexKey string, router *url.URL) (*Signer, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, fmt.Errorf("client IP key is not hex: %w", err)
	}
	if len(key) < MinKeyBytes {
		return nil, fmt.Errorf("client IP key is %d bytes, want at least %d", len(key), MinKeyBytes)
	}
	if router == nil || router.Host == "" {
		return nil, errors.New("client IP signer needs the router URL")
	}
	return &Signer{key: key, routerHost: canonicalHost(router), now: time.Now}, nil
}

type ctxKey struct{}

type state struct {
	signer *Signer
	ip     string
}

// Middleware records the client's address for the request, for Stamp to sign. The
// address is the host of r.RemoteAddr, which under -proxy-protocol is the client's;
// a loopback or unparseable peer (the -health probe, a local run) records nothing.
func (s *Signer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(s.WithClient(r.Context(), r.RemoteAddr)))
	})
}

// WithClient returns ctx carrying remoteAddr's IP for Stamp to sign with s. A
// loopback or unparseable remoteAddr returns ctx unchanged.
func (s *Signer) WithClient(ctx context.Context, remoteAddr string) context.Context {
	ip := clientAddr(remoteAddr)
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, state{signer: s, ip: ip})
}

// Strip removes the three headers. Every header a client sends in the X-0G-*
// namespace is otherwise forwarded to the router, and these are not the client's
// to set; the router would reject a forged set anyway, but it should never see one
// from us.
func Strip(h http.Header) {
	h.Del(HeaderIP)
	h.Del(HeaderTs)
	h.Del(HeaderSig)
}

// Stamp strips any client-supplied copies of the headers from req and, when the
// request's context carries an address (Middleware) and req targets the router,
// sets a freshly signed set. Safe to call on any outbound request: one bound
// elsewhere, or made outside a client request, is only stripped.
func Stamp(req *http.Request) {
	Strip(req.Header)
	st, ok := req.Context().Value(ctxKey{}).(state)
	if !ok || req.URL == nil || canonicalHost(req.URL) != st.signer.routerHost {
		return
	}
	ts := st.signer.now().Unix()
	req.Header.Set(HeaderIP, st.ip)
	req.Header.Set(HeaderTs, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSig, Sign(st.signer.key, st.ip, ts))
}

// clientAddr returns the canonical text of remoteAddr's IP, or "" for a loopback
// or unparseable one.
func clientAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// canonicalHost is u's scheme://host[:port], lower-cased, with the scheme's default
// port dropped, so https://Router.example and https://router.example:443 compare
// equal while http://router.example does not: the scheme is part of the match, so
// a router configured over https is never sent the address in clear text.
func canonicalHost(u *url.URL) string {
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	return scheme + "://" + host
}
