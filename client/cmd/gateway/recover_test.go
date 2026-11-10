package main

import (
	"bytes"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe bytes.Buffer: the server logs from its own
// connection goroutine while the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// clientAddrListener makes every accepted connection report a fixed, recognisable
// "client" address, standing in for what proxyproto hands net/http after reading
// a PROXY header.
type clientAddrListener struct{ net.Listener }

const fakeClientAddr = "203.0.113.77:51234"

func (l clientAddrListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return fixedRemote{c}, nil
}

type fixedRemote struct{ net.Conn }

func (fixedRemote) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", fakeClientAddr)
	return a
}

// serveWithLogs runs h behind recoverWithoutAddress on a server whose ErrorLog and
// application logger both write to buffers the test can inspect, and makes one
// request.
func serveWithLogs(t *testing.T, h http.Handler) (appLog, serverLog string, gotResponse bool) {
	t.Helper()
	var app, srvLog syncBuffer
	logger := slog.New(slog.NewTextHandler(&app, nil))

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:  recoverWithoutAddress(logger, h),
		ErrorLog: log.New(&srvLog, "", 0),
	}
	go func() { _ = srv.Serve(clientAddrListener{inner}) }()
	defer srv.Close()

	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET /boom HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	resp, _ := io.ReadAll(c)

	// The server goroutine logs after the connection is torn down; give it a moment.
	time.Sleep(50 * time.Millisecond)
	return app.String(), srvLog.String(), len(resp) > 0
}

// The finding this guards: a handler panic used to reach net/http's recovery, which
// logs the RemoteAddr — the client's real IP once PROXY protocol is on — to public
// logs. Now neither log names it, the panic is still recorded, and the client still
// gets no response (the connection is aborted, as before).
func TestHandlerPanicLogsNoClientAddress(t *testing.T) {
	appLog, serverLog, gotResponse := serveWithLogs(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("kaboom")
	}))
	ip := strings.Split(fakeClientAddr, ":")[0]
	if strings.Contains(appLog, ip) || strings.Contains(serverLog, ip) {
		t.Fatalf("client address logged:\napp: %s\nserver: %s", appLog, serverLog)
	}
	if !strings.Contains(appLog, "handler panic") || !strings.Contains(appLog, "kaboom") {
		t.Fatalf("panic not recorded in the app log: %s", appLog)
	}
	if strings.Contains(serverLog, "panic serving") {
		t.Fatalf("net/http still logged the panic: %s", serverLog)
	}
	if gotResponse {
		t.Fatal("client got a response from a panicking handler; the connection should be aborted")
	}
}

// http.ErrAbortHandler (httputil.ReverseProxy uses it when the client goes away) is
// passed through: no app log line, and net/http logs nothing for it either.
func TestAbortHandlerPanicPassesThroughSilently(t *testing.T) {
	appLog, serverLog, _ := serveWithLogs(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	if appLog != "" || serverLog != "" {
		t.Fatalf("abort was logged:\napp: %s\nserver: %s", appLog, serverLog)
	}
}

// A handler that does not panic is untouched.
func TestRecoverPassesNormalResponses(t *testing.T) {
	appLog, _, gotResponse := serveWithLogs(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	if !gotResponse || appLog != "" {
		t.Fatalf("normal request disturbed: response=%v log=%q", gotResponse, appLog)
	}
}
