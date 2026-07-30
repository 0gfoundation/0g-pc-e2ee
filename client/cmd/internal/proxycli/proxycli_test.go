package proxycli

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

// testLogger discards output; the shutdown tests assert on serve's return value
// and the listener state, not on log lines.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// serve returns nil once a shutdown signal triggers a graceful drain, and the
// listener is released so a redeploy can rebind the port.
func TestServeGracefulShutdownOnSignal(t *testing.T) {
	// Bind an ephemeral port ourselves so we know the address (ListenAndServe
	// with :0 hides the chosen port), then close it: serve rebinds the same
	// address, and after shutdown we confirm it is free again.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}
	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- serve(srv, testLogger(), sigCh) }()

	// Wait until serve has bound the port before signalling, so the drain path
	// (not the pre-bind shortcut) is what's exercised.
	waitListening(t, addr)

	sigCh <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error on clean shutdown: %v", err)
		}
	case <-time.After(ShutdownTimeout + 2*time.Second):
		t.Fatal("serve did not return after shutdown signal")
	}

	// The port must be released: a graceful shutdown that leaked the listener
	// would block the redeploy this feature exists to support.
	reln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port not released after shutdown: %v", err)
	}
	_ = reln.Close()
}

// serve returns the listen error (and does not block waiting for a signal) when
// the address is already bound.
func TestServeReturnsListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Addr: ln.Addr().String(), Handler: http.NewServeMux()}
	sigCh := make(chan os.Signal, 1) // never fires
	done := make(chan error, 1)
	go func() { done <- serve(srv, testLogger(), sigCh) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve returned nil for an occupied port; want a listen error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve blocked instead of returning the listen error")
	}
}

// waitListening polls addr until a TCP connection succeeds or the deadline
// passes, so a test can synchronize on the server actually being up.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server did not start listening on %s", addr)
}

// envOr uses an env var only when it is present; a set-but-empty value is
// honored (not treated as unset), since "" is meaningful for the CSV fields.
func TestEnvOr(t *testing.T) {
	const key = "ZG_PROXYCLI_TEST_ENVOR"
	t.Setenv(key, "from-env")
	if got := envOr(key, "def"); got != "from-env" {
		t.Fatalf("set var: got %q, want %q", got, "from-env")
	}
	t.Setenv(key, "")
	if got := envOr(key, "def"); got != "" {
		t.Fatalf("empty var: got %q, want empty (honored, not defaulted)", got)
	}
	if got := envOr("ZG_PROXYCLI_TEST_UNSET", "def"); got != "def" {
		t.Fatalf("unset var: got %q, want %q", got, "def")
	}
}

// envBool falls back to def when unset and parses standard boolean forms when
// set. (The set-but-unparseable case is log.Fatal, so it is not exercised here.)
func TestEnvBool(t *testing.T) {
	const key = "ZG_PROXYCLI_TEST_ENVBOOL"
	if got := envBool("ZG_PROXYCLI_TEST_UNSET_BOOL", true); !got {
		t.Fatal("unset var: want fallback to def=true")
	}
	for _, tc := range []struct {
		val  string
		want bool
	}{{"true", true}, {"1", true}, {"false", false}, {"0", false}} {
		t.Setenv(key, tc.val)
		if got := envBool(key, !tc.want); got != tc.want {
			t.Fatalf("%s=%q: got %v, want %v", key, tc.val, got, tc.want)
		}
	}
}

// parseCSV trims each element and drops empty ones, so surrounding spaces and a
// trailing comma do not produce blank fields.
func TestParseCSV(t *testing.T) {
	got := parseCSV(" messages , model ,")
	want := []string{"messages", "model"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
