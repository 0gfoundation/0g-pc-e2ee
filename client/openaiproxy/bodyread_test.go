package openaiproxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// slowRequest opens a raw connection to srv, sends a POST whose headers promise a
// body of declared bytes, and writes only sent of them. It returns the connection
// so the caller decides whether to finish the body, and a reader for the response.
func slowRequest(t *testing.T, srv *httptest.Server, declared int, sent string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	// Closed before the server: Close waits for active connections, so a handler
	// left blocked on this body by a broken bound would otherwise hang the test
	// instead of failing it. (Cleanup runs before the deferred srv.Close only if
	// registered later, so callers defer conn.Close themselves; this is the backstop.)
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\n\r\n%s", declared, sent)
	return conn, bufio.NewReader(conn)
}

// readsBody is a handler that reads the whole body the way the sealed surfaces do.
func readsBody() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes)); err != nil {
			readBodyError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// A body that stops arriving is answered 408 at the deadline, not held open.
func TestBoundBodyReadAnswersATrickledBody408(t *testing.T) {
	srv := httptest.NewServer(BoundBodyRead(200*time.Millisecond, readsBody()))
	defer srv.Close()

	conn, br := slowRequest(t, srv, 100, `{"model":`)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no response to a stalled body: %v (it was held open)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Errorf("status = %d, want 408", resp.StatusCode)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("answered after %v, want about the 200ms deadline", took)
	}
}

// The deadline is lifted at EOF: a handler that keeps streaming long after its body
// was read is neither cut nor has its context cancelled. net/http does the lifting
// (startBackgroundRead clears the read deadline), so this pins that behavior: were
// it to change, every stream would be cancelled d after it started.
func TestBoundBodyReadLiftsAtEOF(t *testing.T) {
	const d = 150 * time.Millisecond
	ctxErr := make(chan error, 1)
	srv := httptest.NewServer(BoundBodyRead(d, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			readBodyError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 6; i++ { // 6 × 100ms: four times the deadline
			fmt.Fprintf(w, "data: %d\n\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
		ctxErr <- r.Context().Err()
	})))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("stream cut after the body was read: %v", err)
	}
	if got := strings.Count(string(body), "data: "); got != 6 {
		t.Errorf("got %d frames, want 6:\n%s", got, body)
	}
	if err := <-ctxErr; err != nil {
		t.Errorf("request context ended mid-stream: %v", err)
	}
}

// A body that arrives within the deadline is served normally, and so is a request
// with no body at all.
func TestBoundBodyReadPassesPromptRequests(t *testing.T) {
	srv := httptest.NewServer(BoundBodyRead(time.Second, readsBody()))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("prompt body: status %d, want 200", resp.StatusCode)
	}
	resp, err = http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("no body: status %d, want 200", resp.StatusCode)
	}
}

// The deadline reaches the connection through the access log's recorder, which is
// the writer the gateway's chain hands the sealed path. Without Unwrap the
// controller stops at the recorder and the bound silently does not apply.
func TestBoundBodyReadThroughTheAccessLog(t *testing.T) {
	srv := httptest.NewServer(LogRequests(slog.New(slog.NewTextHandler(io.Discard, nil)), BoundBodyRead(200*time.Millisecond, readsBody())))
	defer srv.Close()

	conn, br := slowRequest(t, srv, 100, `{`)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no response through the access log: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Errorf("status = %d, want 408", resp.StatusCode)
	}
}

func TestBoundBodyReadDisabled(t *testing.T) {
	h := readsBody()
	if got := BoundBodyRead(0, h); fmt.Sprintf("%p", got) != fmt.Sprintf("%p", h) {
		t.Error("d <= 0 must return the handler unwrapped")
	}
}
