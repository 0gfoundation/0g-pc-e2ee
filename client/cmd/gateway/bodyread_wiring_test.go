package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
)

// The bound's own mechanics are tested in openaiproxy (bodyread_test.go). This is
// the wiring, through the real handler chain: that the deadline reaches the
// connection past every writer wrapper in front of it, and that it frees the slot
// a trickled body was holding. Either regression would leave the openaiproxy tests
// green.
func TestGatewayBodyRead_FreesTheSlotATrickledBodyHolds(t *testing.T) {
	routerMux := http.NewServeMux()
	routerMux.HandleFunc("POST /v1/routing/preview", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no provider", http.StatusInternalServerError) // answer fast; never park
	})
	router := httptest.NewServer(routerMux)
	defer router.Close()
	client := core.NewWithResolver(route.New(router.URL))
	gw := httptest.NewServer(newHandler(sealedClients(client, nil), mustURL(t, router.URL), testOrigins(), "", "",
		1, nil, nil, nil, discardLogger(), withEntryPolicy(entryPolicy{bodyReadTimeout: 2 * time.Second})))
	defer gw.Close()

	// Headers promising 100 bytes, then two of them, then nothing. The credential
	// is any string: the gate checks shape, which is what makes this free.
	trickle := func() (net.Conn, *bufio.Reader) {
		conn, err := net.Dial("tcp", strings.TrimPrefix(gw.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer anything\r\n"+
			"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"")
		return conn, bufio.NewReader(conn)
	}
	conn, br := trickle()
	defer func() { conn.Close() }()

	// While it trickles, it holds the only slot.
	//
	// Unless a probe got there first. A probe takes the slot too, for as long as the
	// router takes to refuse it — ~600ms on a CPU-starved CI runner — and a trickled
	// request arriving inside that is shed with a 503 and never holds anything; every
	// probe after it then passes and the loop ran out its deadline (CI, 2026-11-19).
	// So when a probe gets through, look for an answer already waiting on the trickled
	// connection: if there is one, that request is finished, and a fresh one is sent.
	// The bound is 2s, not 300ms, for the same runner: a probe has to land inside it.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if got := post(t, gw, "Bearer sk-second"); got == http.StatusServiceUnavailable {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, peekErr := br.Peek(1)
		_ = conn.SetReadDeadline(time.Time{})
		if peekErr == nil { // answered already: shed, or its bound ran out between probes
			conn.Close()
			conn, br = trickle()
		}
		if time.Now().After(deadline) {
			t.Fatal("the trickled request never held the slot")
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("the trickled request got no answer: %v — the bound did not reach the connection", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Errorf("trickled request = %d, want 408", resp.StatusCode)
	}

	// And the slot is free again.
	if got := post(t, gw, "Bearer sk-third"); got == http.StatusServiceUnavailable {
		t.Errorf("after the 408 the cap still sheds (%d): the slot was not released", got)
	}
}

func TestEntryPolicyBodyRead(t *testing.T) {
	if got := (entryPolicy{}).bodyRead(); got != defaultBodyReadTimeout {
		t.Errorf("zero policy = %v, want the default %v", got, defaultBodyReadTimeout)
	}
	if got := (entryPolicy{bodyReadTimeout: -1}).bodyRead(); got > 0 {
		t.Errorf("a negative bodyReadTimeout resolves to %v, want disabled (<= 0)", got)
	}
	if got := (entryPolicy{bodyReadTimeout: 5 * time.Second}).bodyRead(); got != 5*time.Second {
		t.Errorf("bodyReadTimeout=5s resolves to %v", got)
	}
}
