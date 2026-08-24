package attest

import (
	"encoding/json"
	"errors"
	"testing"
)

// quoteReplyWith builds a /v1/quote reply in dstack's shape: tcb_info is a JSON
// *string* holding an object whose app_compose is in turn a JSON string. Built by
// marshalling rather than hand-written so the escaping is the encoder's problem and
// the test exercises the real double-decode.
func quoteReplyWith(t *testing.T, appCompose string) []byte {
	t.Helper()
	tcb, err := json.Marshal(map[string]string{"app_compose": appCompose})
	if err != nil {
		t.Fatalf("marshal tcb_info: %v", err)
	}
	body, err := json.Marshal(map[string]string{
		"quote":    "0400",
		"tcb_info": string(tcb),
	})
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	return body
}

func TestAppComposeFromQuoteResponse(t *testing.T) {
	// Braces, quotes and newlines all survive two rounds of JSON string encoding —
	// the shape a real app-compose has, and where a naive single decode would break.
	const want = `{"docker_compose_file":"services:\n  app:\n    image: x@sha256:ab"}`
	got, err := AppComposeFromQuoteResponse(quoteReplyWith(t, want))
	if err != nil {
		t.Fatalf("AppComposeFromQuoteResponse: %v", err)
	}
	if string(got) != want {
		t.Errorf("app_compose:\n got %q\nwant %q", got, want)
	}
}

// The bytes must come back exactly as sent. dstack hashes the file as it wrote it,
// so a re-marshal that produced equal-but-reordered JSON would still be a digest
// mismatch at VerifyAppCompose — a failure that would look like a substituted
// manifest rather than like our own reformatting.
func TestAppComposeFromQuoteResponseIsVerbatim(t *testing.T) {
	const want = "{\n  \"b\": 2,\n  \"a\": 1\n}"
	got, err := AppComposeFromQuoteResponse(quoteReplyWith(t, want))
	if err != nil {
		t.Fatalf("AppComposeFromQuoteResponse: %v", err)
	}
	if string(got) != want {
		t.Errorf("bytes were not preserved:\n got %q\nwant %q", got, want)
	}
}

func TestAppComposeFromQuoteResponseAbsent(t *testing.T) {
	// Absence must be distinguishable from corruption: a provider with public_tcbinfo
	// off has nothing to show (fine), while a reply that will not parse is a bug worth
	// a log line. A caller that cannot tell them apart logs noise on every request.
	tests := []struct {
		name string
		body string
	}{
		{"no tcb_info at all", `{"quote":"0400"}`},
		{"empty tcb_info", `{"quote":"0400","tcb_info":""}`},
		{"tcb_info without app_compose", `{"quote":"0400","tcb_info":"{\"mrtd\":\"ab\"}"}`},
		{"empty app_compose", `{"quote":"0400","tcb_info":"{\"app_compose\":\"\"}"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AppComposeFromQuoteResponse([]byte(tc.body))
			if !errors.Is(err, ErrNoAppCompose) {
				t.Fatalf("err = %v, want ErrNoAppCompose", err)
			}
			if got != nil {
				t.Errorf("bytes = %q, want nil alongside the sentinel", got)
			}
		})
	}
}

func TestAppComposeFromQuoteResponseMalformed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"reply is not JSON", `not json`},
		{"tcb_info is not JSON", `{"quote":"0400","tcb_info":"not json"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AppComposeFromQuoteResponse([]byte(tc.body))
			if err == nil {
				t.Fatal("want an error")
			}
			// Malformed is NOT absent: reporting the sentinel here would silence the one
			// case worth logging.
			if errors.Is(err, ErrNoAppCompose) {
				t.Errorf("malformed input reported as ErrNoAppCompose: %v", err)
			}
		})
	}
}

// DecodeQuoteResponse keeps ignoring everything but the quote. The two functions
// read the same body for different purposes, and the trusted one must not start
// depending on the unsigned half.
func TestDecodeQuoteResponseIgnoresAppCompose(t *testing.T) {
	raw, err := DecodeQuoteResponse(quoteReplyWith(t, `{"docker_compose_file":"services: {}"}`))
	if err != nil {
		t.Fatalf("DecodeQuoteResponse: %v", err)
	}
	if len(raw) != 2 || raw[0] != 0x04 {
		t.Errorf("quote bytes = %x, want the decoded 0400", raw)
	}
}

// The guest agent has shipped tcb_info BOTH ways — a nested object and a JSON
// string holding the same document — and a broker's /v1/quote re-serializes
// whichever shape its SDK received. Committing to one silently loses the other:
// before unwrapJSONString the object form failed at the OUTER unmarshal, so the
// caller saw "cannot unmarshal object into a string" and reported no containers,
// permanently and (at default log level) silently.
func TestAppComposeFromQuoteResponseAcceptsObjectTCBInfo(t *testing.T) {
	const appCompose = `{"docker_compose_file":"services:\n  broker:\n    image: x@sha256:aa\n"}`

	// tcb_info as a nested OBJECT.
	objForm, err := json.Marshal(map[string]any{
		"quote":    "00",
		"tcb_info": map[string]string{"app_compose": appCompose},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// tcb_info as a JSON STRING holding the same document.
	inner, err := json.Marshal(map[string]string{"app_compose": appCompose})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	strForm, err := json.Marshal(map[string]string{"quote": "00", "tcb_info": string(inner)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"object form", objForm},
		{"string form", strForm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AppComposeFromQuoteResponse(tc.body)
			if err != nil {
				t.Fatalf("AppComposeFromQuoteResponse: %v", err)
			}
			// Byte-for-byte: these bytes are the preimage of the compose hash, so a shape
			// difference in the WRAPPER must not change what comes out of it.
			if string(got) != appCompose {
				t.Errorf("app_compose = %q, want %q", got, appCompose)
			}
		})
	}
}
