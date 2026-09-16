package openaiproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
)

// speechProxy stands up the speech surface in front of an upstream that records
// what reached it and answers 418, so a test can tell "was sealed and sent" from
// "was refused at the front door" by the status alone — the same shape as
// TestImagesRejectStreaming.
func speechProxy(t *testing.T) (proxyURL string, hits *atomic.Int64, lastBody *atomic.Value) {
	t.Helper()
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}
	hits = &atomic.Int64{}
	lastBody = &atomic.Value{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		lastBody.Store(b)
		http.Error(w, "the request reached a provider", http.StatusTeapot)
	}))
	t.Cleanup(upstream.Close)

	mux := http.NewServeMux()
	Register(mux, endpoint.Speech, core.New(core.Provider{
		URL:        upstream.URL,
		EncPubKey:  encPub,
		SignerAddr: "0x000000000000000000000000000000000000dEaD",
	}, core.WithEndpoint(endpoint.Speech)))
	proxy := httptest.NewServer(mux)
	t.Cleanup(proxy.Close)
	return proxy.URL, hits, lastBody
}

// speechMultipart builds a transcription request the way an SDK does.
func speechMultipart(t *testing.T, audio []byte, fields ...[2]string) (body *bytes.Reader, contentType string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", "meeting.m4a")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(audio); err != nil {
		t.Fatalf("write audio: %v", err)
	}
	for _, f := range fields {
		if err := w.WriteField(f[0], f[1]); err != nil {
			t.Fatalf("WriteField: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return bytes.NewReader(buf.Bytes()), w.FormDataContentType()
}

// The whole point of the surface: an ordinary multipart upload — what every
// OpenAI SDK posts to this endpoint — is converted, sealed, and sent on as a
// JSON envelope. The assertions are about what the UPSTREAM sees, because that
// is the untrusted side: the audio must not be there in the clear, and the
// envelope must be.
func TestSpeechMultipartIsSealed(t *testing.T) {
	proxyURL, hits, lastBody := speechProxy(t)

	audio := []byte("not really audio, but bytes all the same")
	body, ct := speechMultipart(t, audio,
		[2]string{"model", "whisper-1"},
		[2]string{"prompt", "a private biasing hint"},
		[2]string{"language", "en"},
	)
	resp, err := http.Post(proxyURL+"/v1/audio/transcriptions", ct, body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	// 418 is the upstream's own answer, so reaching it proves the front door
	// accepted a multipart body and the seal succeeded.
	if resp.StatusCode != http.StatusTeapot {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d (%s), want the upstream's 418 — the request never got sealed and sent",
			resp.StatusCode, strings.TrimSpace(string(got)))
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1", hits.Load())
	}

	sent, _ := lastBody.Load().([]byte)
	var env map[string]json.RawMessage
	if err := json.Unmarshal(sent, &env); err != nil {
		t.Fatalf("what reached the upstream is not a JSON envelope: %v\n%s", err, sent)
	}
	if _, ok := env["_e2ee"]; !ok {
		t.Errorf("no _e2ee in the upstream body; it was not sealed at all: %s", sent)
	}
	// The three payload fields (SPEC §5.3.2) must be GONE from the cleartext
	// half, and the audio must not appear anywhere in the body — not under
	// another name, not base64'd beside the envelope.
	for _, f := range []string{"file_base64", "file", "prompt", "language", "filename"} {
		if _, ok := env[f]; ok {
			t.Errorf("%q is in the cleartext half of the sealed request", f)
		}
	}
	if bytes.Contains(sent, audio) {
		t.Error("the raw audio bytes appear in the request sent upstream")
	}
	if bytes.Contains(sent, []byte("a private biasing hint")) {
		t.Error("the prompt appears in the clear in the request sent upstream")
	}
	// `model` stays cleartext — the router routes and attributes on it (§5.1) —
	// and so does the pinned response_format, filled in by PreSeal because the
	// caller omitted it.
	if got := string(env["model"]); got != `"whisper-1"` {
		t.Errorf("model = %s, want it cleartext for routing", got)
	}
	if got := string(env["response_format"]); got != `"json"` {
		t.Errorf("response_format = %s, want PreSeal's explicit \"json\"", got)
	}
}

// §5.3.3 defines no sealed stream frame taxonomy, so Speech.Streams is false and
// the generic check refuses `stream: true`. The `false` row is the one that
// matters for the multipart path: every value in a form is a string, so without
// the decoder typing this field it would reach streamRequested as `"false"` and
// be refused as a malformed boolean — turning a request the profile explicitly
// permits into a 400.
func TestSpeechMultipartStream(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sent       string
		wantStatus int
		wantHits   int64
	}{
		{"true is refused before anything is sealed", "true", http.StatusBadRequest, 0},
		{"false is what the profile permits, and goes through", "false", http.StatusTeapot, 1},
		{"a non-boolean is refused", "yes", http.StatusBadRequest, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxyURL, hits, _ := speechProxy(t)
			body, ct := speechMultipart(t, []byte("audio"),
				[2]string{"model", "whisper-1"},
				[2]string{"stream", tc.sent},
			)
			resp, err := http.Post(proxyURL+"/v1/audio/transcriptions", ct, body)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				got, _ := io.ReadAll(resp.Body)
				t.Errorf("status = %d, want %d (%s)", resp.StatusCode, tc.wantStatus, strings.TrimSpace(string(got)))
			}
			if hits.Load() != tc.wantHits {
				t.Errorf("upstream hits = %d, want %d", hits.Load(), tc.wantHits)
			}
		})
	}
}

// The same path still takes a JSON body — a caller sending the JSON-ified shape
// itself, rather than letting the gateway convert one. Content type is what
// selects the branch, so both work, and both are sealed the same way.
func TestSpeechAcceptsJSONBodyToo(t *testing.T) {
	proxyURL, hits, lastBody := speechProxy(t)

	resp, err := http.Post(proxyURL+"/v1/audio/transcriptions", "application/json",
		strings.NewReader(`{"model":"whisper-1","file_base64":"YXVkaW8=","filename":"a.mp3"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot || hits.Load() != 1 {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, hits = %d; want the JSON-ified shape to be sealed and sent (%s)",
			resp.StatusCode, hits.Load(), strings.TrimSpace(string(got)))
	}
	sent, _ := lastBody.Load().([]byte)
	if bytes.Contains(sent, []byte("YXVkaW8=")) {
		t.Error("file_base64 reached the upstream in the clear")
	}
}

// A Content-Type that announces multipart but cannot be parsed still reaches
// the decoder, so the caller is told what is wrong with the HEADER. Routed to
// the JSON branch instead it would be answered "request body is not a JSON
// object", which is not the complaint — and the decoder's own message about the
// header would be unreachable from the outside.
func TestSpeechMalformedMultipartHeaderIsAnsweredByTheDecoder(t *testing.T) {
	proxyURL, hits, _ := speechProxy(t)

	body, _ := speechMultipart(t, []byte("audio"), [2]string{"model", "whisper-1"})
	resp, err := http.Post(proxyURL+"/v1/audio/transcriptions", "multipart/form-data; boundary", body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), "Content-Type") {
		t.Errorf("body = %s, want the decoder's complaint about the header", got)
	}
	if strings.Contains(string(got), "not a JSON object") {
		t.Errorf("body = %s — the JSON branch answered a request that announced itself as multipart", got)
	}
	if hits.Load() != 0 {
		t.Error("a request with an unparseable Content-Type reached the upstream")
	}
}

// A multipart body on a surface WITHOUT a decoder is what it always was: not a
// JSON object. Stated here because the branch is new — the JSON-only rows must
// answer exactly as they did before it existed.
func TestMultipartOnAJSONOnlySurfaceIsStillNotJSON(t *testing.T) {
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("enc key: %v", err)
	}
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "must not be reached", http.StatusTeapot)
	}))
	defer upstream.Close()

	mux := http.NewServeMux()
	Register(mux, endpoint.Chat, core.New(core.Provider{
		URL:        upstream.URL,
		EncPubKey:  encPub,
		SignerAddr: "0x000000000000000000000000000000000000dEaD",
	}, core.WithEndpoint(endpoint.Chat)))
	proxy := httptest.NewServer(mux)
	defer proxy.Close()

	body, ct := speechMultipart(t, []byte("audio"), [2]string{"model", "glm-5"})
	resp, err := http.Post(proxy.URL+"/v1/chat/completions", ct, body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), "not a JSON object") {
		t.Errorf("body = %s, want the unchanged JSON-branch message", got)
	}
	if hits.Load() != 0 {
		t.Error("a multipart body reached the chat upstream")
	}
}
