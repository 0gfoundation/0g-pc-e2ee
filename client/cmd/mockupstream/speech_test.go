package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
	"github.com/0gfoundation/0g-pc-e2ee/client/route"
	"github.com/0gfoundation/0g-pc-e2ee/client/sig"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// speechGateway is the real serving stack for /v1/audio/transcriptions: the HTTP
// front end over the real client core over the real route resolver, pointed at
// the fixture — how proxycli.Build wires the gateway, minus the attestation the
// fixture cannot satisfy.
func speechGateway(t *testing.T, upstreamURL string, c *http.Client) *httptest.Server {
	t.Helper()
	router := route.New(upstreamURL)
	client := core.NewWithResolver(router,
		core.WithEndpoint(endpoint.Speech),
		core.WithUnboundFields(wire.DefaultUnboundFields()),
		core.WithResponseVerification(route.NewSignatureFetcher(c), sig.Recover),
	)
	mux := http.NewServeMux()
	openaiproxy.Register(mux, endpoint.Speech, client)
	gw := httptest.NewServer(mux)
	t.Cleanup(gw.Close)
	return gw
}

// sdkTranscription builds the request an OpenAI SDK posts: multipart, with the
// audio as a file part and everything else as form fields.
func sdkTranscription(t *testing.T, filename string, audio []byte, fields ...[2]string) (*bytes.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(audio); err != nil {
		t.Fatalf("write audio: %v", err)
	}
	for _, f := range fields {
		if err := w.WriteField(f[0], f[1]); err != nil {
			t.Fatalf("WriteField %q: %v", f[0], err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return bytes.NewReader(buf.Bytes()), w.FormDataContentType()
}

// The whole chain for the speech surface, in one process: an SDK-shaped
// MULTIPART upload to the gateway, the JSON-ification and seal, the
// control-plane hop to route-preview, the data-plane hop to the router's
// /v1/audio/transcriptions, and the enclave behind it — which opens under the
// speech profile, materializes multipart again, and answers sealed.
//
// It is the test no single-package test replaces, and for this surface more than
// any other: the conversion has two halves living in two packages that never
// call each other, so a sender that JSON-ifies in a way no enclave can undo
// passes both halves' own tests. Here it does not.
//
// Four things are asserted, at the point each becomes observable:
//
//  1. the router's CONTROL-PLANE view — which pool to rank, and not the audio;
//  2. the router's DATA-PLANE view — enough to route and bill, and not the audio;
//  3. the ENCLAVE's view — a 200 means it opened under the speech profile AND
//     rebuilt the multipart, since handleSpeech 400s on either failing;
//  4. the CLIENT's view — the transcript, which is DERIVED from the rebuilt
//     upload, so it is evidence the audio bytes and the filename survived the
//     round trip rather than a constant the fixture could emit regardless.
func TestSpeechEndToEndThroughRouterAndEnclave(t *testing.T) {
	s, err := newServer(testConfig())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	rec := recordUpstream(s.handler())
	upstream := httptest.NewServer(rec)
	defer upstream.Close()

	gw := speechGateway(t, upstream.URL, upstream.Client())

	// Deliberately awkward bytes: they encode to "+/+/" under standard base64 and
	// "-_-_" under base64url, so a sender that picked the wrong alphabet cannot
	// round-trip them through the enclave's strict decode.
	audio := bytes.Repeat([]byte{0xfb, 0xff, 0xbf}, 700) // 2100 bytes
	const filename = "board-meeting-2026Q3.m4a"
	const secretPrompt = "the secret biasing hint"

	body, contentType := sdkTranscription(t, filename, audio,
		[2]string{"model", "mock-model"},
		[2]string{"prompt", secretPrompt},
		[2]string{"language", "en"},
		[2]string{"temperature", "0.2"},
		[2]string{"timestamp_granularities[]", "segment"},
		[2]string{"timestamp_granularities[]", "word"},
	)
	resp, err := http.Post(gw.URL+endpoint.Speech.Path, contentType, body)
	if err != nil {
		t.Fatalf("post %s: %v", endpoint.Speech.Path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}

	// (1) The control-plane hop.
	preview := rec.bodyAt(t, "/v1/routing/preview")
	if got := string(preview["service_type"]); got != `"speech-to-text"` {
		t.Errorf("preview service_type = %s, want %q", got, "speech-to-text")
	}
	if _, ok := preview["model"]; !ok {
		t.Error("the router needs cleartext \"model\" to rank providers")
	}
	// The payload fields §5.3.2 seals must not reach the router's preview either
	// — the preview body is "the request minus the withheld fields", and the
	// withheld set comes from the row's profile.
	for _, f := range []string{"file_base64", "filename", "prompt", "language"} {
		if _, leaked := preview[f]; leaked {
			t.Errorf("%q reached the router's preview in the clear", f)
		}
	}

	// (2) The data-plane hop.
	sealedReq := rec.bodyAt(t, endpoint.Speech.UpstreamPath)
	for _, f := range []string{"model", "response_format", "_e2ee"} {
		if _, ok := sealedReq[f]; !ok {
			t.Errorf("the sealed request must carry cleartext %q", f)
		}
	}
	// PreSeal supplied the mandatory pin; the caller never sent it.
	if got := string(sealedReq["response_format"]); got != `"json"` {
		t.Errorf("response_format = %s, want PreSeal's explicit \"json\"", got)
	}
	for _, f := range []string{"file_base64", "filename", "prompt", "language"} {
		if _, leaked := sealedReq[f]; leaked {
			t.Errorf("%q reached the router in the clear on the sealed request", f)
		}
	}
	// And not under any name: the audio and the prompt must be nowhere in the
	// bytes the router saw.
	sealedRaw := rec.rawAt(t, endpoint.Speech.UpstreamPath)
	if bytes.Contains(sealedRaw, audio) {
		t.Error("the raw audio bytes are in the body the router received")
	}
	for _, secret := range []string{secretPrompt, filename} {
		if bytes.Contains(sealedRaw, []byte(secret)) {
			t.Errorf("%q is in the body the router received", secret)
		}
	}

	// (4) The client's view. handleSpeech derives the transcript from the
	// multipart it rebuilt, so this one string carries three facts: the audio
	// decoded to the exact bytes sent (the count), the sealed filename was
	// forwarded onto the rebuilt part header (§5.3's SHOULD), and the whole
	// seal → route → open → materialize → seal → open round trip held.
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("client response is not a JSON object: %v\n%s", err, raw)
	}
	var text string
	if err := json.Unmarshal(out["text"], &text); err != nil {
		t.Fatalf("no readable \"text\" in the opened response: %s", raw)
	}
	wantText := `heard 2100 audio bytes from "board-meeting-2026Q3.m4a"`
	if text != wantText {
		t.Errorf("transcript = %q, want %q", text, wantText)
	}
	// §7.3's billable duration is cleartext and survives the open.
	if got := string(out["usage"]); !strings.Contains(got, `"seconds":2`) {
		t.Errorf("usage = %s, want the cleartext duration derived from the audio", got)
	}
	if _, leaked := out["_e2ee"]; leaked {
		t.Error("the opened response still carries _e2ee")
	}
}

// verbose_json is the shape the profile pays for by admitting it, so the fixture
// answers it differently and this proves the whole conditional path: the sealed
// set is computed PER FRAME (segments joins text), and the billable duration
// arrives at §7.3's OTHER locator — the top-level `duration`, because a
// verbose_json response commonly carries no usage block at all.
func TestSpeechVerboseJSONEndToEnd(t *testing.T) {
	s, err := newServer(testConfig())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	rec := recordUpstream(s.handler())
	upstream := httptest.NewServer(rec)
	defer upstream.Close()

	gw := speechGateway(t, upstream.URL, upstream.Client())

	audio := bytes.Repeat([]byte{0x01}, 3000)
	body, contentType := sdkTranscription(t, "a.mp3", audio,
		[2]string{"model", "mock-model"},
		[2]string{"response_format", "verbose_json"},
	)
	resp, err := http.Post(gw.URL+endpoint.Speech.Path, contentType, body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}

	// The caller's explicit value survives PreSeal — narrowing the pinned set to
	// `json` would cost the profile its timestamps, and with them subtitles.
	sealedReq := rec.bodyAt(t, endpoint.Speech.UpstreamPath)
	if got := string(sealedReq["response_format"]); got != `"verbose_json"` {
		t.Errorf("response_format = %s, want the caller's own value", got)
	}

	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("client response is not a JSON object: %v", err)
	}
	// segments is optional response payload: sealed on this frame, absent from
	// the plain `json` one, and back in the clear after the open.
	if _, ok := out["segments"]; !ok {
		t.Error("no \"segments\" after the open; the per-frame sealed set did not include it")
	}
	if got := string(out["duration"]); got != "3" {
		t.Errorf("duration = %s, want 3 — §7.3's other billable locator", got)
	}
	// It must have been SEALED, not passed through in the clear.
	sealedRaw := rec.rawAt(t, endpoint.Speech.UpstreamPath)
	if bytes.Contains(sealedRaw, []byte("segments")) {
		t.Error("segments appears in the sealed request body")
	}
}

// The enclave's own fail-closed half, exercised where it is reachable: a request
// the gateway would never build, posted straight at the fixture. Each of these
// is a way a DIFFERENT client could get the profile wrong, and the fixture is
// the only thing in this repository that would notice.
func TestSpeechEnclaveRefusesMalformedSealedRequests(t *testing.T) {
	s, err := newServer(testConfig())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	upstream := httptest.NewServer(s.handler())
	defer upstream.Close()

	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{
			// §5.3.1's first rule: a JSON body on a multipart endpoint must be a
			// valid envelope or be rejected — never forwarded as an unsealed request.
			"an unsealed JSON body",
			`{"model":"mock-model","file_base64":"YXVkaW8=","response_format":"json"}`,
			"_e2ee",
		},
		{
			"not a JSON object at all",
			`--boundary\r\nContent-Disposition: form-data; name="file"`,
			"not a JSON object",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(upstream.URL+endpoint.Speech.UpstreamPath,
				"application/json", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", resp.StatusCode, got)
			}
			if !strings.Contains(string(got), tt.want) {
				t.Errorf("body = %s, want it to mention %q", got, tt.want)
			}
		})
	}
}

// materializeTranscription is the enclave half, and these are the properties an
// upstream depends on that the end-to-end test can only observe indirectly.
func TestMaterializeTranscription(t *testing.T) {
	req := wire.Request{
		"file_base64":             json.RawMessage(`"+/+/AA=="`),
		"filename":                json.RawMessage(`"a.m4a"`),
		"model":                   json.RawMessage(`"mock-model"`),
		"stream":                  json.RawMessage(`false`),
		"temperature":             json.RawMessage(`"0.2"`),
		"timestamp_granularities": json.RawMessage(`["segment","word"]`),
	}
	upload, err := materializeTranscription(req)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if !bytes.Equal(upload.Audio, []byte{0xfb, 0xff, 0xbf, 0x00}) {
		t.Errorf("audio = %x, want the standard-base64 decode", upload.Audio)
	}

	_, params, err := mime.ParseMediaType(upload.ContentType)
	if err != nil {
		t.Fatalf("content type: %v", err)
	}
	if params["boundary"] == "" {
		t.Fatal("no boundary — §5.3 requires the enclave to generate its own")
	}
	mr := multipart.NewReader(bytes.NewReader(upload.Body), params["boundary"])
	form, err := mr.ReadForm(1 << 20)
	if err != nil {
		t.Fatalf("the materialized body is not readable multipart: %v", err)
	}
	defer form.RemoveAll()

	files := form.File["file"]
	if len(files) != 1 {
		t.Fatalf("file parts = %d, want 1", len(files))
	}
	// §5.3's SHOULD: the filename reached the enclave inside the ciphertext and
	// goes back onto the part header, because some backends sniff the container
	// from the extension.
	if files[0].Filename != "a.m4a" {
		t.Errorf("part filename = %q, want the sealed one forwarded", files[0].Filename)
	}
	// An array becomes repeated parts under the BRACKETED name — the inverse of
	// the sender's stripping, and what an OpenAI upstream expects.
	if got := form.Value["timestamp_granularities[]"]; len(got) != 2 || got[0] != "segment" || got[1] != "word" {
		t.Errorf("timestamp_granularities[] = %v, want [segment word]", got)
	}
	if _, ok := form.Value["timestamp_granularities"]; ok {
		t.Error("the unbracketed name must not also be written")
	}
	// `stream` is DROPPED, not rendered: the pin already guarantees false, the
	// endpoint's default is non-streaming, and a field that is not written cannot
	// be misread by a parser whose truthiness differs. Measured against the
	// broker's materializeSpeechRequest, which does the same.
	if got, ok := form.Value["stream"]; ok {
		t.Errorf("stream = %v, want it absent", got)
	}
	if got := form.Value["temperature"]; len(got) != 1 || got[0] != "0.2" {
		t.Errorf("temperature = %v, want the string carried straight through", got)
	}
	for _, gone := range []string{"file_base64", "filename"} {
		if _, ok := form.Value[gone]; ok {
			t.Errorf("%q was written as a form field; it belongs to the file part", gone)
		}
	}
}

// The strict decode is the point: a sender that used §3's base64url — the
// alphabet that governs `enc` and `ciphertext` on the wire — is refused rather
// than silently accepted by a decoder that tries both. One field name, one
// decoder.
func TestMaterializeTranscriptionRefusesBase64URL(t *testing.T) {
	req := wire.Request{
		"file_base64": json.RawMessage(`"-_-_AA=="`), // the same bytes, wrong alphabet
		"model":       json.RawMessage(`"mock-model"`),
	}
	if _, err := materializeTranscription(req); err == nil {
		t.Fatal("materialize accepted base64url")
	} else if !strings.Contains(err.Error(), "standard padded base64") {
		t.Errorf("error %q should name the encoding rule", err)
	}
}

// The fixture must materialize what the REAL enclave materializes, and it is a
// re-implementation rather than a shared package — the broker is another module
// in another repository, so nothing makes the two agree except this table.
//
// Every row was MEASURED by running the same input through
// 0g-serving-broker's materializeSpeechRequest and reading the form back. Five
// of them disagreed the first time this comparison was made, and two of those
// were outright bugs here rather than differences of taste:
//
//   - a number went through float64, so 12345678901234567890 materialized as
//     1.2345678901234567e+19 — a rewrite of what the client sealed, and lossy
//     above 2^53. The broker carries a comment about having fixed exactly this.
//   - with no sealed filename the file part was written with an empty one, and
//     Go's ReadForm then classifies it as a TEXT FIELD: an upstream reading
//     form.File["file"] finds no audio at all. Invisible here until measured,
//     because the fixture's own read-back looks the part up by FormName.
//
// A row that starts failing means one side moved. Go find out which.
func TestMaterializeMatchesTheBrokerEnclave(t *testing.T) {
	const audioB64 = `"YXVkaW8="`
	tests := []struct {
		name       string
		field      string
		value      string
		wantValues map[string][]string // form fields, beyond the file part
		wantFile   string              // the file part's filename
		wantErr    string
	}{
		{
			name: "stream is dropped, not rendered", field: "stream", value: `false`,
			wantValues: map[string][]string{}, wantFile: "audio",
		},
		{
			name: "a big integer keeps its literal", field: "temperature", value: `12345678901234567890`,
			wantValues: map[string][]string{"temperature": {"12345678901234567890"}}, wantFile: "audio",
		},
		{
			name: "a float keeps its shortest form", field: "temperature", value: `0.2`,
			wantValues: map[string][]string{"temperature": {"0.2"}}, wantFile: "audio",
		},
		{
			// Absence is a value the endpoint understands; "null" is a string it
			// would try to parse.
			name: "a null field is omitted", field: "language", value: `null`,
			wantValues: map[string][]string{}, wantFile: "audio",
		},
		{
			name: "an array becomes repeated bracketed parts", field: "timestamp_granularities",
			value:      `["segment","word"]`,
			wantValues: map[string][]string{"timestamp_granularities[]": {"segment", "word"}}, wantFile: "audio",
		},
		{
			name: "a quoted filename is refused", field: "filename", value: `"a\".mp3"`,
			wantErr: "cannot appear in a multipart part header",
		},
		{
			name: "a path filename is refused", field: "filename", value: `"../../etc/cron.d/x"`,
			wantErr: "is a path, not a filename",
		},
		{
			name: "an object has no form rendering", field: "chunking_strategy", value: `{"type":"auto"}`,
			wantErr: "no multipart rendering",
		},
		{
			// A null value does not excuse an unsafe NAME. The name writes no part,
			// so the header argument does not apply — what applies is that whether a
			// request materializes must not depend on one field happening to be null.
			name: "an unsafe field name with a null value", field: "zz; name=model", value: `null`,
			wantErr: "cannot appear in a multipart part header",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := wire.Request{
				"file_base64": json.RawMessage(audioB64),
				tt.field:      json.RawMessage(tt.value),
			}
			upload, err := materializeTranscription(req)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("materialize accepted %s=%s; the enclave refuses it", tt.field, tt.value)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("materialize: %v", err)
			}
			_, params, err := mime.ParseMediaType(upload.ContentType)
			if err != nil {
				t.Fatalf("content type: %v", err)
			}
			form, err := multipart.NewReader(bytes.NewReader(upload.Body), params["boundary"]).ReadForm(1 << 20)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			defer form.RemoveAll()

			files := form.File["file"]
			if len(files) != 1 {
				t.Fatalf("file parts = %d, want 1 — an empty filename degrades the part to a text field", len(files))
			}
			if files[0].Filename != tt.wantFile {
				t.Errorf("file part filename = %q, want %q", files[0].Filename, tt.wantFile)
			}
			if len(form.Value) != len(tt.wantValues) {
				t.Errorf("form fields = %v, want %v", form.Value, tt.wantValues)
			}
			for name, want := range tt.wantValues {
				got := form.Value[name]
				if len(got) != len(want) {
					t.Errorf("%s = %v, want %v", name, got, want)
					continue
				}
				for i := range want {
					if got[i] != want[i] {
						t.Errorf("%s[%d] = %q, want %q", name, i, got[i], want[i])
					}
				}
			}
		})
	}
}

// The gateway refuses a filename the enclave could not put in a part header, and
// refuses it ITSELF — `_0g.source` is "gateway", not "upstream". Before
// speechPreSeal checked, this request was sealed, routed, and refused by the
// enclave, so the caller learned about their filename from a relayed upstream
// error three hops away. Both spellings of the damage are covered: the quote,
// which multipart.Writer escapes and a non-unescaping parser still misreads, and
// the semicolon, which is RFC-legal inside a quoted parameter and which a
// `;`-splitting parser reads as a second parameter.
func TestSpeechGatewayRefusesAnUnmaterializableFilename(t *testing.T) {
	s, err := newServer(testConfig())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	rec := recordUpstream(s.handler())
	upstream := httptest.NewServer(rec)
	defer upstream.Close()
	gw := speechGateway(t, upstream.URL, upstream.Client())

	for _, filename := range []string{`a".mp3`, "a;b.mp3"} {
		t.Run(filename, func(t *testing.T) {
			body, ct := sdkTranscription(t, filename, []byte("audio"), [2]string{"model", "mock-model"})
			resp, err := http.Post(gw.URL+endpoint.Speech.Path, ct, body)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", resp.StatusCode, raw)
			}
			if !strings.Contains(string(raw), `"source":"gateway"`) {
				t.Errorf("body = %s, want the gateway to own this refusal", raw)
			}
			if strings.Contains(string(raw), "upstream") {
				t.Errorf("body = %s — the request reached the enclave before being refused", raw)
			}
		})
	}
}
