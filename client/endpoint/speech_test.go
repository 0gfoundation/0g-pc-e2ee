package endpoint

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"strings"
	"testing"
)

// audioWithAwkwardBytes encodes to "+/+/AA==" under standard base64 and
// "-_-_AA==" under base64url, so a test that pins the output pins BOTH the
// alphabet and the padding — the two halves of the rule SPEC §5.3 spells out
// (RFC 4648 §4, padding required, not §3's base64url-without-padding).
var audioWithAwkwardBytes = []byte{0xfb, 0xff, 0xbf, 0x00}

const audioStdBase64 = "+/+/AA=="

// buildMultipart writes a transcription request the way an SDK would: one file
// part plus zero or more form fields, in order.
func buildMultipart(t *testing.T, filename string, audio []byte, fields ...[2]string) (body []byte, contentType string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if filename != "" || audio != nil {
		fw, err := w.CreateFormFile("file", filename)
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := fw.Write(audio); err != nil {
			t.Fatalf("write audio: %v", err)
		}
	}
	for _, f := range fields {
		if err := w.WriteField(f[0], f[1]); err != nil {
			t.Fatalf("WriteField %q: %v", f[0], err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes(), w.FormDataContentType()
}

// field reads one decoded field as raw JSON, failing if it is absent.
func field(t *testing.T, req map[string]json.RawMessage, name string) string {
	t.Helper()
	raw, ok := req[name]
	if !ok {
		t.Fatalf("decoded request has no %q; got %v", name, keys(req))
	}
	return string(raw)
}

func keys(req map[string]json.RawMessage) []string {
	out := make([]string, 0, len(req))
	for k := range req {
		out = append(out, k)
	}
	return out
}

// The shape of the conversion: the binary part becomes base64 in `file_base64`,
// the part header's filename becomes a field of its own (which is what makes it
// sealable at all), and every other form value crosses as the string it was.
func TestSpeechDecodeMultipart(t *testing.T) {
	body, ct := buildMultipart(t, "board-meeting.m4a", audioWithAwkwardBytes,
		[2]string{"model", "whisper-1"},
		[2]string{"response_format", "verbose_json"},
		[2]string{"language", "en"},
		[2]string{"temperature", "0.2"},
	)

	req, err := speechDecodeMultipart(body, ct)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got := field(t, req, "file_base64"); got != `"`+audioStdBase64+`"` {
		t.Errorf("file_base64 = %s, want %q — standard base64 WITH padding (SPEC §5.3), not base64url", got, audioStdBase64)
	}
	if got := field(t, req, "filename"); got != `"board-meeting.m4a"` {
		t.Errorf("filename = %s, want it lifted out of the part header", got)
	}
	// `temperature` is the case the typing rule exists for: nothing in this
	// gateway reads it, the enclave turns the object back into multipart where
	// every value is a string anyway, so carrying it across as a string is
	// round-trip correct rather than lossy.
	if got := field(t, req, "temperature"); got != `"0.2"` {
		t.Errorf("temperature = %s, want the string the caller sent", got)
	}
	for name, want := range map[string]string{
		"model":           `"whisper-1"`,
		"response_format": `"verbose_json"`,
		"language":        `"en"`,
	} {
		if got := field(t, req, name); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	if _, ok := req["file"]; ok {
		t.Error(`the audio part must land in "file_base64", not stay under "file"`)
	}
}

// `timestamp_granularities[]` is the only field with real structure, and an SDK
// spells it with the brackets while SPEC §5.3.2 names it without. Both the
// repeated and the single case must produce an ARRAY under the stripped name:
// a lone bracketed value is still a list of one, and turning it into a bare
// string would change what the enclave re-materializes.
func TestSpeechDecodeMultipartArrayFields(t *testing.T) {
	tests := []struct {
		name   string
		fields [][2]string
		want   string
	}{
		{
			"bracketed and repeated",
			[][2]string{{"timestamp_granularities[]", "segment"}, {"timestamp_granularities[]", "word"}},
			`["segment","word"]`,
		},
		{
			"bracketed once is still an array",
			[][2]string{{"timestamp_granularities[]", "word"}},
			`["word"]`,
		},
		{
			"repeated without brackets is an array too",
			[][2]string{{"timestamp_granularities", "segment"}, {"timestamp_granularities", "word"}},
			`["segment","word"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := append([][2]string{{"model", "whisper-1"}}, tt.fields...)
			body, ct := buildMultipart(t, "a.mp3", audioWithAwkwardBytes, fields...)
			req, err := speechDecodeMultipart(body, ct)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := field(t, req, "timestamp_granularities"); got != tt.want {
				t.Errorf("timestamp_granularities = %s, want %s", got, tt.want)
			}
			if _, ok := req["timestamp_granularities[]"]; ok {
				t.Error("the bracketed name must not survive; SPEC §5.3.2 names the field without them")
			}
		})
	}
}

// `stream` is the one field this gateway reads for itself, so it is the one
// field the decoder types. A multipart `stream=false` is LEGAL — the profile's
// pin permits exactly that value — and left as the string "false" it would be
// refused by openaiproxy.streamRequested as a malformed boolean, which is the
// concrete bug this typing exists to prevent.
func TestSpeechDecodeMultipartTypesStream(t *testing.T) {
	tests := []struct {
		sent string
		want string
	}{
		{"false", `false`},
		{"true", `true`},
		// ParseBool's other spellings resolve too, which is the ambiguity §5.3.3
		// names as the pin's whole reason: "the values a multipart materialization
		// reads as true are an open set". Resolving here means nothing downstream
		// has to decide.
		{"0", `false`},
		{"1", `true`},
		{"TRUE", `true`},
		// Not a boolean in any spelling: left as the string it was, so the refusal
		// comes from openaiproxy's own `"stream" must be a boolean` rather than a
		// second wording invented here.
		{"yes", `"yes"`},
		{"", `""`},
	}
	for _, tt := range tests {
		t.Run("stream="+tt.sent, func(t *testing.T) {
			body, ct := buildMultipart(t, "a.mp3", audioWithAwkwardBytes, [2]string{"stream", tt.sent})
			req, err := speechDecodeMultipart(body, ct)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := field(t, req, "stream"); got != tt.want {
				t.Errorf("stream = %s, want %s", got, tt.want)
			}
		})
	}
}

// A repeated `stream` is an array and stays one — the typing rule is for the
// single value a caller actually sends, and quietly picking one of two would be
// worse than the 400 an array earns downstream.
func TestSpeechDecodeMultipartRepeatedStreamIsNotTyped(t *testing.T) {
	body, ct := buildMultipart(t, "a.mp3", audioWithAwkwardBytes,
		[2]string{"stream", "false"}, [2]string{"stream", "true"})
	req, err := speechDecodeMultipart(body, ct)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := field(t, req, "stream"); got != `["false","true"]` {
		t.Errorf("stream = %s, want the array, untyped", got)
	}
}

// Every value here is caller input, so it goes through encoding/json rather than
// hand-quoting: a filename or prompt carrying a quote, a backslash or a newline
// must not be able to break the object it lands in.
// (A filename carrying a quote is refused later, by speechPreSeal, because the
// enclave cannot put it in a part header — see
// TestSpeechPreSealRefusesWhatTheEnclaveWillRefuse. What is under test here is
// the DECODER's escaping, which has to be right for `prompt` regardless.)
//
// The filename carries a quote and a backslash but no newline: Go's multipart
// WRITER percent-escapes a newline into the Content-Disposition header, so a
// filename containing one never reaches a reader as one and asserting otherwise
// tests the writer rather than the decoder. A form VALUE has no such escaping,
// which is why the newline lives in `prompt` here.
func TestSpeechDecodeMultipartEscapesCallerInput(t *testing.T) {
	const nasty = `a".mp3x\y`
	body, ct := buildMultipart(t, nasty, audioWithAwkwardBytes,
		[2]string{"prompt", "he said \"hi\"\nthen left"})

	req, err := speechDecodeMultipart(body, ct)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The real assertion is that the whole thing still parses as one object with
	// the exact values back — which is what escaping means.
	round, err := json.Marshal(map[string]json.RawMessage(req))
	if err != nil {
		t.Fatalf("decoded request does not re-marshal: %v", err)
	}
	var back map[string]string
	if err := json.Unmarshal(round, &back); err != nil {
		t.Fatalf("decoded request is not a flat JSON object of strings: %v", err)
	}
	if back["prompt"] != "he said \"hi\"\nthen left" {
		t.Errorf("prompt round-tripped as %q", back["prompt"])
	}
	if back["filename"] != nasty {
		t.Errorf("filename round-tripped as %q, want %q", back["filename"], nasty)
	}
}

// Each case builds its OWN (body, contentType) pair. buildMultipart picks a
// fresh random boundary per call, so pairing one case's body with another's
// content type finds no parts at all and fails with "no file part" whatever the
// body actually contains — which is a pass, or a failure, for the wrong reason.
// The first draft of this table did exactly that in two rows.
func TestSpeechDecodeMultipartRejects(t *testing.T) {
	tests := []struct {
		name    string
		build   func(t *testing.T) ([]byte, string)
		wantErr string
	}{
		{
			// SPEC §5.3.1's second rule, the one it calls easy to omit and expensive
			// to omit. wire.SealRequestFor refuses such a request too, but as a
			// seal-stage failure; caught here it is the request error it is.
			name: "a part named _e2ee",
			build: func(t *testing.T) ([]byte, string) {
				return buildMultipart(t, "a.mp3", audioWithAwkwardBytes, [2]string{"_e2ee", `{"v":1}`})
			},
			wantErr: "_e2ee",
		},
		{
			name: "no file part",
			build: func(t *testing.T) ([]byte, string) {
				return buildMultipart(t, "", nil, [2]string{"model", "whisper-1"})
			},
			wantErr: `no "file" part`,
		},
		{
			name: "content-type is not multipart",
			build: func(t *testing.T) ([]byte, string) {
				b, _ := buildMultipart(t, "a.mp3", audioWithAwkwardBytes)
				return b, "application/json"
			},
			wantErr: "not multipart",
		},
		{
			name: "multipart content-type with no boundary",
			build: func(t *testing.T) ([]byte, string) {
				b, _ := buildMultipart(t, "a.mp3", audioWithAwkwardBytes)
				return b, "multipart/form-data"
			},
			wantErr: "boundary",
		},
		{
			name: "unparseable content-type",
			build: func(t *testing.T) ([]byte, string) {
				b, _ := buildMultipart(t, "a.mp3", audioWithAwkwardBytes)
				return b, "multipart/form-data; boundary"
			},
			wantErr: "malformed Content-Type",
		},
		{
			// A JSON body arriving under a multipart content type. It parses as zero
			// parts rather than as an error, so what refuses it is the missing audio
			// — stated here so the expectation is the real reason and not a substring
			// that happens to appear in several messages.
			name: "a JSON body under a multipart content type",
			build: func(t *testing.T) ([]byte, string) {
				_, ct := buildMultipart(t, "a.mp3", audioWithAwkwardBytes)
				return []byte(`{"model":"whisper-1"}`), ct
			},
			wantErr: `no "file" part`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, ct := tt.build(t)
			_, err := speechDecodeMultipart(body, ct)
			if err == nil {
				t.Fatalf("decode accepted %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// The pinned cleartext field, filled in when absent — and the fill-in is the
// endpoint's own default, so it changes nothing about what the upstream does.
// What it changes is that the value is EXPLICIT and therefore bound by the AAD,
// which an absent field (taking the server's default) can never be.
func TestSpeechPreSealFillsResponseFormat(t *testing.T) {
	for _, tt := range []struct{ name, sent string }{
		{"absent", ""},
		{"explicit null reads as absent", `null`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := map[string]json.RawMessage{"model": json.RawMessage(`"whisper-1"`)}
			if tt.sent != "" {
				req["response_format"] = json.RawMessage(tt.sent)
			}
			out, err := speechPreSeal(req)
			if err != nil {
				t.Fatalf("preseal: %v", err)
			}
			if got := string(out["response_format"]); got != `"json"` {
				t.Errorf("response_format = %s, want \"json\"", got)
			}
		})
	}
}

// verbose_json is PERMITTED, and this is the guard on that. Excluding it was
// considered and rejected at the protocol layer: it would cost the profile its
// timestamps and with them subtitles (SPEC §5.3.2), so a client that quietly
// narrowed the set here would make a documented capability unreachable.
func TestSpeechPreSealKeepsPermittedFormats(t *testing.T) {
	for _, format := range []string{"json", "verbose_json"} {
		t.Run(format, func(t *testing.T) {
			req := map[string]json.RawMessage{"response_format": json.RawMessage(`"` + format + `"`)}
			out, err := speechPreSeal(req)
			if err != nil {
				t.Fatalf("preseal refused %q, which the profile permits: %v", format, err)
			}
			if got := string(out["response_format"]); got != `"`+format+`"` {
				t.Errorf("response_format = %s, want it untouched", got)
			}
		})
	}
}

// The three that cannot be expressed under sealing at all: their response body
// is not a JSON object, so there is nowhere to attach `_e2ee` and nothing for
// §8's respH to hash. Refused rather than rewritten, because the caller asked
// for something this mode cannot honour and has to learn that.
func TestSpeechPreSealRejectsUnsealableFormats(t *testing.T) {
	for _, tt := range []struct{ name, sent string }{
		{"text", `"text"`},
		{"srt", `"srt"`},
		{"vtt", `"vtt"`},
		{"unknown value", `"json5"`},
		{"not a string", `7`},
		{"a composite", `{"type":"json"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := map[string]json.RawMessage{"response_format": json.RawMessage(tt.sent)}
			if _, err := speechPreSeal(req); err == nil {
				t.Fatalf("preseal accepted response_format=%s", tt.sent)
			} else if !strings.Contains(err.Error(), "verbose_json") {
				t.Errorf("error %q should name the permitted set", err)
			}
		})
	}
}

// A JSON `null` stream is dropped, and the reason is a divergence with a long
// fuse: openaiproxy.streamRequested decodes null into a bool without error and
// reads it as "not streaming", while the profile's pin renders it as the token
// "null" and permits only "false". Left in place the request passes this gateway
// and is refused three hops away, by the enclave.
func TestSpeechPreSealDropsNullStream(t *testing.T) {
	req := map[string]json.RawMessage{
		"model":  json.RawMessage(`"whisper-1"`),
		"stream": json.RawMessage(`null`),
	}
	out, err := speechPreSeal(req)
	if err != nil {
		t.Fatalf("preseal: %v", err)
	}
	if _, ok := out["stream"]; ok {
		t.Error("a null stream must be dropped, not carried to the enclave's pin")
	}
	// An explicit false is what the pin permits, so it stays.
	req["stream"] = json.RawMessage(`false`)
	out, err = speechPreSeal(req)
	if err != nil {
		t.Fatalf("preseal: %v", err)
	}
	if got := string(out["stream"]); got != `false` {
		t.Errorf("stream = %s, want it kept — the pin permits false", got)
	}
}

// PreSeal must not mutate its input: the same body is re-sealed to each fallback
// candidate, so a mutation would make the second attempt a different request.
func TestSpeechPreSealDoesNotMutateInput(t *testing.T) {
	req := map[string]json.RawMessage{
		"model":  json.RawMessage(`"whisper-1"`),
		"stream": json.RawMessage(`null`),
	}
	if _, err := speechPreSeal(req); err != nil {
		t.Fatalf("preseal: %v", err)
	}
	if _, ok := req["response_format"]; ok {
		t.Error("preseal added response_format to the CALLER's map")
	}
	if _, ok := req["stream"]; !ok {
		t.Error("preseal deleted stream from the CALLER's map")
	}
}

// The row itself: the fields every layer reads off it, and the two hooks that
// make this surface different from the other three.
func TestSpeechRow(t *testing.T) {
	if Speech.Profile != "speech" {
		t.Errorf("Profile = %q, want the wire speech profile", Speech.Profile)
	}
	if Speech.ServiceType != "speech-to-text" {
		t.Errorf("ServiceType = %q — it is the value the router's preview API accepts", Speech.ServiceType)
	}
	if Speech.Streams {
		t.Error("Streams must be false: §5.3.3 defines no sealed stream frame taxonomy")
	}
	if Speech.DecodeMultipart == nil {
		t.Error("no DecodeMultipart — every SDK posts multipart here, so the surface would 400 on every real call")
	}
	if Speech.PreSeal == nil {
		t.Error("no PreSeal — response_format is a mandatory pin and nothing else would supply it")
	}
	// And it is the ONLY row with a decoder, which is what keeps the other three
	// on exactly the path they were on before it existed.
	for _, ep := range All {
		if ep.Path != Speech.Path && ep.DecodeMultipart != nil {
			t.Errorf("row %s also has a DecodeMultipart; the JSON-only rows must be untouched", ep.Path)
		}
	}
}

// The enclave writes the part headers of the multipart it rebuilds, and both the
// filename and the field names come out of the envelope — i.e. from the caller.
// Refusing here is not belt-and-braces: without it the request is sealed, sent,
// and refused by the enclave, so the caller gets a relayed upstream error three
// hops from the thing they got wrong. Reproduced end to end before this existed.
//
// The set mirrors the broker's speechHeaderSafe character for character. No
// stricter — that would refuse requests the enclave would serve — and no looser.
func TestSpeechPreSealRefusesWhatTheEnclaveWillRefuse(t *testing.T) {
	tests := []struct {
		name    string
		req     map[string]json.RawMessage
		wantErr string
	}{
		{
			"a quoted filename",
			map[string]json.RawMessage{"filename": json.RawMessage(`"a\".mp3"`)},
			"cannot appear in a multipart part header",
		},
		{
			// A separate mechanism from the quote: inside a quoted parameter a
			// semicolon is RFC-legal and needs no escaping, so what breaks is a
			// parser that splits the disposition on `;` before honouring the quotes.
			"a semicolon in the filename",
			map[string]json.RawMessage{"filename": json.RawMessage(`"a;b.mp3"`)},
			"cannot appear in a multipart part header",
		},
		{
			"a newline in the filename",
			map[string]json.RawMessage{"filename": json.RawMessage(`"a.mp3\nX-Injected: yes"`)},
			"cannot appear in a multipart part header",
		},
		{
			// Reaches only the JSON-ified caller in practice — a multipart upload's
			// filename has already been through filepath.Base by the time the decoder
			// sees it — which is exactly why the rule cannot live in the decoder.
			"a path filename",
			map[string]json.RawMessage{"filename": json.RawMessage(`"../../etc/cron.d/x"`)},
			"is a path, not a filename",
		},
		{
			// A field NAME reaches a part header too, and this is the injection the
			// broker's comment records: a `;`-splitting parser reads a second
			// `name=model` out of it and disagrees with the broker about the model.
			"a field name that forges a second parameter",
			map[string]json.RawMessage{"zz; name=model": json.RawMessage(`"x"`)},
			"cannot appear in a multipart part header",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := map[string]json.RawMessage{
				"model":       json.RawMessage(`"whisper-1"`),
				"file_base64": json.RawMessage(`"YXVkaW8="`),
			}
			for k, v := range tt.req {
				req[k] = v
			}
			if _, err := speechPreSeal(req); err == nil {
				t.Fatalf("preseal accepted %s", tt.name)
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// And the other half of "no stricter": these all materialize fine, so refusing
// them would break requests the enclave would have served.
func TestSpeechPreSealAcceptsWhatTheEnclaveAccepts(t *testing.T) {
	for _, tt := range []struct {
		name string
		req  map[string]json.RawMessage
	}{
		{"an ordinary filename", map[string]json.RawMessage{"filename": json.RawMessage(`"board-meeting.m4a"`)}},
		{
			// The broker accepts this deliberately: on the POSIX upstreams it runs
			// against, a backslash is an ordinary filename character rather than a
			// separator, and refusing it would reject a Windows-style name for nothing.
			"a Windows-style filename",
			map[string]json.RawMessage{"filename": json.RawMessage(`"C:\\recordings\\a.mp3"`)},
		},
		{
			// `=` is not in the set, and measured for the same reason the backslash is
			// not: a `;`-splitter still sees one segment, so there is no second
			// parameter to read out of it.
			"an equals sign in a field name",
			map[string]json.RawMessage{"zz=model": json.RawMessage(`"x"`)},
		},
		{"no filename at all", map[string]json.RawMessage{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := map[string]json.RawMessage{
				"model":       json.RawMessage(`"whisper-1"`),
				"file_base64": json.RawMessage(`"YXVkaW8="`),
			}
			for k, v := range tt.req {
				req[k] = v
			}
			if _, err := speechPreSeal(req); err != nil {
				t.Errorf("preseal refused %s, which the enclave materializes fine: %v", tt.name, err)
			}
		})
	}
}
