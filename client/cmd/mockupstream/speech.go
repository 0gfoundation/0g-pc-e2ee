package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// The two JSON field names this fixture reaches for by name. The rest of the
// request is carried through generically, which is what lets a field a future
// upstream adds reach the multipart without a change here.
const (
	fieldFileBase64 = "file_base64"
	fieldFilename   = "filename"
	fieldStream     = "stream"

	// fallbackFilename is written when the request sealed none. The part needs
	// SOME filename to read as a file upload at all: with an empty one Go's
	// ReadForm classifies it as a text field, so an upstream reading
	// form.File["file"] finds no audio. Measured, and it is what the broker's
	// speechFallbackFilename exists for.
	fallbackFilename = "audio"
)

// handleSpeech is the sealed transcription path — POST /v1/audio/transcriptions.
//
// It is the counterpart of handleImages, with one thing none of the other
// fixtures has to do: this profile's request reaches the enclave as JSON and
// must leave it as MULTIPART (SPEC §5.3), because the upstream speaks only
// multipart. That conversion is half of the profile, it is the enclave's half,
// and nothing else in this repository performs it — so a client that JSON-ifies
// a request in a way no enclave could undo would otherwise look correct all the
// way to a passing test.
//
// So this handler does the enclave's whole job rather than stopping at "it
// opened": it opens under the SPEECH profile, materializes the multipart it
// would POST upstream, and reports what that multipart actually contained back
// through the sealed response. The transcript the client opens is therefore
// evidence about the audio bytes — not a constant the fixture could emit whether
// or not the conversion worked.
func (s *server) handleSpeech(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read request body")
		return
	}
	// SPEC §5.3.1, first rule: on a multipart endpoint a JSON body MUST be a
	// valid sealed envelope or be rejected, never forwarded as an unsealed JSON
	// request "just in case". Everything below is that rejection, spelled out.
	var env wire.Request
	if err := json.Unmarshal(body, &env); err != nil {
		writeError(w, http.StatusBadRequest, "request body is not a JSON object")
		return
	}
	meta, err := env.E2EE()
	if err != nil {
		writeError(w, http.StatusBadRequest, "request carries no readable _e2ee metadata")
		return
	}
	// OpenRequestFor is what a real enclave runs, and for this profile it carries
	// the checks a gateway is most likely to get wrong: the sealed set covers
	// `file_base64` (and `filename` / `language` / `prompt` whenever present),
	// `response_format` is present and one of the two JSON-shaped values, and
	// `stream` — if present at all — is false. A request that seals the wrong
	// field, leaves the audio in the clear, or omits the pin fails HERE.
	opened, err := wire.OpenRequestFor(wire.ProfileSpeech, s.encPriv, env)
	if err != nil {
		writeError(w, http.StatusBadRequest, "sealed transcription did not open: "+err.Error())
		return
	}
	upload, err := materializeTranscription(opened)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot materialize multipart for the upstream: "+err.Error())
		return
	}
	ephPub, err := b64.DecodeString(meta.ClientEphPub)
	if err != nil || len(ephPub) != 32 {
		writeError(w, http.StatusBadRequest, "bad _e2ee.client_eph_pub")
		return
	}

	var reqH [32]byte
	if s.cfg.Sign {
		if reqH, err = proof.FrameBindingHash(env); err != nil {
			writeError(w, http.StatusBadRequest, "cannot bind the sealed request")
			return
		}
	}

	chatKey, err := newChatKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate chat key")
		return
	}

	frame, err := transcriptionFrame(opened, upload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build transcription response: "+err.Error())
		return
	}
	// The sealed set is per-frame for this profile, unlike chat's and image's:
	// `segments` and `words` are optional response payload, so a plain `json`
	// transcription seals only `text` while a `verbose_json` one seals more.
	// Asking wire which fields THIS frame must seal is what keeps the fixture
	// from hard-coding one of the two answers.
	fields, err := wire.ResponseSealedFieldsForFrame(wire.ProfileSpeech, frame)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sealed fields for the transcription frame: "+err.Error())
		return
	}
	// SealResponseFor also enforces §7.3's required cleartext quantity, so a
	// frame that forgot the billable duration is refused right here rather than
	// reaching a router that cannot price it.
	sealed, err := wire.SealResponseFor(wire.ProfileSpeech, crypto.PublicKey(ephPub), frame, fields)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "seal transcription response: "+err.Error())
		return
	}
	if s.cfg.Sign {
		respH, err := proof.FrameBindingHash(sealed)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "bind sealed response")
			return
		}
		s.sigs.put(chatKey, s.sign(proof.SignedTextE2EEFromHashes(reqH, respH)))
	}
	w.Header().Set("ZG-Res-Key", chatKey)
	writeJSON(w, http.StatusOK, sealed)
}

// transcriptionUpload is the multipart request an enclave would POST upstream,
// plus what it turned out to contain — which is what makes the conversion
// assertable from outside the enclave.
type transcriptionUpload struct {
	Body        []byte
	ContentType string
	Audio       []byte
	Filename    string
}

// materializeTranscription performs the enclave's half of SPEC §5.3: the
// JSON-ified request in, the multipart/form-data body an upstream speaks out.
//
// Two MUSTs and a SHOULD from §5.3, all of them load-bearing:
//
//   - the boundary is generated HERE. No boundary crosses the sealed channel, so
//     there is nothing in the request to carry one from; multipart.NewWriter
//     makes its own, which is the required behaviour rather than a convenience.
//   - `file_base64` is decoded as STANDARD base64 WITH PADDING (RFC 4648 §4),
//     strictly. §3's base64url-without-padding governs what appears on the wire
//     in the clear (`enc`, `ciphertext`); a binary payload field is fixed to the
//     other encoding precisely so one field name does not get two decoders. A
//     sender that used the §3 alphabet fails here, which is the point of
//     decoding strictly rather than trying both.
//   - the sealed `filename` is forwarded onto the part header, which §5.3 says a
//     receiver SHOULD do because some backends sniff the container from the
//     extension. It reached us inside the ciphertext; it goes back out in the
//     clear only because by now we are inside the TEE.
//
// Everything else becomes an ordinary form field. A JSON array becomes repeated
// parts under `name[]` — the inverse of the sender's bracket-stripping, and the
// spelling an OpenAI upstream expects for `timestamp_granularities` — while a
// scalar becomes one part rendered as the form value it would have been.
//
// `_e2ee` needs no exclusion: OpenRequest returns `cleartext ∪ decrypted` with
// the envelope key already dropped.
func materializeTranscription(req wire.Request) (*transcriptionUpload, error) {
	raw, ok := req[fieldFileBase64]
	if !ok {
		return nil, fmt.Errorf("opened request has no %q", fieldFileBase64)
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("%s is not a JSON string", fieldFileBase64)
	}
	audio, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%s is not standard padded base64 (SPEC §5.3 fixes RFC 4648 §4, not §3's base64url): %w",
			fieldFileBase64, err)
	}

	filename := fallbackFilename
	if raw, ok := req[fieldFilename]; ok {
		var sealed string
		if err := json.Unmarshal(raw, &sealed); err != nil {
			return nil, errors.New(`"filename" is not a JSON string`)
		}
		if sealed != "" {
			filename = sealed
		}
	}
	// A filename is a NAME, not a path: a backend that joins it onto an upload
	// directory would follow "../../etc/cron.d/x" verbatim.
	if strings.Contains(filename, "/") || filename == "." || filename == ".." {
		return nil, fmt.Errorf("%q is a path, not a filename (SPEC §5.3)", filename)
	}
	if err := headerSafe("filename", filename); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		return nil, fmt.Errorf("create the file part: %w", err)
	}
	if _, err := fw.Write(audio); err != nil {
		return nil, fmt.Errorf("write the audio: %w", err)
	}
	// Sorted so the body is deterministic: a fixture whose output depends on Go's
	// map order produces tests that pass most of the time.
	names := make([]string, 0, len(req))
	for name := range req {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		// `stream` is DROPPED rather than rendered. The pin has already guaranteed
		// it is false, the endpoint's default is non-streaming, so writing it adds
		// nothing — and a field that is not written cannot be misread by a form
		// parser whose notion of truthiness differs (SPEC §5.3.3 calls that set
		// open).
		if name == fieldFileBase64 || name == fieldFilename || name == fieldStream {
			continue
		}
		values, repeated, omit, err := formValues(req[name])
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", name, err)
		}
		field := name
		if repeated {
			field += "[]"
		}
		// Checked even when the field is OMITTED, which is what the broker does.
		// It looks pointless — a name that writes no part cannot appear in a part
		// header — and the point is not the header: it is that whether a request
		// materializes at all must not depend on one field happening to be null.
		// Measured: the broker refuses `{"zz; name=model": null}` and this returned
		// nil until the two were compared.
		if err := headerSafe("field name", field); err != nil {
			return nil, err
		}
		if omit {
			continue
		}
		for _, v := range values {
			if err := w.WriteField(field, v); err != nil {
				return nil, fmt.Errorf("write field %q: %w", field, err)
			}
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close the multipart body: %w", err)
	}
	// Read the body back and report what the PARSE found, not what went in. An
	// upstream sees only these bytes, so that is the honest thing for a fixture to
	// report — and it is what makes the transcript derived from it evidence about
	// the rebuilt multipart rather than about the JSON that produced it. Written
	// the other way round, blanking the part header's filename changed nothing any
	// test could see.
	audio, filename, err = readBackUpload(buf.Bytes(), w.Boundary())
	if err != nil {
		return nil, err
	}
	return &transcriptionUpload{
		Body:        buf.Bytes(),
		ContentType: w.FormDataContentType(),
		Audio:       audio,
		Filename:    filename,
	}, nil
}

// readBackUpload parses a materialized body and returns what its `file` part
// actually holds. The enclave checking its own output is not ceremony: the part
// header and the part body are written through two different calls, so "the
// audio is right" and "the filename is right" can fail independently, and a
// fixture that reported its INPUTS would call both of them fine.
func readBackUpload(body []byte, boundary string) (audio []byte, filename string, err error) {
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("the materialized body is not readable multipart: %w", err)
		}
		if part.FormName() != "file" {
			part.Close()
			continue
		}
		audio, err = io.ReadAll(part)
		filename = part.FileName()
		part.Close()
		if err != nil {
			return nil, "", fmt.Errorf("read back the file part: %w", err)
		}
		return audio, filename, nil
	}
	return nil, "", errors.New(`the materialized body has no "file" part`)
}

// formValues renders one JSON field as the form value(s) it materializes to. A
// form carries strings and nothing else, so this is where the JSON types the
// sender used collapse back — a string as itself, a bool or number as its JSON
// text, an array as repeated values, and a null as no field at all (absence is a
// value the endpoint understands; the four letters are a string it would parse).
//
// That collapse is why §5.1 compares a rendered TOKEN rather than a JSON type:
// `false` and `"false"` arrive here as the same form value, so a pin that
// distinguished them would mean different things on the two sides of this
// function.
//
// Numbers are decoded with UseNumber and emitted as the LITERAL the client
// sealed. Through float64 they are both a rewrite of what was sealed and lossy
// above 2^53 — 12345678901234567890 comes back as 1.2345678901234567e+19 —
// which is the bug the broker's speechFormValues already carries a comment
// about, and which this fixture reproduced until it was measured against it.
func formValues(raw json.RawMessage) (values []string, repeated, omit bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false, false, fmt.Errorf("not valid JSON: %w", err)
	}
	switch t := v.(type) {
	case nil:
		return nil, false, true, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, el := range t {
			s, err := formScalar(el)
			if err != nil {
				return nil, false, false, err
			}
			out = append(out, s)
		}
		return out, true, false, nil
	default:
		s, err := formScalar(t)
		if err != nil {
			return nil, false, false, err
		}
		return []string{s}, false, false, nil
	}
}

// headerSafe refuses a form field name or filename that cannot appear in a
// multipart part header without changing its meaning (RFC 7578 §5.1). Both
// strings come out of the opened envelope, i.e. from the client, and
// multipart.Writer escapes only `\` and `"` — writing CR and LF verbatim.
//
// The set matches the broker's speechHeaderSafe exactly, refused rather than
// escaped for the reason it gives: a rewritten name is not the name the client
// sealed, and the client's signature covers what it sealed. The semicolon is in
// the set because a parser that splits the disposition on `;` before honouring
// the quotes reads a second parameter out of it.
func headerSafe(kind, s string) error {
	if i := strings.IndexAny(s, "\r\n\";"); i >= 0 {
		return fmt.Errorf("%s %q contains %q at offset %d, which cannot appear in a multipart part header (RFC 7578 §5.1, SPEC §5.3)", kind, s, s[i], i)
	}
	return nil
}

func formScalar(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case json.Number:
		// The literal, verbatim — see the UseNumber note in formValues.
		return t.String(), nil
	default:
		return "", errors.New("a JSON object has no multipart rendering")
	}
}

// transcriptionFrame builds the response an upstream would return, shaped by the
// `response_format` the caller pinned.
//
// The transcript is DERIVED from the materialized upload rather than being a
// constant, so what the client finally opens is evidence that the audio and the
// filename survived seal → router → open → materialize intact. A fixture that
// answered "hello world" would pass exactly as well with a broken conversion.
//
// The billable duration is cleartext in both shapes and in the two different
// places §7.3 permits: `usage.seconds` for `json`, and verbose_json's top-level
// `duration` — which is the case the profile pays for by admitting
// `verbose_json` at all, so the fixture exercises it rather than emitting the
// easy one twice.
func transcriptionFrame(req wire.Request, upload *transcriptionUpload) (wire.Response, error) {
	text := fmt.Sprintf("heard %d audio bytes from %q", len(upload.Audio), upload.Filename)
	var textRaw json.RawMessage
	if err := marshalInto(&textRaw, text); err != nil {
		return nil, err
	}
	// One second per 1000 audio bytes, floored at 1: a number the test can predict
	// from what it sent, so a billing figure that stops tracking the audio is
	// visible rather than plausible.
	seconds := len(upload.Audio) / 1000
	if seconds < 1 {
		seconds = 1
	}

	// The pin has already been enforced by OpenRequestFor, so by here the value is
	// one of the two permitted strings. The decode error is dropped deliberately
	// rather than by omission: anything that does not decode to a string leaves
	// `format` empty and takes the `json` branch, which is the endpoint's own
	// default and the safe shape of the two.
	var format string
	if raw, ok := req["response_format"]; ok {
		if err := json.Unmarshal(raw, &format); err != nil {
			format = ""
		}
	}
	if format != "verbose_json" {
		return wire.Response{
			"text":  textRaw,
			"usage": json.RawMessage(fmt.Sprintf(`{"type":"duration","seconds":%d}`, seconds)),
		}, nil
	}
	return wire.Response{
		"text":     textRaw,
		"duration": json.RawMessage(strconv.Itoa(seconds)),
		"language": json.RawMessage(`"en"`),
		"segments": json.RawMessage(fmt.Sprintf(
			`[{"id":0,"start":0,"end":%d,"text":%s}]`, seconds, textRaw)),
	}, nil
}
