// Speech is the one surface that does not speak JSON on the wire its caller
// sees, so it gets its own file: the multipart→JSON conversion SPEC §5.3 puts on
// the sender is larger than every other row's rules put together, and burying it
// among three one-line rows would misrepresent both.
package endpoint

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"slices"
	"strconv"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Speech is POST /v1/audio/transcriptions: the OpenAI transcription surface,
// JSON-ified (SPEC §5.3). The caller speaks multipart, as every OpenAI SDK does
// for this endpoint; DecodeMultipart converts that to the JSON object the
// profile seals, and the enclave materializes multipart again on the far side.
//
// Streams is false, and for a sharper reason than the image row's. §5.3.3 pins
// `stream` to `false` because the profile defines no sealed stream frame
// taxonomy — a streaming request is refused rather than answered with frames
// whose shape the SPEC does not define. openaiproxy.Register's generic
// `stream && !ep.Streams` check is what enforces it here.
var Speech = Endpoint{
	ServiceType:     "speech-to-text",
	Profile:         wire.ProfileSpeech,
	Path:            "/v1/audio/transcriptions",
	UpstreamPath:    "/v1/audio/transcriptions",
	Streams:         false,
	PreSeal:         speechPreSeal,
	DecodeMultipart: speechDecodeMultipart,
}

const (
	// fieldFile is the multipart part carrying the audio, and fieldFileBase64 the
	// JSON field it becomes — the profile's one unconditionally required payload
	// field (SPEC §5.3.2).
	fieldFile       = "file"
	fieldFileBase64 = "file_base64"
	// fieldFilename is payload too, and travels today as a part header every
	// intermediary can read. JSON-ifying it is what makes sealing it possible.
	fieldFilename = "filename"
	// fieldStream is the profile's optional pin, and the one field this gateway
	// reads for itself — see the typing note in speechDecodeMultipart.
	fieldStream = "stream"
	// e2eeField is the envelope key. A multipart body may not carry a part by
	// this name (SPEC §5.3.1).
	e2eeField = "_e2ee"
)

// speechResponseFormats is the profile's pinned set (SPEC §5.3.2). Both
// JSON-shaped values are permitted: `text` / `srt` / `vtt` return a body that is
// not a JSON object, so there is nowhere to attach `_e2ee` and nothing for §8's
// respH to hash, while excluding `verbose_json` would cost the profile its
// timestamps and with them subtitles.
var speechResponseFormats = []string{"json", "verbose_json"}

// speechDecodeMultipart converts a multipart transcription request into the
// JSON-ified request of SPEC §5.3: each form field becomes a top-level JSON
// field, and the binary `file` part becomes base64 in `file_base64`.
//
// TYPING. Every multipart value is a string, and the enclave turns this object
// back into multipart before the upstream sees it — so carrying a value across
// as the string it arrived as is round-trip correct, not a shortcut. §5.1's
// token comparison is built for exactly that ("a sender that carries them across
// as strings is doing nothing wrong"). The one exception is `stream`, and only
// because THIS GATEWAY reads it: openaiproxy.streamRequested requires a JSON
// boolean, so a multipart `stream=false` — which is legal, and which the pin
// explicitly permits — would otherwise be refused as malformed. Resolving it to
// a real boolean here also collapses the ambiguity §5.3.3 names as the pin's
// reason ("the values a multipart materialization reads as true are an open
// set"): downstream sees `true` or `false` and never has to decide.
//
// So the rule is: type what this gateway interprets, and leave everything else
// as the string the caller sent. `temperature`, `chunking_strategy` and whatever
// a future upstream adds need no entry here and get none.
//
// A field whose name ends in `[]` (the convention an OpenAI SDK uses for
// `timestamp_granularities[]`) becomes a JSON array under the name with the
// brackets stripped, which is the name SPEC §5.3.2 lists. So does any field sent
// more than once, bracketed or not.
func speechDecodeMultipart(body []byte, contentType string) (wire.Request, error) {
	boundary, err := multipartBoundary(contentType)
	if err != nil {
		return nil, err
	}

	req := wire.Request{}
	// Values are collected first and encoded after, so "sent once" and "sent
	// repeatedly" are one decision made in one place rather than a scalar written
	// and then promoted.
	values := map[string][]string{}
	// A name is an array because it was bracketed OR because it repeated; a
	// bracketed name sent once is still an array, which is why this is tracked
	// apart from the count.
	isArray := map[string]bool{}
	var filename string

	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed multipart body: %w", err)
		}
		name := part.FormName()
		if name == "" {
			part.Close()
			return nil, errors.New(`multipart body has a part with no "name": every form field must be named`)
		}
		// SPEC §5.3.1: a multipart request MUST NOT carry a part named `_e2ee`,
		// and one that does MUST be rejected rather than forwarded. wire.SealRequestFor
		// refuses such a request too, but as a seal-stage failure — caught here it is
		// the request error it actually is.
		if name == e2eeField {
			part.Close()
			return nil, fmt.Errorf("multipart body carries a %q part: a sealed envelope cannot be smuggled through a form field (SPEC §5.3.1)", e2eeField)
		}
		// The body is already capped by the caller, so the whole part is bounded;
		// reading it in full is what lets the audio be base64'd without a second
		// buffering strategy. Deliberately NOT ParseMultipartForm, which spills
		// parts over its memory threshold to temporary files — inside the CVM that
		// would write the caller's audio to disk, outside the sealed channel.
		val, err := io.ReadAll(part)
		part.Close()
		if err != nil {
			return nil, fmt.Errorf("read multipart part %q: %w", name, err)
		}
		if name == fieldFile {
			req[fieldFileBase64] = jsonString(base64.StdEncoding.EncodeToString(val))
			// Standard base64 with padding (RFC 4648 §4), NOT the base64url-without-
			// padding of §3. §3 governs binary that appears on the wire in the clear;
			// a payload field rides inside the ciphertext, and `file_base64` already
			// has an unsealed contract on the router's JSON surface — one field name
			// must not have two decoders depending on whether the request was sealed.
			filename = part.FileName()
			continue
		}
		key, bracketed := strings.CutSuffix(name, "[]")
		values[key] = append(values[key], string(val))
		isArray[key] = isArray[key] || bracketed
	}

	if _, ok := req[fieldFileBase64]; !ok {
		return nil, fmt.Errorf("multipart body has no %q part: the audio is the one field a sealed transcription must carry", fieldFile)
	}

	for key, vs := range values {
		if isArray[key] || len(vs) > 1 {
			req[key] = jsonStringArray(vs)
			continue
		}
		req[key] = jsonString(vs[0])
	}
	// After the loop, so the part header wins over a form field of the same name:
	// the header is where an SDK actually puts it, and a request carrying both is
	// incoherent rather than a case to honour.
	if filename != "" {
		req[fieldFilename] = jsonString(filename)
	}
	// The one typed field (see the TYPING note above). An unparseable value is
	// left as the string it was, so openaiproxy answers it with its own
	// `"stream" must be a boolean` rather than this package inventing a second
	// wording for the same complaint.
	if vs, ok := values[fieldStream]; ok && len(vs) == 1 && !isArray[fieldStream] {
		if b, err := strconv.ParseBool(strings.TrimSpace(vs[0])); err == nil {
			req[fieldStream] = jsonBool(b)
		}
	}
	return req, nil
}

// multipartBoundary pulls the boundary out of a Content-Type. The caller has
// already decided the body IS multipart; this re-parses rather than being handed
// the parameters so the decoder is self-contained — it takes a body and a header
// value and needs nothing else.
func multipartBoundary(contentType string) (string, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", fmt.Errorf("malformed Content-Type: %w", err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return "", fmt.Errorf("Content-Type %q is not multipart", mediaType)
	}
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		return "", errors.New("multipart Content-Type has no boundary parameter")
	}
	return boundary, nil
}

// speechPreSeal fills in the profile's pinned cleartext `response_format` when
// the caller omitted it, and rejects a value outside the permitted set.
//
// It is the image row's rule with one difference worth stating, because the two
// pins look identical and are argued differently. On images the DEFAULT IS THE
// LEAK (`url` publishes the generated images outside the sealed channel), so
// filling the field in changes what happens. Here the endpoint's own default
// (`json`) is already permitted, and the pin exists because three of the five
// values cannot be EXPRESSED under sealing at all. So this fill-in is not
// closing a leak — it is supplying the explicit value §5.3.2 requires for a
// reason that has nothing to do with the caller: an absent field takes the
// SERVER's default, and a server's default is not a thing the AAD can bind.
//
// The request is shallow-copied rather than mutated, as PreSeal requires. That
// is cheap even here: wire.Request holds json.RawMessage, so copying the map
// copies slice headers — the base64 audio is not duplicated.
func speechPreSeal(req wire.Request) (wire.Request, error) {
	if raw, ok := req[fieldResponseFormat]; ok && string(raw) != "null" {
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			return nil, fmt.Errorf("%s must be a JSON string, one of %s", fieldResponseFormat, quotedList(speechResponseFormats))
		}
		if !slices.Contains(speechResponseFormats, got) {
			return nil, fmt.Errorf(
				"%s=%q is not supported for a sealed transcription (its response body is not a JSON object, so there is nowhere to attach the sealed envelope); use %s",
				fieldResponseFormat, got, quotedList(speechResponseFormats))
		}
	}

	out := make(wire.Request, len(req)+1)
	for k, v := range req {
		out[k] = v
	}
	if raw, ok := out[fieldResponseFormat]; !ok || string(raw) == "null" {
		// A JSON `null` is the absence of a value rather than a value — the same
		// reading wire.IsE2EESealed gives `_e2ee: null`, and the same one imagePreSeal
		// gives this field.
		out[fieldResponseFormat] = jsonString(speechResponseFormats[0])
	}
	if raw, ok := out[fieldStream]; ok && string(raw) == "null" {
		// Dropped for that same reading, and because leaving it is a divergence with
		// a long fuse: openaiproxy.streamRequested decodes `null` into a bool without
		// error and reads it as "not streaming", while the profile's pin compares a
		// rendered token and refuses `"null"` as a value nothing permits. Kept, the
		// request passes this gateway and is refused three hops away by the enclave.
		delete(out, fieldStream)
	}
	return out, nil
}

// quotedList renders a permitted set for an error message, matching the phrasing
// wire uses for the same pins: always "must be …", never "must not be …", since
// naming the refused value is how a message points at the nearest bypass.
func quotedList(vals []string) string {
	quoted := make([]string, len(vals))
	for i, v := range vals {
		quoted[i] = strconv.Quote(v)
	}
	if len(quoted) == 2 {
		return quoted[0] + " or " + quoted[1]
	}
	return strings.Join(quoted, ", ")
}

// jsonString, jsonStringArray and jsonBool encode a decoded form value. They go
// through encoding/json rather than quoting by hand: every value here is caller
// input, and a filename or prompt containing a quote or a newline must not be
// able to break the object it lands in.
func jsonString(s string) json.RawMessage {
	b, _ := json.Marshal(s) // a string always marshals
	return b
}

func jsonStringArray(vs []string) json.RawMessage {
	b, _ := json.Marshal(vs) // a []string always marshals
	return b
}

func jsonBool(b bool) json.RawMessage {
	if b {
		return json.RawMessage(`true`)
	}
	return json.RawMessage(`false`)
}
