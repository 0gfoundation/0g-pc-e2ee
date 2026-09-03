package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// handleMessages is the sealed /v1/messages path — the Anthropic counterpart of
// handleCompletions, for the same reason handleImages exists: without it every
// test of that surface stops at a package boundary, and nothing proves a sealed
// Anthropic request survives gateway → route → seal → router → provider → open
// → per-frame unseal.
//
// It opens under the ANTHROPIC profile, which is what makes it a test and not a
// lookalike. wire.OpenRequestFor enforces what a real enclave enforces — the
// sealed set covers `messages`, and `system` too WHEN PRESENT, which the chat
// profile has no opinion about — so a gateway that sealed this surface under
// chat's rules fails here instead of shipping the system prompt in the clear.
//
// Its responses are frame-typed (SPEC §7.2), so unlike the other two surfaces
// each frame seals a different field and the stream ends with a terminal frame
// of its own rather than a `[DONE]` sentinel. The sealed set per frame comes from
// wire.ResponseSealedFieldsForFrame rather than a list here, so this fixture
// tracks the taxonomy instead of restating it.
func (s *server) handleMessages(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read request body")
		return
	}
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
	if _, err := wire.OpenRequestFor(wire.ProfileAnthropic, s.encPriv, env); err != nil {
		writeError(w, http.StatusBadRequest, "sealed Anthropic request did not open: "+err.Error())
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

	if streamRequested(env) {
		s.serveAnthropicStream(w, r, ephPub, reqH, chatKey)
		return
	}
	s.serveAnthropicMessage(w, r, ephPub, reqH, chatKey)
}

// anthropicText is the generated text one frame carries, sized by -chunk-bytes.
// Built once per request rather than precomputed on the server like the chat
// path's choices: this surface exists for protocol fidelity first, and a load
// run that targets it can precompute then.
func (s *server) anthropicText() string {
	return strings.Repeat("x", s.cfg.ChunkBytes)
}

// serveAnthropicMessage answers a non-streaming /v1/messages request: one
// `message` frame holding the whole content array, sealed, marked final.
func (s *server) serveAnthropicMessage(w http.ResponseWriter, r *http.Request, ephPub []byte, reqH [32]byte, chatKey string) {
	if !sleep(r.Context(), s.completionDuration()) {
		return
	}
	content, err := json.Marshal([]map[string]string{{"type": "text", "text": s.anthropicText()}})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode content")
		return
	}
	frame := wire.Response{
		"id":      json.RawMessage(`"msg_` + chatKey + `"`),
		"type":    json.RawMessage(`"message"`),
		"role":    json.RawMessage(`"assistant"`),
		"model":   s.modelRaw,
		"content": content,
		"usage":   s.anthropicUsageRaw(),
	}
	// Explicit sealed fields: this profile has no profile-wide default (what a
	// frame seals is a property of the frame), so nil — which the chat path can
	// pass — would be refused here.
	fields, err := wire.ResponseSealedFieldsForFrame(wire.ProfileAnthropic, frame)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "resolve sealed fields")
		return
	}
	sealed, err := wire.SealResponseFor(wire.ProfileAnthropic, crypto.PublicKey(ephPub), frame, fields)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "seal response")
		return
	}
	// The SINGLE-FRAME §8 scheme, not the streaming one. A stream binder here
	// signs under "zg-sig-v1/e2ee-ct-stream" and the client — which asked for a
	// non-streaming response and so expects "zg-sig-v1/e2ee-ct" — rejects the
	// signature - and therefore the whole response. Same split the chat path
	// draws between serveBuffered and serveStream.
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

// serveAnthropicStream answers a streaming /v1/messages request as the §7.2
// event sequence.
//
// The shape of the turn, not just its content, is what a client is tested
// against: message_start carries the input token count in a `message` the
// profile protects as cleartext (so its content array must be EMPTY — checked on
// every frame, not just this one), the deltas carry the text, message_delta
// carries the output count, and message_stop is TERMINAL. There is no `[DONE]`:
// a receiver that appends one is emitting an event the taxonomy has no rule for.
//
// Every frame gets an `event:` line naming its own type, as a real broker sends —
// but a conforming client must NOT trust it. §7.2 puts that line outside the JSON
// and therefore outside the AAD, so an intermediary can rewrite it undetected; a
// receiver rebuilds it from the frame's bound `type`. This fixture sends the
// honest name because it is impersonating an honest broker.
func (s *server) serveAnthropicStream(w http.ResponseWriter, r *http.Request, ephPub []byte, reqH [32]byte, chatKey string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	sealer, err := wire.NewResponseSealerFor(wire.ProfileAnthropic, crypto.PublicKey(ephPub))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "set up response sealing")
		return
	}
	var binder *proof.StreamBinder
	if s.cfg.Sign {
		binder = proof.NewStreamBinderFromReqHash(reqH)
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ZG-Res-Key", chatKey)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// The delta frames are the paced ones; the metadata frames around them go out
	// with whichever delta they neighbour, so -ttft still measures the wait for
	// the first TOKEN rather than for the first event.
	frames := make([]wire.Response, 0, s.cfg.Chunks+5)
	frames = append(frames,
		wire.Response{
			"type": json.RawMessage(`"message_start"`),
			"message": json.RawMessage(`{"id":"msg_` + chatKey + `","type":"message","role":"assistant","model":` +
				string(s.modelRaw) + `,"content":[],"usage":{"input_tokens":` + fmt.Sprint(promptTokens) + `}}`),
		},
		wire.Response{
			"type":          json.RawMessage(`"content_block_start"`),
			"index":         json.RawMessage(`0`),
			"content_block": json.RawMessage(`{"type":"text","text":""}`),
		},
	)
	text, err := json.Marshal(s.anthropicText())
	if err != nil {
		return
	}
	for range s.cfg.Chunks {
		frames = append(frames, wire.Response{
			"type":  json.RawMessage(`"content_block_delta"`),
			"index": json.RawMessage(`0`),
			"delta": json.RawMessage(`{"type":"text_delta","text":` + string(text) + `}`),
		})
	}
	frames = append(frames,
		wire.Response{"type": json.RawMessage(`"content_block_stop"`), "index": json.RawMessage(`0`)},
		wire.Response{
			"type":  json.RawMessage(`"message_delta"`),
			"delta": json.RawMessage(`{"stop_reason":"end_turn","stop_sequence":null}`),
			// ONLY the output count, as the real surface sends it: the input count
			// arrived on message_start. Repeating it here is not a protocol
			// violation (`usage` has no required shape, only the rule that it stays
			// cleartext) but a client summing across frames would double-count it,
			// and this fixture's value is being indistinguishable from the real thing.
			"usage": json.RawMessage(fmt.Sprintf(`{"output_tokens":%d}`, s.cfg.Chunks)),
		},
		wire.Response{"type": json.RawMessage(`"message_stop"`)},
	)

	pace := newPacer()
	defer pace.stop()
	buf := &bytes.Buffer{}
	ctx := r.Context()
	firstDelta := true
	for i, frame := range frames {
		if isContentDelta(frame) {
			gap := s.cfg.ChunkInterval
			if firstDelta {
				gap = s.cfg.TTFT
				firstDelta = false
			}
			if !pace.wait(ctx, gap) {
				return
			}
		}
		final := i == len(frames)-1
		sealed, err := s.sealAnthropicFrame(sealer, frame, final)
		if err != nil {
			// Mid-stream the status is long gone, so cutting the connection is the
			// only honest signal; the gateway reports it as a truncated stream.
			return
		}
		if binder != nil {
			if err := binder.AddFrame(sealed); err != nil {
				return
			}
			// Before the final frame is on the wire: the gateway finishes the stream
			// on that frame and fetches the signature immediately after.
			if final {
				sigText, err := binder.Text()
				if err != nil {
					return
				}
				s.sigs.put(chatKey, s.sign(sigText))
			}
		}
		name, err := wire.ResponseEventName(wire.ProfileAnthropic, frame)
		if err != nil {
			return
		}
		buf.Reset()
		buf.WriteString("event: ")
		buf.WriteString(name)
		buf.WriteString("\ndata: ")
		if err := json.NewEncoder(buf).Encode(sealed); err != nil { // Encode appends the newline
			return
		}
		buf.WriteString("\n")
		if _, err := w.Write(buf.Bytes()); err != nil {
			return
		}
		flusher.Flush()
	}
}

// sealAnthropicFrame seals one frame under the field set ITS OWN shape requires,
// which for a frame-typed profile is the only correct answer — passing nil would
// ask for a profile-wide default this profile deliberately does not have.
func (s *server) sealAnthropicFrame(sealer *wire.ResponseSealer, frame wire.Response, final bool) (wire.Response, error) {
	fields, err := wire.ResponseSealedFieldsForFrame(wire.ProfileAnthropic, frame)
	if err != nil {
		return nil, err
	}
	return sealer.SealFrame(frame, fields, final)
}

// isContentDelta reports whether a frame is one of the text-carrying ones, so
// only those are paced.
func isContentDelta(frame wire.Response) bool {
	return string(frame["type"]) == `"content_block_delta"`
}

// promptTokens is the synthetic input count message_start reports. A fixed
// plausible number: nothing here bills, and the value's job is to be a readable
// cleartext count in the place §7.2 puts it.
const promptTokens = 11

// anthropicUsageRaw is the non-streaming `message` frame's cleartext `usage`,
// which carries BOTH counts because that frame is the whole turn. The streaming
// path splits them the way the real surface does: input on message_start, output
// on message_delta. Sized off -chunks so it moves with the content rather than
// contradicting it.
func (s *server) anthropicUsageRaw() json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"input_tokens":%d,"output_tokens":%d}`, promptTokens, s.cfg.Chunks))
}
