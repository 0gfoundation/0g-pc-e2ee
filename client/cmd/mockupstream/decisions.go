package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// handleDecisions is the sealed decisions path — handleEmbeddings' counterpart
// for POST /v1/decisions (SPEC §7.7). It opens under the DECISIONS profile, so
// the sealed set must cover `state` and `questions`, and answers with `answers`
// sealed and `usage.input_tokens` cleartext.
//
// The answer is DERIVED from what it opened, so the client's view is evidence
// that both fields survived the round trip: each question is answered with its
// first criterion in sorted order, and input_tokens is the word count of
// `state`.
func (s *server) handleDecisions(w http.ResponseWriter, r *http.Request) {
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
	opened, err := wire.OpenRequestFor(wire.ProfileDecisions, s.encPriv, env)
	if err != nil {
		writeError(w, http.StatusBadRequest, "sealed decisions request did not open: "+err.Error())
		return
	}
	var state string
	if err := json.Unmarshal(opened["state"], &state); err != nil {
		writeError(w, http.StatusBadRequest, "state must be a string")
		return
	}
	var questions map[string]struct {
		Criteria map[string]string `json:"criteria"`
	}
	if err := json.Unmarshal(opened["questions"], &questions); err != nil || len(questions) == 0 {
		writeError(w, http.StatusBadRequest, "questions must be a non-empty object")
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

	answers := map[string]map[string]any{}
	for name, q := range questions {
		keys := make([]string, 0, len(q.Criteria))
		for k := range q.Criteria {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("question %q has no criteria", name))
			return
		}
		answers[name] = map[string]any{"type": "choice", "choice": keys[0], "confidence": 1.0}
	}
	var answersRaw, usageRaw json.RawMessage
	if err := marshalInto(&answersRaw, answers); err != nil {
		writeError(w, http.StatusInternalServerError, "encode answers")
		return
	}
	if err := marshalInto(&usageRaw, map[string]int{"input_tokens": len(strings.Fields(state)), "output_tokens": 0}); err != nil {
		writeError(w, http.StatusInternalServerError, "encode usage")
		return
	}
	frame := wire.Response{"model": s.modelRaw, "usage": usageRaw, "answers": answersRaw}
	sealed, err := wire.SealResponseFor(wire.ProfileDecisions, crypto.PublicKey(ephPub), frame, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "seal decisions response: "+err.Error())
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
