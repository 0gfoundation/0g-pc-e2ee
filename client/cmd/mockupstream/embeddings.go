package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// handleEmbeddings is the sealed embedding path — the counterpart of
// handleImages for POST /v1/embeddings, and the fixture that lets a sealed
// embedding request be followed gateway → route → seal → provider → open.
//
// It opens under the EMBEDDING profile, which enforces what a real enclave
// enforces: the sealed set covers `input`. It then answers with §7.4's shape —
// `data` sealed, `usage.prompt_tokens` cleartext — and wire.SealResponseFor
// refuses a frame without that count, so the fixture cannot drift into emitting
// the unbillable response the profile exists to prevent.
//
// The response is DERIVED from the opened input rather than being a constant:
// one vector per input string, whose single component is that string's byte
// length, and a prompt_tokens equal to the total word count. So what the client
// finally opens is evidence that the input survived the round trip — how many
// strings, and how long each was — which a constant response could not be.
func (s *server) handleEmbeddings(w http.ResponseWriter, r *http.Request) {
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
	opened, err := wire.OpenRequestFor(wire.ProfileEmbedding, s.encPriv, env)
	if err != nil {
		writeError(w, http.StatusBadRequest, "sealed embedding request did not open: "+err.Error())
		return
	}
	inputs, err := embeddingInputs(opened["input"])
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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

	type item struct {
		Object    string    `json:"object"`
		Index     int       `json:"index"`
		Embedding []float64 `json:"embedding"`
	}
	data := make([]item, len(inputs))
	promptTokens := 0
	for i, in := range inputs {
		data[i] = item{Object: "embedding", Index: i, Embedding: []float64{float64(len(in))}}
		promptTokens += len(strings.Fields(in))
	}
	var dataRaw, usageRaw json.RawMessage
	if err := marshalInto(&dataRaw, data); err != nil {
		writeError(w, http.StatusInternalServerError, "encode embeddings")
		return
	}
	if err := marshalInto(&usageRaw, map[string]int{"prompt_tokens": promptTokens, "total_tokens": promptTokens}); err != nil {
		writeError(w, http.StatusInternalServerError, "encode usage")
		return
	}
	var createdRaw json.RawMessage
	if err := marshalInto(&createdRaw, time.Now().Unix()); err != nil {
		writeError(w, http.StatusInternalServerError, "encode response timestamp")
		return
	}
	frame := wire.Response{
		"object":  json.RawMessage(`"list"`),
		"created": createdRaw,
		"model":   s.modelRaw,
		"usage":   usageRaw,
		"data":    dataRaw,
	}
	sealed, err := wire.SealResponseFor(wire.ProfileEmbedding, crypto.PublicKey(ephPub), frame, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "seal embedding response: "+err.Error())
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

// embeddingInputs reads `input` as the two text shapes /v1/embeddings accepts:
// one string, or an array of strings. The token-array shapes are real OpenAI
// shapes too, but nothing in this fixture's tests sends them, and answering one
// with an invented length would make the derived response a claim about input
// the fixture never actually read.
func embeddingInputs(raw json.RawMessage) ([]string, error) {
	// Decoding `null` into a string is a no-op that returns no error, so it
	// would otherwise read as one empty input.
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("input is missing")
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil && len(many) > 0 {
		return many, nil
	}
	return nil, fmt.Errorf("input must be a string or a non-empty array of strings, got %s", raw)
}
