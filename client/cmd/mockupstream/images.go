package main

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/proof"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// handleImages is the sealed image path — the counterpart of handleCompletions
// for POST /v1/images/generations. It exists so the image profile has an end to
// end fixture at all: without it every image test stops at a package boundary,
// and nothing proves a sealed image request survives gateway → route → seal →
// provider → open.
//
// It opens under the IMAGE profile, which is the point. wire.OpenRequestFor
// enforces what a real enclave enforces — the sealed set covers `prompt`, and
// `response_format` is present, `b64_json`, cleartext and bound — so a gateway
// change that seals the wrong field, or drops the pinned format, fails here
// rather than passing silently.
func (s *server) handleImages(w http.ResponseWriter, r *http.Request) {
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
	if _, err := wire.OpenRequestFor(wire.ProfileImage, s.encPriv, env); err != nil {
		writeError(w, http.StatusBadRequest, "sealed image request did not open: "+err.Error())
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
	var createdRaw json.RawMessage
	if err := marshalInto(&createdRaw, time.Now().Unix()); err != nil {
		writeError(w, http.StatusInternalServerError, "encode response timestamp")
		return
	}

	// One image, and a cleartext usage.output_images to match — the count the
	// router bills on (SPEC §7.1). Sealing `data` while publishing the count is
	// the whole shape of the profile, so the fixture emits it rather than a
	// stripped-down frame that would let a missing count go unnoticed.
	frame := wire.Response{
		"created": createdRaw,
		"model":   s.modelRaw,
		"usage":   json.RawMessage(`{"output_images":1}`),
		"data":    json.RawMessage(`[{"b64_json":"aW1hZ2VieXRlcw=="}]`),
	}
	sealed, err := wire.SealResponseFor(wire.ProfileImage, crypto.PublicKey(ephPub), frame, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "seal image response")
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
