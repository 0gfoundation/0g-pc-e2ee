package core_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/core"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/crypto"
	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// This test reproduces (or fails to reproduce) the streaming decode error
//
//	open stream frame: open: chacha20poly1305: message authentication failed
//
// against the REAL sidecar decoder (core.CompleteStream: the sseReader + per-frame
// frame.E2EE() + opener.OpenFrame loop), by standing up an httptest "provider"
// that seals a faithful SSE stream and then applies a Router-style reframing of
// the tail. The hypothesis under test: the failure comes from the Router changing
// SSE frame STRUCTURE/ORDER (desyncing the per-frame AEAD sequence), not from
// mutating bound field content.
//
// The Router transform is decomposed so we can see which sub-change is the
// minimal trigger:
//
//	T1  stray bare blank line before the usage frame       (SSE boundary noise)
//	T2  reorder sealed frames (usage frame moved earlier)  (frame ORDER change)
//	T3  reserialize + fold x_0g_trace/model into the frame (UNBOUND content change)
//	T3b rewrite a BOUND field (usage) on the sealed frame  (BOUND content change)
//
// Decoder facts this pins down (answers the "decoder details" questions):
//   - The AEAD nonce is a per-frame sequence counter internal to the one HPKE
//     response context; it is NOT carried on the wire and advances once per
//     opener.OpenFrame call. Order/count of SEALED frames is therefore load-bearing.
//   - A frame's AAD is JCS(frame minus _e2ee.ciphertext minus the unbound field
//     values) — the frame's own bytes only. No frame index / running hash / length
//     is in the AAD; ordering is protected solely by the AEAD sequence (the nonce).
//   - sseReader dispatches an event only when a `data:` line was seen before the
//     blank line, so a bare blank line emits no event and never advances the seq.
//   - Every streamed frame must carry `_e2ee`; a plaintext usage frame with none
//     fails at frame.E2EE() ("frame missing _e2ee"), a DIFFERENT error, before any
//     AEAD open.

var reframeSigner = "0x" + strings.Repeat("a", 40)

func streamReq() wire.Request {
	return wire.Request{
		"model":    json.RawMessage(`"gpt-4o"`),
		"stream":   json.RawMessage(`true`),
		"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
	}
}

// sealTail seals the canonical provider tail to ephPub: two content frames then a
// final frame carrying cleartext usage. Response unbound = [model, x_0g_trace],
// mirroring the deployment where the Router rewrites model and folds a trace.
// Returned blobs are in seal order (AEAD seq 0,1,2).
func sealTail(ephPub crypto.PublicKey) (c0, c1, fin []byte, err error) {
	sealer, err := wire.NewResponseSealer(ephPub, "model", "x_0g_trace")
	if err != nil {
		return nil, nil, nil, err
	}
	specs := []struct {
		choices, usage string
		final          bool
	}{
		{choices: `[{"index":0,"delta":{"content":"he"}}]`},
		{choices: `[{"index":0,"delta":{"content":"llo"}}]`},
		{choices: `[{"index":0,"delta":{},"finish_reason":"stop"}]`, usage: `{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13}`, final: true},
	}
	var blobs [][]byte
	for _, s := range specs {
		fr := wire.Response{"model": json.RawMessage(`"gpt-4o"`), "choices": json.RawMessage(s.choices)}
		if s.usage != "" {
			fr["usage"] = json.RawMessage(s.usage)
		}
		sealed, err := sealer.SealFrame(fr, nil, s.final)
		if err != nil {
			return nil, nil, nil, err
		}
		blob, err := json.Marshal(sealed)
		if err != nil {
			return nil, nil, nil, err
		}
		blobs = append(blobs, blob)
	}
	return blobs[0], blobs[1], blobs[2], nil
}

// foldUnbound simulates the Router buffering the frame, rewriting model, folding
// x_0g_trace, and re-marshaling (key reorder). It only touches UNBOUND top-level
// fields and leaves _e2ee (a RawMessage) byte-verbatim.
func foldUnbound(blob []byte) []byte {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(blob, &m)
	m["model"] = json.RawMessage(`"router-rewritten-model"`)
	m["x_0g_trace"] = json.RawMessage(`{"rid":"abc-123","span":"7"}`)
	out, _ := json.Marshal(m)
	return out
}

// mutateBound rewrites the BOUND `usage` value (a Router overbilling attempt).
func mutateBound(blob []byte) []byte {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(blob, &m)
	m["usage"] = json.RawMessage(`{"prompt_tokens":10,"completion_tokens":9999,"total_tokens":10009}`)
	out, _ := json.Marshal(m)
	return out
}

func dataLine(payload []byte) string { return "data: " + string(payload) + "\n\n" }

// runReframe stands up the provider, seals the tail, lets `reframe` rewrite the
// SSE body bytes from the three sealed blobs, and drives the real decoder.
func runReframe(t *testing.T, reframe func(c0, c1, fin []byte) string) ([]wire.Response, error) {
	t.Helper()
	_, encPub, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("provider keygen: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env wire.Request
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		e2ee, err := env.E2EE()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ephPub, err := base64.RawURLEncoding.DecodeString(e2ee.ClientEphPub)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c0, c1, fin, err := sealTail(ephPub)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, reframe(c0, c1, fin))
	}))
	defer srv.Close()

	client := core.New(
		core.Provider{URL: srv.URL, EncPubKey: encPub, SignerAddr: reframeSigner},
		core.WithSealFields([]string{"messages"}),
	)
	var got []wire.Response
	err = client.CompleteStream(context.Background(), streamReq(), func(f wire.Response) error {
		got = append(got, f)
		return nil
	})
	return got, err
}

func TestStreamRouterReframing(t *testing.T) {
	done := dataLine([]byte("[DONE]"))

	cases := []struct {
		name    string
		reframe func(c0, c1, fin []byte) string
		// wantMAC: expect the chacha20poly1305 MAC failure.
		wantMAC bool
		// wantErr: expect any error (superset of wantMAC).
		wantErr bool
	}{
		{
			name:    "baseline_untouched",
			reframe: func(c0, c1, fin []byte) string { return dataLine(c0) + dataLine(c1) + dataLine(fin) + done },
		},
		{
			name: "T1_stray_blank_line_before_usage",
			// A bare blank line injected before the (in-order) usage frame.
			reframe: func(c0, c1, fin []byte) string {
				return dataLine(c0) + dataLine(c1) + "\n" + dataLine(fin) + done
			},
		},
		{
			name: "T2_reorder_sealed_frames",
			// usage frame emitted before the last content frame => sealed frames
			// arrive out of seal order.
			reframe: func(c0, c1, fin []byte) string {
				return dataLine(c0) + dataLine(fin) + dataLine(c1) + done
			},
			wantMAC: true,
			wantErr: true,
		},
		{
			name: "T3_fold_unbound_model_and_trace",
			// Rewrite model + fold x_0g_trace into the (in-order) usage frame.
			reframe: func(c0, c1, fin []byte) string {
				return dataLine(c0) + dataLine(c1) + dataLine(foldUnbound(fin)) + done
			},
		},
		{
			name: "T3b_mutate_bound_usage",
			// Rewrite the BOUND usage value on the (in-order) usage frame.
			reframe: func(c0, c1, fin []byte) string {
				return dataLine(c0) + dataLine(c1) + dataLine(mutateBound(fin)) + done
			},
			wantMAC: true,
			wantErr: true,
		},
		{
			name: "T_literal_stray_plus_fold_no_reorder",
			// The Router's LITERAL described behavior: stray blank line + reserialize
			// + fold unbound, but usage kept last (no sealed-frame reorder).
			reframe: func(c0, c1, fin []byte) string {
				return dataLine(c0) + dataLine(c1) + "\n" + dataLine(foldUnbound(fin)) + done
			},
		},
		{
			name: "T_all_reorder_plus_fold_plus_stray",
			reframe: func(c0, c1, fin []byte) string {
				return dataLine(c0) + "\n" + dataLine(foldUnbound(fin)) + dataLine(c1) + done
			},
			wantMAC: true,
			wantErr: true,
		},
		{
			name: "plaintext_usage_tail_no_e2ee",
			// The literal provider frame the hypothesis assumes: a plaintext usage
			// frame with no _e2ee. Here c1 is the final sealed frame.
			reframe: func(c0, c1, fin []byte) string {
				// Re-seal with c1 as final is overkill; reuse c0 then a plaintext tail.
				plain := `{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13}}`
				return dataLine(c0) + dataLine(c1) + dataLine([]byte(plain)) + done
			},
			wantErr: true, // fails, but NOT with a MAC error
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := runReframe(t, tc.reframe)
			gotErr := err != nil
			gotMAC := err != nil && strings.Contains(err.Error(), "message authentication failed")

			if gotErr {
				t.Logf("%-40s -> error: %v", tc.name, err)
			} else {
				t.Logf("%-40s -> OK (%d frames opened)", tc.name, len(got))
			}

			if gotErr != tc.wantErr {
				t.Errorf("%s: got error=%v (%v), want error=%v", tc.name, gotErr, err, tc.wantErr)
			}
			if gotMAC != tc.wantMAC {
				t.Errorf("%s: got MAC-failure=%v, want MAC-failure=%v (err=%v)", tc.name, gotMAC, tc.wantMAC, err)
			}
			// The plaintext-tail case must fail for a DIFFERENT reason than a MAC.
			if tc.name == "plaintext_usage_tail_no_e2ee" && gotErr && !strings.Contains(err.Error(), "_e2ee") {
				t.Errorf("plaintext tail: expected an _e2ee-metadata error, got %v", err)
			}
		})
	}
}
