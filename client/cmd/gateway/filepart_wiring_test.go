package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-pc-e2ee/client/endpoint"
	"github.com/0gfoundation/0g-pc-e2ee/client/openaiproxy"
)

// The refusal's own rules are tested in openaiproxy (fileparts_test.go). This
// is the wiring: that the gateway tells the sealed path when "0g/auto" can be
// offered, and marks the requests that already came that way.

const filePartBodyFor = `{"model":%q,"messages":[{"role":"user","content":[` +
	`{"type":"text","text":"summarize"},` +
	`{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,AA=="}}]}]}`

func filePartBody(model string) string {
	b, _ := json.Marshal(model)
	return strings.Replace(filePartBodyFor, "%q", string(b), 1)
}

// refusalMessage fails unless resp is the file-part 400, and returns its message.
func refusalMessage(t *testing.T, resp *http.Response, body string) string {
	t.Helper()
	var got struct {
		Error struct{ Message, Code string }
	}
	_ = json.Unmarshal([]byte(body), &got)
	if resp.StatusCode != http.StatusBadRequest || got.Error.Code != openaiproxy.ErrCodeSealedFilePart {
		t.Fatalf("status %d, body %s; want the %s 400", resp.StatusCode, body, openaiproxy.ErrCodeSealedFilePart)
	}
	return got.Error.Message
}

// A request naming a sealed model on a gateway that routes "0g/auto" is told
// it can use it.
func TestFilePartNamedSealedModelOffersAuto(t *testing.T) {
	f := &fakeAutoRouter{}
	resp, body := postAuto(t, autoGateway(t, f).URL, filePartBody(sealedModel), nil)
	if msg := refusalMessage(t, resp, body); !strings.Contains(msg, `"0g/auto"`) {
		t.Errorf("message %q does not offer 0g/auto", msg)
	}
	if len(f.chatBodies) != 0 {
		t.Error("the refused request reached the router")
	}
}

// "0g/auto" that still lands on a sealed model (the account allows only
// sealable ones, say) is refused without suggesting "0g/auto" again.
func TestFilePartAutoChosenSealedDoesNotOfferAuto(t *testing.T) {
	f := &fakeAutoRouter{task: "x", chosen: sealedModel}
	resp, body := postAuto(t, autoGateway(t, f).URL, filePartBody("0g/auto"), nil)
	if msg := refusalMessage(t, resp, body); strings.Contains(msg, "0g/auto") {
		t.Errorf("an auto-routed request was told to use 0g/auto: %q", msg)
	}
	if len(f.chatBodies) != 0 {
		t.Error("the refused request reached the router")
	}
}

// A gateway that seals every model does not route "0g/auto", so it must not
// offer it.
func TestFilePartSealAllDoesNotOfferAuto(t *testing.T) {
	f := &fakeAutoRouter{}
	gw := catalogGateway(t, f.server(t), entryPolicy{sealModels: mustSealModels(t, "*")})
	resp, body := postAuto(t, gw.URL, filePartBody(sealedModel), nil)
	if msg := refusalMessage(t, resp, body); strings.Contains(msg, "0g/auto") {
		t.Errorf("a seal-all gateway offered 0g/auto: %q", msg)
	}
}

// noFileSealedModels are the models checked to read no files: their endpoints
// declare no "file" input modality, so the router would read a file part into
// text for them in the clear, and sealed they would refuse it (0gm with a 400
// from vLLM). openaiproxy.refuseFilePart relies on this: it refuses a sealed
// request carrying a file before the route is resolved.
//
// Adding a model to a deployed seal list means adding it here, after checking
// that its endpoints do not declare "file". If one does, this list is not the
// thing to change: refuseFilePart is (see THE PRECONDITION there).
var noFileSealedModels = map[string]bool{
	"0gm-1.0-35b-a3b":      true,
	"glm-5.3":              true,
	"qwen3-embedding-8b":   true, // embeddings: no messages
	"qwen3-embedding-0.6b": true, // embeddings: no messages
	"vela-2.0-9b":          true, // /v1/decisions
}

// envSealModels reads a deploy target's seal list out of its env file.
var envSealModels = regexp.MustCompile(`(?m)^CVM_ENV_ZG_GATEWAY_SEAL_MODELS='([^']*)'`)

// TestSealedModelsReadNoFiles pins refuseFilePart's precondition to what is
// deployed: every model a deploy target or the compose default seals is one
// checked to read no files, and neither seals a whole chat surface.
func TestSealedModelsReadNoFiles(t *testing.T) {
	lists := map[string]string{}
	compose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	m := composeSealModels.FindSubmatch(compose)
	if m == nil {
		t.Fatalf("no ZG_GATEWAY_SEAL_MODELS=${...-<default>} entry in %s", composePath)
	}
	lists[composePath] = string(m[2])
	envs, _ := filepath.Glob(filepath.Join(filepath.Dir(composePath), "env", "*.env"))
	if len(envs) == 0 {
		t.Fatal("no deploy env files found")
	}
	for _, p := range envs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if m := envSealModels.FindSubmatch(b); m != nil {
			lists[p] = string(m[1])
		}
	}
	for src, csv := range lists {
		s, err := parseSealModels(csv)
		if err != nil {
			t.Errorf("%s: seal list %q does not parse: %v", src, csv, err)
			continue
		}
		if s.all() {
			t.Errorf("%s seals every model; refuseFilePart cannot assume none reads files", src)
			continue
		}
		for _, chat := range []string{endpoint.Chat.Path, endpoint.Anthropic.Path} {
			if entry, ok := s.surfaces[chat]; ok {
				t.Errorf("%s seals the whole %s surface (%s); refuseFilePart cannot assume none of its models reads files", src, chat, entry)
			}
		}
		for model := range s.allow {
			if !noFileSealedModels[model] {
				t.Errorf("%s seals %q, which is not in noFileSealedModels: check that it reads no files, then add it", src, model)
			}
		}
	}
}
