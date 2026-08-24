package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

// dstack ships tcb_info as a nested object on some deployments and as a JSON string
// holding the same document on others. This path used to declare it a string, so the
// object form failed at the OUTER unmarshal — which loses the whole Info reply, not
// just this field, and takes the gateway's own container list with it whenever the
// app-compose file is unavailable and this fallback is what answers.
func TestFetchAppComposeAcceptsBothTCBInfoShapes(t *testing.T) {
	const appCompose = `{"docker_compose_file":"services:\n  gateway:\n    image: x@sha256:aa\n"}`

	inner, err := json.Marshal(map[string]string{"app_compose": appCompose})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, tc := range []struct {
		name    string
		tcbInfo any
	}{
		{"object form", json.RawMessage(inner)},
		{"string form", string(inner)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"app_id": "aabbccdd", "tcb_info": tc.tcbInfo})
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			srv, _ := guestAgent(t, body, 200)

			got, err := FetchAppCompose(context.Background(), httpTo(srv), "aabbccdd", "example.test")
			if err != nil {
				t.Fatalf("FetchAppCompose: %v", err)
			}
			// Byte-for-byte: these are the compose hash preimage, so the wrapper shape must
			// not change what comes out of it.
			if string(got) != appCompose {
				t.Errorf("app_compose = %q, want %q", got, appCompose)
			}
		})
	}
}
