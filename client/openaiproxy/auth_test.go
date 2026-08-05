package openaiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler is the wrapped handler standing in for the sealed chat route: it
// records that the gate let the request through and returns 200.
func okHandler(passed *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*passed = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestRequireInferenceCredential(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		wantStatus int
		wantPass   bool // whether the wrapped handler should be reached
	}{
		{"no credential", nil, http.StatusUnauthorized, false},
		{"empty bearer", map[string]string{"Authorization": "Bearer "}, http.StatusUnauthorized, false},
		{"non-bearer authorization", map[string]string{"Authorization": "Basic abc"}, http.StatusUnauthorized, false},
		{"mgmt key via authorization", map[string]string{"Authorization": "Bearer mk-abc"}, http.StatusForbidden, false},
		{"mgmt key via x-api-key", map[string]string{"x-api-key": "mk-abc"}, http.StatusForbidden, false},
		{"inference key passes on prefix", map[string]string{"Authorization": "Bearer sk-abc"}, http.StatusOK, true},
		{"short inference key still passes (prefix only)", map[string]string{"Authorization": "Bearer sk-x"}, http.StatusOK, true},
		{"inference key via x-api-key", map[string]string{"x-api-key": "sk-abc"}, http.StatusOK, true},
		{"jwt-shaped token passes through", map[string]string{"Authorization": "Bearer eyJhbGciOi.J.k"}, http.StatusOK, true},
		{"opaque token passes through", map[string]string{"Authorization": "Bearer privy-token-xyz"}, http.StatusOK, true},
		{"lowercase bearer scheme", map[string]string{"Authorization": "bearer sk-abc"}, http.StatusOK, true},
		{"authorization wins over x-api-key", map[string]string{"Authorization": "Bearer sk-abc", "x-api-key": "mk-should-be-ignored"}, http.StatusOK, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var passed bool
			h := RequireInferenceCredential(okHandler(&passed))

			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if passed != tc.wantPass {
				t.Errorf("wrapped handler reached = %v, want %v", passed, tc.wantPass)
			}
			// A rejection must carry the canonical gateway error envelope so a thin
			// client parses it identically to the sealed path's errors.
			if !tc.wantPass {
				var body struct {
					Error struct {
						Message string `json:"message"`
						Type    string `json:"type"`
					} `json:"error"`
					ZG struct {
						Source string `json:"source"`
					} `json:"_0g"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatalf("rejection body is not the JSON error envelope: %v", err)
				}
				if body.Error.Message == "" {
					t.Error("rejection envelope missing error.message")
				}
				if body.ZG.Source != "gateway" {
					t.Errorf("rejection source = %q, want %q", body.ZG.Source, "gateway")
				}
			}
		})
	}
}
