// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package introspection

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// TestIntrospection_SecretsRotation_UsesActiveSecret wires the
// introspection identifier to the shared `secrets:` rotation config
// format and verifies the Basic Auth sent to the introspection endpoint
// uses the still-active secret, not the retired one — cfg.ClientSecret is
// read fresh on every callIntrospection call, so resolveSecret's
// per-request resolution takes effect immediately.
func TestIntrospection_SecretsRotation_UsesActiveSecret(t *testing.T) {
	t.Parallel()
	now := time.Now()
	var gotPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pass, _ := r.BasicAuth()
		gotPass = pass
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "sub": "alice", "exp": float64(time.Now().Add(time.Hour).Unix()),
		})
	}))
	defer srv.Close()

	a, err := factory("introspect", map[string]any{
		"url":      srv.URL,
		"clientId": "lwauth",
		"secrets": []any{
			map[string]any{
				"kid":      "v1-retired",
				"secret":   base64.StdEncoding.EncodeToString([]byte("retired-secret-0123456789ab")),
				"notAfter": now.Add(-time.Hour).Format(time.RFC3339),
			},
			map[string]any{
				"kid":    "v2-active",
				"secret": base64.StdEncoding.EncodeToString([]byte("active-secret-0123456789ab!!")),
			},
		},
	}, testDeps(t))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	if _, ok := a.(module.Rotatable); !ok {
		t.Fatal("expected identifier to implement module.Rotatable when secrets: is configured")
	}

	if _, err := a.Identify(t.Context(), req("tok")); err != nil {
		t.Fatalf("Identify: %v", err)
	}

	wantSecret := "active-secret-0123456789ab!!"
	if gotPass != wantSecret {
		t.Errorf("Basic Auth password = %q, want %q (active secret)", gotPass, wantSecret)
	}
}
