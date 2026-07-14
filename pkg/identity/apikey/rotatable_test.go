// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package apikey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// TestApikey_SecretsRotation_OnlyActiveAuthenticates wires the apikey
// identifier to the shared `secrets:` rotation config format
// (keyrotation.ParseSecretsConfig / buildRotatableStore) and verifies only
// the still-valid (active) secret authenticates — a retired secret (past
// NotAfter + its grace period) must be rejected, not silently accepted.
func TestApikey_SecretsRotation_OnlyActiveAuthenticates(t *testing.T) {
	t.Parallel()
	now := time.Now()
	raw := map[string]any{
		"header": "X-API-Key",
		"secrets": []any{
			map[string]any{
				"kid":      "v1-retired",
				"secret":   "retired-secret-0123456789",
				"notAfter": now.Add(-time.Hour).Format(time.RFC3339),
			},
			map[string]any{
				"kid":    "v2-active",
				"secret": "active-secret-0123456789ab",
			},
		},
	}
	id, err := factory("apikey", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// KeyStates surfaces both entries for observability before either is
	// looked up — Get() auto-prunes retired entries inline, so checking
	// this after Identify calls below would only see the survivor.
	rot, ok := id.(module.Rotatable)
	if !ok {
		t.Fatal("expected identifier to implement module.Rotatable when secrets: is configured")
	}
	if states := rot.KeyStates(); len(states) != 2 {
		t.Errorf("KeyStates() returned %d entries, want 2", len(states))
	}

	got, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-API-Key": {"active-secret-0123456789ab"}},
	})
	if err != nil {
		t.Fatalf("active secret should authenticate: %v", err)
	}
	if got.Claims["keyId"] != "v2-active" {
		t.Errorf("keyId = %v, want v2-active", got.Claims["keyId"])
	}

	_, err = id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-API-Key": {"retired-secret-0123456789"}},
	})
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (retired secret must not authenticate)", err)
	}
}

// TestApikey_SecretsRotation_MutuallyExclusiveWithStatic verifies the
// factory rejects configs that mix `secrets:` with `static`/`hashed`.
func TestApikey_SecretsRotation_MutuallyExclusiveWithStatic(t *testing.T) {
	t.Parallel()
	_, err := factory("apikey", map[string]any{
		"header": "X-API-Key",
		"static": map[string]any{"k1": "alice"},
		"secrets": []any{
			map[string]any{"kid": "v1", "secret": "active-secret-0123456789ab"},
		},
	})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig (secrets/static are mutually exclusive)", err)
	}
}
