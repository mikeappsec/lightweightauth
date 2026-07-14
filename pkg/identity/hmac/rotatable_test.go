// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package hmac

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

var (
	testSecretActive  = []byte("active-secret-32-bytes-long!!!!")
	testSecretRetired = []byte("retired-secret-32-bytes-long!!!")
)

// TestHMAC_SecretsRotation_OnlyActiveAuthenticates wires the hmac identifier
// to the shared `secrets:` rotation config format and verifies only the
// still-valid (active) key authenticates. This is a regression test for
// buildRotatableIdentifier populating a flat, state-unaware map: previously
// a key past its notAfter+grace period kept verifying signatures forever
// because identifier.Identify read straight from that map, never consulting
// the KeySet's lifecycle state.
func TestHMAC_SecretsRotation_OnlyActiveAuthenticates(t *testing.T) {
	t.Parallel()
	now := time.Now()
	id, err := factory("hmac", map[string]any{
		"secrets": []any{
			map[string]any{
				"kid":      "v1-retired",
				"secret":   base64.StdEncoding.EncodeToString(testSecretRetired),
				"notAfter": now.Add(-time.Hour).Format(time.RFC3339),
			},
			map[string]any{
				"kid":    "v2-active",
				"secret": base64.StdEncoding.EncodeToString(testSecretActive),
			},
		},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	reqDate := time.Now().UTC().Format(time.RFC3339)
	mkReq := func() *module.Request {
		return &module.Request{
			Method: "POST",
			Host:   "api.example.com",
			Path:   "/things",
			Headers: map[string][]string{
				"Date": {reqDate},
				"Host": {"api.example.com"},
			},
		}
	}

	activeReq := mkReq()
	activeReq.Headers["Authorization"] = []string{
		signReq(testSecretActive, "v2-active", activeReq, []string{"date", "host"}),
	}
	got, err := id.Identify(context.Background(), activeReq)
	if err != nil {
		t.Fatalf("active key should authenticate: %v", err)
	}
	if got.Claims["keyId"] != "v2-active" {
		t.Errorf("keyId = %v, want v2-active", got.Claims["keyId"])
	}

	retiredReq := mkReq()
	retiredReq.Headers["Authorization"] = []string{
		signReq(testSecretRetired, "v1-retired", retiredReq, []string{"date", "host"}),
	}
	_, err = id.Identify(context.Background(), retiredReq)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (retired key must not authenticate)", err)
	}
}

// TestHMAC_SecretsRotation_MutuallyExclusiveWithKeys verifies the factory
// rejects configs that mix `secrets:` with `keys:`.
func TestHMAC_SecretsRotation_MutuallyExclusiveWithKeys(t *testing.T) {
	t.Parallel()
	_, err := factory("hmac", map[string]any{
		"keys": map[string]any{
			"abc": map[string]any{"secret": base64.StdEncoding.EncodeToString(testSecretActive)},
		},
		"secrets": []any{
			map[string]any{"kid": "v1", "secret": base64.StdEncoding.EncodeToString(testSecretActive)},
		},
	})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig (keys/secrets are mutually exclusive)", err)
	}
}
