// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package apikey

import (
	"context"
	"errors"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func build(t *testing.T) module.Identifier {
	t.Helper()
	id, err := factory("apikey-test", map[string]any{
		"headerName": "X-Api-Key",
		"static":     map[string]any{"k1": "alice", "k2": "bob"},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return id
}

func TestAPIKey_Match(t *testing.T) {
	id := build(t)
	r := &module.Request{Headers: map[string][]string{"X-Api-Key": {"k1"}}}
	got, err := id.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", got.Subject)
	}
}

func TestAPIKey_NoHeader(t *testing.T) {
	id := build(t)
	_, err := id.Identify(context.Background(), &module.Request{Headers: map[string][]string{}})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestAPIKey_UnknownKey(t *testing.T) {
	id := build(t)
	r := &module.Request{Headers: map[string][]string{"X-Api-Key": {"nope"}}}
	_, err := id.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestApiKey_RejectsUnknownConfigKey(t *testing.T) {
	t.Parallel()
	_, err := factory("ak", map[string]any{
		"static":     map[string]any{"key1": "svc"},
		"lookupMode": "prefix",
	})
	if err == nil {
		t.Fatal("expected error for unknown config key, got nil")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("error = %v, want ErrConfig wrapper", err)
	}
}

// TestApiKey_RejectsEmptySubjectStatic verifies APIKEY-VULN-01: a static
// entry with empty subject is rejected at config time. Empty subjects
// defeat per-user RBAC, audit attribution, and revocation.
func TestApiKey_RejectsEmptySubjectStatic(t *testing.T) {
	t.Parallel()

	// String-form: the value IS the subject.
	_, err := factory("ak", map[string]any{
		"static": map[string]any{"key1": ""},
	})
	if err == nil {
		t.Fatal("expected error for empty subject (string form), got nil")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("error = %v, want ErrConfig wrapper", err)
	}

	// Map-form: explicit subject field missing.
	_, err = factory("ak", map[string]any{
		"static": map[string]any{"key1": map[string]any{"roles": []any{"admin"}}},
	})
	if err == nil {
		t.Fatal("expected error for empty subject (map form), got nil")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("error = %v, want ErrConfig wrapper", err)
	}
}

// TestApiKey_RejectsEmptySubjectHashedEntries verifies APIKEY-VULN-01
// for the hashed.entries backend.
func TestApiKey_RejectsEmptySubjectHashedEntries(t *testing.T) {
	t.Parallel()
	hash, _ := HashKey("some-key")
	_, err := factory("ak", map[string]any{
		"hashed": map[string]any{
			"entries": map[string]any{
				"k1": map[string]any{
					"hash":  hash,
					"roles": []any{"admin"},
					// no "subject" → empty
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for empty subject in hashed.entries, got nil")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("error = %v, want ErrConfig wrapper", err)
	}
}
