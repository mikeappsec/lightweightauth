// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/secrets"
	"github.com/mikeappsec/lightweightauth/pkg/secrets/vault"
)

func TestVault_Resolve(t *testing.T) {
	// Mock Vault KV v2 API.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/v1/secret/data/myapp/creds" {
			resp := map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"username": "admin",
						"password": "s3cr3t",
					},
					"metadata": map[string]any{
						"version": 3,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	b, err := vault.Factory(map[string]any{
		"addr":  srv.URL,
		"token": "test-token",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	defer b.Close()

	ctx := context.Background()

	// Resolve specific field.
	val, err := b.Resolve(ctx, "secret/data/myapp/creds", "password")
	if err != nil {
		t.Fatalf("resolve field: %v", err)
	}
	if string(val) != "s3cr3t" {
		t.Fatalf("got %q, want %q", string(val), "s3cr3t")
	}

	// Resolve without field (get entire data map).
	val, err = b.Resolve(ctx, "secret/data/myapp/creds", "")
	if err != nil {
		t.Fatalf("resolve all: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(val, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["username"] != "admin" || data["password"] != "s3cr3t" {
		t.Fatalf("unexpected data: %v", data)
	}
}

func TestVault_ResolveMissingField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"data": map[string]any{"only": "this"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	b, err := vault.Factory(map[string]any{
		"addr":  srv.URL,
		"token": "t",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	defer b.Close()

	_, err = b.Resolve(context.Background(), "secret/data/x", "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestVault_RegistrationViaScheme(t *testing.T) {
	// Verify the vault package registers itself on import.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"data": map[string]any{"key": "value123"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	resolver := secrets.New(secrets.Options{
		BackendConfigs: map[string]map[string]any{
			"vault": {"addr": srv.URL, "token": "tk"},
		},
	})
	defer resolver.Close()

	val, err := resolver.ResolveString(context.Background(), "vault://secret/data/test#key")
	if err != nil {
		t.Fatalf("resolve via scheme: %v", err)
	}
	if val != "value123" {
		t.Fatalf("got %q, want %q", val, "value123")
	}
}

func TestVault_FactoryMissingAddr(t *testing.T) {
	// Unset VAULT_ADDR for this test.
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")

	_, err := vault.Factory(nil)
	if err == nil {
		t.Fatal("expected error when addr is missing")
	}
}
