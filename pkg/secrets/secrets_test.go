// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/secrets"
)

// memBackend is a test backend that returns values from an in-memory map.
type memBackend struct {
	data   map[string]map[string]string // path -> field -> value
	calls  atomic.Int64
	closed atomic.Bool
}

func (m *memBackend) Resolve(_ context.Context, path, field string) ([]byte, error) {
	m.calls.Add(1)
	fields, ok := m.data[path]
	if !ok {
		return nil, fmt.Errorf("not found: %s", path)
	}
	if field == "" {
		// Return all fields concatenated (simplified).
		var result string
		for _, v := range fields {
			result += v
		}
		return []byte(result), nil
	}
	val, ok := fields[field]
	if !ok {
		return nil, fmt.Errorf("field %q not found in %s", field, path)
	}
	return []byte(val), nil
}

func (m *memBackend) Close() error {
	m.closed.Store(true)
	return nil
}

func newMemBackend(data map[string]map[string]string) *memBackend {
	return &memBackend{data: data}
}

func TestParseRef(t *testing.T) {
	tests := []struct {
		input   string
		want    secrets.Ref
		wantErr bool
	}{
		{
			input: "vault://kv/data/lwauth/jwt-key#current",
			want:  secrets.Ref{Scheme: "vault", Path: "kv/data/lwauth/jwt-key", Field: "current"},
		},
		{
			input: "aws-sm://us-east-1/myapp/db-password#password",
			want:  secrets.Ref{Scheme: "aws-sm", Path: "us-east-1/myapp/db-password", Field: "password"},
		},
		{
			input: "vault://secret/data/app/db",
			want:  secrets.Ref{Scheme: "vault", Path: "secret/data/app/db", Field: ""},
		},
		{
			input:   "",
			wantErr: true,
		},
		{
			input:   "no-scheme-here",
			wantErr: true,
		},
		{
			input:   "vault://",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := secrets.ParseRef(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestIsSecretRef(t *testing.T) {
	// Register a test backend so IsSecretRef recognizes the scheme.
	secrets.RegisterBackend("vault-test", func(opts map[string]any) (secrets.Backend, error) {
		return newMemBackend(nil), nil
	})

	if !secrets.IsSecretRef("vault-test://kv/data/test#key") {
		t.Error("expected true for vault-test:// ref")
	}
	if secrets.IsSecretRef("https://example.com/jwks.json") {
		t.Error("expected false for https:// URL (not a secret backend)")
	}
	if secrets.IsSecretRef("plain-text-value") {
		t.Error("expected false for plain text")
	}
	if secrets.IsSecretRef("") {
		t.Error("expected false for empty string")
	}
}

func TestResolver_Resolve(t *testing.T) {
	backend := newMemBackend(map[string]map[string]string{
		"kv/data/app/secret": {"password": "hunter2", "username": "admin"},
	})

	secrets.RegisterBackend("mem", func(opts map[string]any) (secrets.Backend, error) {
		return backend, nil
	})

	resolver := secrets.New(secrets.Options{
		DefaultTTL:     1 * time.Minute,
		BackendConfigs: map[string]map[string]any{"mem": {}},
	})
	defer resolver.Close()

	ctx := context.Background()

	// Resolve with field.
	val, err := resolver.ResolveString(ctx, "mem://kv/data/app/secret#password")
	if err != nil {
		t.Fatalf("resolve with field: %v", err)
	}
	if val != "hunter2" {
		t.Fatalf("got %q, want %q", val, "hunter2")
	}

	// Second call should hit cache (call count stays at 1).
	_, err = resolver.ResolveString(ctx, "mem://kv/data/app/secret#password")
	if err != nil {
		t.Fatalf("cached resolve: %v", err)
	}
	if backend.calls.Load() != 1 {
		t.Fatalf("expected 1 backend call (cached), got %d", backend.calls.Load())
	}
}

func TestResolver_CacheTTLExpiry(t *testing.T) {
	backend := newMemBackend(map[string]map[string]string{
		"kv/data/key": {"val": "v1"},
	})

	secrets.RegisterBackend("mem-ttl", func(opts map[string]any) (secrets.Backend, error) {
		return backend, nil
	})

	resolver := secrets.New(secrets.Options{
		DefaultTTL:     1 * time.Millisecond, // very short TTL
		BackendConfigs: map[string]map[string]any{"mem-ttl": {}},
	})
	defer resolver.Close()

	ctx := context.Background()

	_, _ = resolver.ResolveString(ctx, "mem-ttl://kv/data/key#val")
	time.Sleep(5 * time.Millisecond)

	// After TTL, backend should be called again.
	_, _ = resolver.ResolveString(ctx, "mem-ttl://kv/data/key#val")
	if backend.calls.Load() != 2 {
		t.Fatalf("expected 2 backend calls after TTL expiry, got %d", backend.calls.Load())
	}
}

func TestResolver_UnknownScheme(t *testing.T) {
	resolver := secrets.New(secrets.Options{})
	defer resolver.Close()

	_, err := resolver.Resolve(context.Background(), "unknown://path/to/secret")
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestResolver_Close(t *testing.T) {
	backend := newMemBackend(map[string]map[string]string{
		"kv/data/x": {"k": "v"},
	})

	secrets.RegisterBackend("mem-close", func(opts map[string]any) (secrets.Backend, error) {
		return backend, nil
	})

	resolver := secrets.New(secrets.Options{
		DefaultTTL:     time.Minute,
		BackendConfigs: map[string]map[string]any{"mem-close": {}},
	})

	// Trigger backend init.
	_, _ = resolver.ResolveString(context.Background(), "mem-close://kv/data/x#k")

	if err := resolver.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !backend.closed.Load() {
		t.Error("backend was not closed")
	}
}
