// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package apikey

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
	"golang.org/x/crypto/argon2"
)

func TestApikey_HashedEntries(t *testing.T) {
	t.Parallel()
	hash, err := HashKey("super-secret-key")
	if err != nil {
		t.Fatalf("HashKey: %v", err)
	}
	id, err := factory("apikey", map[string]any{
		"header": "X-API-Key",
		"hashed": map[string]any{
			"entries": map[string]any{
				"key1": map[string]any{
					"hash":    hash,
					"subject": "alice",
					"roles":   []any{"admin"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// Correct key → identity.
	got, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-API-Key": {"super-secret-key"}},
	})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "alice" {
		t.Errorf("subject = %q", got.Subject)
	}
	if got.Claims["keyId"] != "key1" {
		t.Errorf("keyId claim = %v", got.Claims["keyId"])
	}

	// Wrong key → ErrInvalidCredential.
	_, err = id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-API-Key": {"nope"}},
	})
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// TestApikey_HashedEntry_HonorsEmbeddedParams is a regression test: Lookup
// previously always recomputed argon2id with this package's own
// argonTime/argonMemory/argonThreads constants, ignoring the m=/t=/p=
// fields actually embedded in the stored hash string — so a hash generated
// by a standard argon2 tool with different (but still safe) parameters
// never matched.
func TestApikey_HashedEntry_HonorsEmbeddedParams(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	const tParam, mParam, pParam = argonTime + 1, argonMemory * 2, argonThreads
	digest := argon2.IDKey([]byte("custom-key"), salt, tParam, mParam, pParam, 24)
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		mParam, tParam, pParam,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)

	id, err := factory("apikey", map[string]any{
		"header": "X-API-Key",
		"hashed": map[string]any{
			"entries": map[string]any{
				"key1": map[string]any{
					"hash":    encoded,
					"subject": "dave",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	got, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-API-Key": {"custom-key"}},
	})
	if err != nil {
		t.Fatalf("Identify: %v (embedded params should be honored, not overridden)", err)
	}
	if got.Subject != "dave" {
		t.Errorf("subject = %q", got.Subject)
	}
}

// TestApikey_HashedEntry_RejectsParamsBelowFloor verifies a hash advertising
// cost parameters below this package's own minimum is rejected at load time
// rather than silently accepted — a tampered or corrupted hash file must
// not be able to downgrade verification cost.
func TestApikey_HashedEntry_RejectsParamsBelowFloor(t *testing.T) {
	t.Parallel()
	salt := []byte("0123456789abcdef")
	const tParam, mParam, pParam = 1, 1024, 1
	digest := argon2.IDKey([]byte("weak-key"), salt, tParam, mParam, pParam, 24)
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		mParam, tParam, pParam,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)

	_, err := factory("apikey", map[string]any{
		"header": "X-API-Key",
		"hashed": map[string]any{
			"entries": map[string]any{
				"key1": map[string]any{
					"hash":    encoded,
					"subject": "eve",
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected factory to reject a hash with cost params below the security floor")
	}
}

func TestApikey_HashedFileBackend(t *testing.T) {
	t.Parallel()
	hash, _ := HashKey("k1")
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.txt")
	contents := "# header\nteam-a " + hash + " bob viewer,editor\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	id, err := factory("apikey", map[string]any{
		"header": "X-API-Key",
		"hashed": map[string]any{"file": path},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	got, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-API-Key": {"k1"}},
	})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "bob" {
		t.Errorf("subject = %q", got.Subject)
	}
}

func TestApikey_HashedDirBackend(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	hash, _ := HashKey("dirkey")
	// K8s-style: filename = id, contents = hash\nsubject\nroles
	if err := os.WriteFile(filepath.Join(dir, "carol-key"),
		[]byte(hash+"\ncarol\nadmin"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Add a ..data symlink-ish file to verify it's skipped.
	if err := os.WriteFile(filepath.Join(dir, "..data-junk"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write data: %v", err)
	}

	id, err := factory("apikey", map[string]any{
		"header": "X-API-Key",
		"hashed": map[string]any{"dir": dir},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	got, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-API-Key": {"dirkey"}},
	})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "carol" {
		t.Errorf("subject = %q", got.Subject)
	}
	if got.Claims["keyId"] != "carol-key" {
		t.Errorf("keyId = %v, want carol-key", got.Claims["keyId"])
	}
}
