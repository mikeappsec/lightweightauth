package apikey

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yourorg/lightweightauth/pkg/module"
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
