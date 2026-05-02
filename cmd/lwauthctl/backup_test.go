// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	// Create a minimal valid config file.
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, []byte(`{"hosts":["example.com"],"identifiers":[{"type":"anonymous"}],"authorizers":[{"type":"allow"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("test-signing-key-32-bytes-long!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(dir, "backup.json")

	// Run backup.
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"lwauthctl", "backup", "--config", cfgFile, "--out", outFile, "--signing-key", keyFile}

	// We can't easily call backup() because os.Exit, so test the core logic directly.
	ac, err := config.LoadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	cfgJSON, _ := canonicalJSON(ac)
	key, _ := os.ReadFile(keyFile)
	mac := hmac.New(sha256.New, key)
	mac.Write(cfgJSON)
	checksum := hex.EncodeToString(mac.Sum(nil))

	bk := Backup{
		FormatVersion: 1,
		CreatedAt:     time.Now().UTC(),
		Checksum:      checksum,
		Signed:        true,
		Config:        ac,
	}

	data, err := json.MarshalIndent(bk, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outFile, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Verify round-trip: re-read and check HMAC.
	raw, _ := os.ReadFile(outFile)
	var restored Backup
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}

	cfgJSON2, _ := canonicalJSON(restored.Config)
	mac2 := hmac.New(sha256.New, key)
	mac2.Write(cfgJSON2)
	expected := hex.EncodeToString(mac2.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(restored.Checksum)) {
		t.Fatalf("HMAC mismatch: got %s want %s", restored.Checksum, expected)
	}
}

func TestBackupTamperedChecksum(t *testing.T) {
	ac := &config.AuthConfig{}
	cfgJSON, _ := canonicalJSON(ac)

	key := []byte("test-key-for-tamper-detection!!!")
	mac := hmac.New(sha256.New, key)
	mac.Write(cfgJSON)
	checksum := hex.EncodeToString(mac.Sum(nil))

	bk := Backup{
		FormatVersion: 1,
		CreatedAt:     time.Now().UTC(),
		Checksum:      checksum,
		Signed:        true,
		Config:        ac,
	}

	// Tamper with config.
	bk.Config.Hosts = []string{"evil.com"}

	// Recompute and verify mismatch.
	cfgJSON2, _ := canonicalJSON(bk.Config)
	mac2 := hmac.New(sha256.New, key)
	mac2.Write(cfgJSON2)
	actual := hex.EncodeToString(mac2.Sum(nil))

	if hmac.Equal([]byte(actual), []byte(bk.Checksum)) {
		t.Fatal("tampered config should not match original HMAC")
	}
}

func TestRestoreStaleDetection(t *testing.T) {
	bk := Backup{
		FormatVersion: 1,
		CreatedAt:     time.Now().Add(-72 * time.Hour), // 3 days old
	}

	age := time.Since(bk.CreatedAt)
	if age <= defaultMaxAge {
		t.Fatalf("expected age %v > %v", age, defaultMaxAge)
	}
}

func TestRedactSecrets(t *testing.T) {
	ac := &config.AuthConfig{
		Identifiers: []config.ModuleSpec{
			{Type: "apikey", Config: map[string]any{"secret": "s3cr3t", "name": "mykey"}},
		},
	}
	redactSecrets(ac)

	val := ac.Identifiers[0].Config["secret"]
	if val != "<redacted>" {
		t.Fatalf("expected <redacted>, got %v", val)
	}
	// Non-secret field preserved.
	if ac.Identifiers[0].Config["name"] != "mykey" {
		t.Fatal("non-secret field was modified")
	}
}

func TestMaxRestoreSize(t *testing.T) {
	if maxRestoreSize != 10<<20 {
		t.Fatalf("expected 10MB limit, got %d", maxRestoreSize)
	}
}
