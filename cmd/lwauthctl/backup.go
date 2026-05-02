// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

// maxRestoreSize is the maximum bytes accepted from stdin (10 MB).
const maxRestoreSize = 10 << 20

// defaultMaxAge is the default staleness threshold for restore warnings.
const defaultMaxAge = 24 * time.Hour

// Backup envelope wraps config state with integrity metadata.
type Backup struct {
	// Version of the backup format.
	FormatVersion int `json:"formatVersion"`
	// CreatedAt is the backup creation timestamp.
	CreatedAt time.Time `json:"createdAt"`
	// Checksum is HMAC-SHA256(signingKey, canonicalJSON(config)) hex.
	// If no signing key is provided, falls back to plain SHA-256 (legacy).
	Checksum string `json:"checksum"`
	// Signed indicates the checksum is HMAC-authenticated.
	Signed bool `json:"signed"`
	// RedactedSecrets indicates secret values were stripped.
	RedactedSecrets bool `json:"redactedSecrets,omitempty"`
	// Config is the raw AuthConfig as loaded from YAML.
	Config *config.AuthConfig `json:"config"`
}

func backup(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML to back up")
	outPath := fs.String("out", "", "output file (default: stdout)")
	keyPath := fs.String("signing-key", "", "path to HMAC signing key file (recommended)")
	redact := fs.Bool("redact-secrets", false, "strip secret values from backup")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "backup: --config required")
		os.Exit(2)
	}

	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: load: %v\n", err)
		os.Exit(1)
	}

	// Validate config compiles before backing up.
	if _, err := config.Compile(ac); err != nil {
		fmt.Fprintf(os.Stderr, "backup: config does not compile: %v\n", err)
		os.Exit(1)
	}

	// Optionally redact secrets before serialization.
	if *redact {
		redactSecrets(ac)
	}

	// Compute checksum of canonical config JSON.
	cfgJSON, err := canonicalJSON(ac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: marshal config: %v\n", err)
		os.Exit(1)
	}

	var checksum string
	var signed bool
	if *keyPath != "" {
		// HMAC-SHA256 with operator-provided signing key.
		key, err := os.ReadFile(*keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "backup: read signing key: %v\n", err)
			os.Exit(1)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(cfgJSON)
		checksum = hex.EncodeToString(mac.Sum(nil))
		signed = true
	} else {
		fmt.Fprintln(os.Stderr, "backup: WARNING --signing-key not provided; backup is NOT authenticated")
		hash := sha256.Sum256(cfgJSON)
		checksum = hex.EncodeToString(hash[:])
	}

	bk := Backup{
		FormatVersion:   1,
		CreatedAt:       time.Now().UTC(),
		Checksum:        checksum,
		Signed:          signed,
		RedactedSecrets: *redact,
		Config:          ac,
	}

	out, err := json.MarshalIndent(bk, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: marshal: %v\n", err)
		os.Exit(1)
	}

	if *outPath == "" {
		os.Stdout.Write(out)
		fmt.Fprintln(os.Stdout)
	} else {
		if err := validateOutPath(*outPath); err != nil {
			fmt.Fprintf(os.Stderr, "backup: %v\n", err)
			os.Exit(1)
		}
		// Security: Use 0o700 for directories (restrict listing).
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "backup: mkdir: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outPath, out, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "backup: write: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "backup: wrote %s (hmac:%v, sha256-prefix:%s)\n", *outPath, signed, checksum[:16])
	}
}

func restore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	inPath := fs.String("from", "", "backup file to restore from (default: stdin)")
	outPath := fs.String("out", "", "output YAML/JSON config path (required)")
	verify := fs.Bool("verify-only", false, "only verify integrity, don't write")
	keyPath := fs.String("signing-key", "", "path to HMAC signing key (required for signed backups)")
	force := fs.Bool("force", false, "write config even if it doesn't compile")
	allowStale := fs.Bool("allow-stale", false, "allow restoring backups older than 24h")
	maxAge := fs.Duration("max-age", defaultMaxAge, "maximum acceptable backup age")
	_ = fs.Parse(args)

	if *outPath == "" && !*verify {
		fmt.Fprintln(os.Stderr, "restore: --out required (or use --verify-only)")
		os.Exit(2)
	}

	var data []byte
	var err error
	if *inPath == "" {
		// Cap stdin read at maxRestoreSize to prevent OOM.
		data, err = io.ReadAll(io.LimitReader(os.Stdin, maxRestoreSize+1))
		if err == nil && len(data) > maxRestoreSize {
			fmt.Fprintf(os.Stderr, "restore: input exceeds %d bytes limit\n", maxRestoreSize)
			os.Exit(1)
		}
	} else {
		info, statErr := os.Stat(*inPath)
		if statErr != nil {
			fmt.Fprintf(os.Stderr, "restore: stat: %v\n", statErr)
			os.Exit(1)
		}
		if info.Size() > maxRestoreSize {
			fmt.Fprintf(os.Stderr, "restore: file exceeds %d bytes limit\n", maxRestoreSize)
			os.Exit(1)
		}
		data, err = os.ReadFile(*inPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: read: %v\n", err)
		os.Exit(1)
	}

	var bk Backup
	if err := json.Unmarshal(data, &bk); err != nil {
		fmt.Fprintf(os.Stderr, "restore: parse backup: %v\n", err)
		os.Exit(1)
	}

	if bk.FormatVersion != 1 {
		fmt.Fprintf(os.Stderr, "restore: unsupported format version %d\n", bk.FormatVersion)
		os.Exit(1)
	}

	// Verify checksum integrity.
	cfgJSON, err := canonicalJSON(bk.Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: marshal config for checksum: %v\n", err)
		os.Exit(1)
	}

	// Verify HMAC if backup is signed.
	if bk.Signed {
		if *keyPath == "" {
			fmt.Fprintln(os.Stderr, "restore: backup is HMAC-signed but --signing-key not provided")
			os.Exit(1)
		}
		key, err := os.ReadFile(*keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "restore: read signing key: %v\n", err)
			os.Exit(1)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(cfgJSON)
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(bk.Checksum)) {
			fmt.Fprintln(os.Stderr, "restore: HMAC VERIFICATION FAILED — backup may be forged or tampered")
			os.Exit(1)
		}
	} else {
		// Legacy unsigned backup — plain SHA-256 check.
		fmt.Fprintln(os.Stderr, "restore: WARNING backup is NOT signed (legacy format) — authenticity cannot be verified")
		hash := sha256.Sum256(cfgJSON)
		actual := hex.EncodeToString(hash[:])
		if actual != bk.Checksum {
			fmt.Fprintf(os.Stderr, "restore: INTEGRITY FAILURE: expected sha256:%s got sha256:%s\n", bk.Checksum, actual)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "restore: integrity OK (signed:%v, created %s)\n", bk.Signed, bk.CreatedAt.Format(time.RFC3339))

	// Warn on stale backups.
	age := time.Since(bk.CreatedAt)
	if age > *maxAge {
		fmt.Fprintf(os.Stderr, "restore: WARNING backup is %s old (created %s)\n", age.Round(time.Minute), bk.CreatedAt.Format(time.RFC3339))
		if !*allowStale {
			fmt.Fprintln(os.Stderr, "restore: refusing stale backup — use --allow-stale to override")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "restore: proceeding with stale backup (--allow-stale)")
	}

	if bk.RedactedSecrets {
		fmt.Fprintln(os.Stderr, "restore: NOTE backup has redacted secrets — you must re-supply secret material separately")
	}

	if *verify {
		return
	}

	// Abort on compile failure unless --force is set.
	if _, err := config.Compile(bk.Config); err != nil {
		fmt.Fprintf(os.Stderr, "restore: config does not compile: %v\n", err)
		if !*force {
			fmt.Fprintln(os.Stderr, "restore: aborting — use --force to write anyway")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "restore: --force set, writing non-compiling config")
	}

	if err := validateOutPath(*outPath); err != nil {
		fmt.Fprintf(os.Stderr, "restore: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(bk.Config, "", "  ")
	// Security: Use 0o700 for directories (restrict listing).
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "restore: mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, out, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "restore: write: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "restore: wrote %s\n", *outPath)
}

// redactSecrets strips sensitive values from the config.
// Only metadata (key IDs, expiry) is preserved.
func redactSecrets(ac *config.AuthConfig) {
	for i := range ac.Identifiers {
		if ac.Identifiers[i].Config != nil {
			redactMapSecrets(ac.Identifiers[i].Config)
		}
	}
	for i := range ac.Authorizers {
		if ac.Authorizers[i].Config != nil {
			redactMapSecrets(ac.Authorizers[i].Config)
		}
	}
}

// redactMapSecrets replaces known secret field values with "<redacted>".
var secretFieldNames = map[string]bool{
	"secret": true, "secrets": true, "client_secret": true,
	"api_key": true, "apiKey": true, "hmac_secret": true,
	"password": true, "token": true, "private_key": true,
}

func redactMapSecrets(m map[string]any) {
	for k, v := range m {
		if secretFieldNames[k] {
			m[k] = "<redacted>"
			continue
		}
		switch val := v.(type) {
		case map[string]any:
			redactMapSecrets(val)
		case []any:
			for _, item := range val {
				if sub, ok := item.(map[string]any); ok {
					redactMapSecrets(sub)
				}
			}
		}
	}
}
