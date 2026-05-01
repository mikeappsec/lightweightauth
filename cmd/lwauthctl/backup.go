package main

import (
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

// Backup envelope wraps config state with integrity metadata.
type Backup struct {
	// Version of the backup format.
	FormatVersion int `json:"formatVersion"`
	// CreatedAt is the backup creation timestamp.
	CreatedAt time.Time `json:"createdAt"`
	// Checksum is the SHA-256 hex digest of the Config JSON payload.
	Checksum string `json:"checksum"`
	// Config is the raw AuthConfig as loaded from YAML.
	Config *config.AuthConfig `json:"config"`
}

func backup(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML to back up")
	outPath := fs.String("out", "", "output file (default: stdout)")
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

	// Compute checksum of canonical config JSON.
	cfgJSON, err := canonicalJSON(ac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: marshal config: %v\n", err)
		os.Exit(1)
	}
	hash := sha256.Sum256(cfgJSON)

	bk := Backup{
		FormatVersion: 1,
		CreatedAt:     time.Now().UTC(),
		Checksum:      hex.EncodeToString(hash[:]),
		Config:        ac,
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
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "backup: mkdir: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outPath, out, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "backup: write: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "backup: wrote %s (sha256:%s)\n", *outPath, bk.Checksum)
	}
}

func restore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	inPath := fs.String("from", "", "backup file to restore from (default: stdin)")
	outPath := fs.String("out", "", "output YAML/JSON config path (required)")
	verify := fs.Bool("verify-only", false, "only verify integrity, don't write")
	_ = fs.Parse(args)

	if *outPath == "" && !*verify {
		fmt.Fprintln(os.Stderr, "restore: --out required (or use --verify-only)")
		os.Exit(2)
	}

	var data []byte
	var err error
	if *inPath == "" {
		data, err = io.ReadAll(os.Stdin)
	} else {
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
	hash := sha256.Sum256(cfgJSON)
	actual := hex.EncodeToString(hash[:])
	if actual != bk.Checksum {
		fmt.Fprintf(os.Stderr, "restore: INTEGRITY FAILURE: expected sha256:%s got sha256:%s\n", bk.Checksum, actual)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "restore: integrity OK (sha256:%s, created %s)\n", bk.Checksum, bk.CreatedAt.Format(time.RFC3339))

	if *verify {
		return
	}

	// Validate the config still compiles.
	if _, err := config.Compile(bk.Config); err != nil {
		fmt.Fprintf(os.Stderr, "restore: WARNING config no longer compiles: %v\n", err)
		fmt.Fprintln(os.Stderr, "restore: writing anyway (operator may need to fix before applying)")
	}

	if err := validateOutPath(*outPath); err != nil {
		fmt.Fprintf(os.Stderr, "restore: %v\n", err)
		os.Exit(1)
	}

	out, _ := json.MarshalIndent(bk.Config, "", "  ")
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "restore: mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, out, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "restore: write: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "restore: wrote %s\n", *outPath)
}
