package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBinary compiles cmd/lwauthctl into a tempdir and returns the path.
// Re-built once per test binary via t.TempDir + go build.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "lwauthctl")
	if os.PathSeparator == '\\' {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}
	return bin
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

const validConfigYAML = `
hosts: ["api.example.com"]
identifiers:
  - name: static-key
    type: apikey
    config:
      headerName: X-Api-Key
      static:
        sekret:
          subject: alice
          roles: [admin]
authorizers:
  - name: allow-all
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [admin]
`

const validConfigYAMLChanged = `
hosts: ["api.example.com", "api2.example.com"]
identifiers:
  - name: static-key
    type: apikey
    config:
      headerName: Authorization
      static:
        sekret:
          subject: alice
          roles: [admin]
authorizers:
  - name: allow-all
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [admin]
  - name: extra
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [other]
rateLimit:
  perTenant:
    rps: 100
    burst: 200
`

func TestValidate_OK(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	cfg := writeFile(t, dir, "ac.yaml", validConfigYAML)

	// Use Output (stdout only) -- the apikey module emits a slog
	// warning to stderr when the plaintext `static` backend loads,
	// which is a feature of the dev/prod safety net we don't want
	// to mute here.
	out, err := exec.Command(bin, "validate", "--config", cfg).Output()
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	if !bytes.HasPrefix(out, []byte("OK")) {
		t.Fatalf("expected OK summary, got: %s", out)
	}
}

func TestValidate_BadConfigExits1(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	cfg := writeFile(t, dir, "ac.yaml", "identifiers: []\nauthorizers: []\n")

	cmd := exec.Command(bin, "validate", "--config", cfg)
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() == 0 {
		t.Fatalf("expected non-zero exit on empty config; out: %s", out)
	}
}

func TestDiff_DetectsChanges(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	a := writeFile(t, dir, "a.yaml", validConfigYAML)
	b := writeFile(t, dir, "b.yaml", validConfigYAMLChanged)

	out, err := exec.Command(bin, "diff", "--from", a, "--to", b).CombinedOutput()
	if err != nil {
		t.Fatalf("diff: %v\n%s", err, out)
	}
	s := string(out)
	for _, want := range []string{
		"hosts:",
		"+ authorizers/extra",
		"identifiers/static-key config:",
		"rateLimit:",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("diff output missing %q\n--full output:\n%s", want, s)
		}
	}
}

func TestDiff_NoChanges(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	a := writeFile(t, dir, "a.yaml", validConfigYAML)
	b := writeFile(t, dir, "b.yaml", validConfigYAML)

	out, err := exec.Command(bin, "diff", "--from", a, "--to", b).CombinedOutput()
	if err != nil {
		t.Fatalf("diff: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "(no changes)") {
		t.Fatalf("expected (no changes), got: %s", out)
	}
}

func TestExplain_AllowPath(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	cfg := writeFile(t, dir, "ac.yaml", validConfigYAML)
	reqJSON, _ := json.Marshal(map[string]any{
		"method": "GET",
		"host":   "api.example.com",
		"path":   "/v1/things",
		"headers": map[string][]string{
			"X-Api-Key": {"sekret"},
		},
	})
	req := writeFile(t, dir, "req.json", string(reqJSON))

	out, err := exec.Command(bin, "explain", "--config", cfg, "--request", req).CombinedOutput()
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	s := string(out)
	for _, want := range []string{
		"identify:",
		"✓ static-key",
		"authorize: ✓ allow-all",
		"decision: allow",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("explain output missing %q\n--full output:\n%s", want, s)
		}
	}
}

func TestExplain_NoIdentifierMatch(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	cfg := writeFile(t, dir, "ac.yaml", validConfigYAML)
	reqJSON, _ := json.Marshal(map[string]any{
		"method": "GET",
		"path":   "/x",
		// No X-Api-Key header
		"headers": map[string][]string{},
	})
	req := writeFile(t, dir, "req.json", string(reqJSON))

	out, err := exec.Command(bin, "explain", "--config", cfg, "--request", req).CombinedOutput()
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "no_match") || !strings.Contains(s, "decision: deny status=401") {
		t.Fatalf("expected deny 401 with no_match, got:\n%s", s)
	}
}
