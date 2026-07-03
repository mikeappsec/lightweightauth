// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package provisioner_test

import (
	"strings"
	"testing"

	"github.com/mikeappsec/lightweightauth/internal/controlplane/provisioner"
)

// ── Validation ────────────────────────────────────────────────────────────────

func TestValidate_MissingName(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
	}
	result := req.Validate()
	if result.Valid {
		t.Fatal("expected invalid, got valid")
	}
	if !containsField(result.Errors, "name") {
		t.Errorf("expected 'name' error, got %v", result.Errors)
	}
}

func TestValidate_InvalidK8sName(t *testing.T) {
	for _, bad := range []string{"My_App", "APP", "-start", "end-", strings.Repeat("a", 64)} {
		req := &provisioner.CreateNodeRequest{
			Name:        bad,
			Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
			Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
		}
		result := req.Validate()
		if result.Valid {
			t.Errorf("name %q: expected invalid, got valid", bad)
		}
	}
}

func TestValidate_ValidName(t *testing.T) {
	for _, good := range []string{"payments-auth", "a", "node1", "my-auth-v2"} {
		req := &provisioner.CreateNodeRequest{
			Name:        good,
			Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
			Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
		}
		result := req.Validate()
		if !result.Valid {
			t.Errorf("name %q: expected valid, got errors %v", good, result.Errors)
		}
	}
}

func TestValidate_MissingIdentifiers(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
	}
	result := req.Validate()
	if result.Valid {
		t.Fatal("expected invalid")
	}
	if !containsField(result.Errors, "identifiers") {
		t.Errorf("expected 'identifiers' error, got %v", result.Errors)
	}
}

func TestValidate_MissingAuthorizers(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
	}
	result := req.Validate()
	if result.Valid {
		t.Fatal("expected invalid")
	}
	if !containsField(result.Errors, "authorizers") {
		t.Errorf("expected 'authorizers' error, got %v", result.Errors)
	}
}

func TestValidate_ReplicaOutOfRange(t *testing.T) {
	tooMany := int32(11)
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Replicas:    &tooMany,
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
	}
	result := req.Validate()
	if result.Valid {
		t.Fatal("expected invalid for replicas=11")
	}
	if !containsField(result.Errors, "replicas") {
		t.Errorf("expected 'replicas' error, got %v", result.Errors)
	}
}

func TestValidate_IdentifierMissingType(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt-ident", Type: ""}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
	}
	result := req.Validate()
	if result.Valid {
		t.Fatal("expected invalid when identifier type is empty")
	}
	if !containsField(result.Errors, "identifiers[0].type") {
		t.Errorf("expected identifiers[0].type error, got %v", result.Errors)
	}
}

// ── Auth Config Generation ─────────────────────────────────────────────────────

func TestGenerateAuthConfig_RBACRolesMap(t *testing.T) {
	// The wizard sends roles: { roleName: { permissions: [...] } }.
	// GenerateAuthConfig must collapse this to allow: [roleName, ...].
	req := &provisioner.CreateNodeRequest{
		Name: "payments-auth",
		Identifiers: []provisioner.ModuleEntry{
			{Name: "jwt-verifier", Type: "jwt"},
		},
		Authorizers: []provisioner.ModuleEntry{
			{
				Name: "rbac-main",
				Type: "rbac",
				Config: map[string]any{
					"roles": map[string]any{
						"admin":  map[string]any{"permissions": []any{"read", "write"}},
						"viewer": map[string]any{"permissions": []any{"read"}},
					},
				},
			},
		},
	}

	cfg, err := req.GenerateAuthConfig()
	if err != nil {
		t.Fatalf("GenerateAuthConfig error: %v", err)
	}

	mustContain(t, cfg, "allow:")
	mustContain(t, cfg, "- admin")
	mustContain(t, cfg, "- viewer")
	// The permissions field must NOT be emitted — the rbac module doesn't read it.
	if strings.Contains(cfg, "permissions") {
		t.Errorf("expected no 'permissions' in output; got:\n%s", cfg)
	}
}

func TestGenerateAuthConfig_RBACAllowList(t *testing.T) {
	// When the request already uses the correct allow: [...] form, it should
	// be passed through unchanged.
	req := &provisioner.CreateNodeRequest{
		Name: "my-node",
		Identifiers: []provisioner.ModuleEntry{
			{Name: "jwt", Type: "jwt"},
		},
		Authorizers: []provisioner.ModuleEntry{
			{
				Name: "rbac",
				Type: "rbac",
				Config: map[string]any{
					"allow": []any{"admin", "viewer"},
				},
			},
		},
	}

	cfg, err := req.GenerateAuthConfig()
	if err != nil {
		t.Fatalf("GenerateAuthConfig error: %v", err)
	}
	mustContain(t, cfg, "allow:")
	mustContain(t, cfg, "- admin")
	mustContain(t, cfg, "- viewer")
}

func TestGenerateAuthConfig_APIKeyEntriesRenamedToStatic(t *testing.T) {
	// The wizard sends inline keys under "entries"; the apikey module expects "static".
	req := &provisioner.CreateNodeRequest{
		Name: "my-node",
		Identifiers: []provisioner.ModuleEntry{
			{
				Name: "apikey-auth",
				Type: "apikey",
				Config: map[string]any{
					"headerName": "X-API-Key",
					"entries": map[string]any{
						"test-key-1": map[string]any{"subject": "alice", "roles": []any{"admin"}},
					},
				},
			},
		},
		Authorizers: []provisioner.ModuleEntry{
			{Name: "rbac", Type: "rbac", Config: map[string]any{"allow": []any{"admin"}}},
		},
	}

	cfg, err := req.GenerateAuthConfig()
	if err != nil {
		t.Fatalf("GenerateAuthConfig error: %v", err)
	}

	mustContain(t, cfg, "static:")
	mustContain(t, cfg, "test-key-1:")
	// "entries:" must not appear — it's not a valid apikey field.
	if strings.Contains(cfg, "entries:") {
		t.Errorf("expected 'entries:' to be renamed to 'static:'; got:\n%s", cfg)
	}
}

func TestGenerateAuthConfig_Basic(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name: "payments-auth",
		Identifiers: []provisioner.ModuleEntry{
			{
				Name: "jwt-verifier",
				Type: "jwt",
				Config: map[string]any{
					"issuer":  "https://auth.example.com",
					"jwksUrl": "https://auth.example.com/.well-known/jwks.json",
				},
			},
		},
		Authorizers: []provisioner.ModuleEntry{
			{
				Name: "rbac-main",
				Type: "rbac",
			},
		},
		Mutators: []provisioner.ModuleEntry{
			{
				Name: "fwd-identity",
				Type: "header-add",
				Config: map[string]any{
					"subjectHeader": "X-Auth-Subject",
				},
			},
		},
	}

	cfg, err := req.GenerateAuthConfig()
	if err != nil {
		t.Fatalf("GenerateAuthConfig error: %v", err)
	}

	mustContain(t, cfg, "identifiers:")
	mustContain(t, cfg, "name: jwt-verifier")
	mustContain(t, cfg, "type: jwt")
	mustContain(t, cfg, "authorizers:")
	mustContain(t, cfg, "name: rbac-main")
	mustContain(t, cfg, "type: rbac")
	mustContain(t, cfg, "response:")
	mustContain(t, cfg, "type: header-add")
}

func TestGenerateAuthConfig_NoMutators(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name: "simple-node",
		Identifiers: []provisioner.ModuleEntry{
			{Name: "apikey", Type: "apikey"},
		},
		Authorizers: []provisioner.ModuleEntry{
			{Name: "cel", Type: "cel", Config: map[string]any{"expression": "true"}},
		},
	}

	cfg, err := req.GenerateAuthConfig()
	if err != nil {
		t.Fatalf("GenerateAuthConfig error: %v", err)
	}

	mustContain(t, cfg, "identifiers:")
	mustContain(t, cfg, "authorizers:")
	if strings.Contains(cfg, "response:") {
		t.Error("expected no response: section when no mutators")
	}
}

// ── Helm Values Generation ─────────────────────────────────────────────────────

func TestGenerateHelmValues_ReplicaCount(t *testing.T) {
	replicas := int32(3)
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Replicas:    &replicas,
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
	}

	vals, err := req.GenerateHelmValues()
	if err != nil {
		t.Fatalf("GenerateHelmValues error: %v", err)
	}
	mustContain(t, vals, "replicaCount: 3")
}

func TestGenerateHelmValues_DefaultReplicas(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
	}

	vals, err := req.GenerateHelmValues()
	if err != nil {
		t.Fatalf("GenerateHelmValues error: %v", err)
	}
	mustContain(t, vals, "replicaCount: 1")
}

func TestGenerateHelmValues_ImageTag(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		ImageTag:    "v1.3.0",
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
	}

	vals, err := req.GenerateHelmValues()
	if err != nil {
		t.Fatalf("GenerateHelmValues error: %v", err)
	}
	mustContain(t, vals, `tag: "v1.3.0"`)
}

func TestGenerateHelmValues_CacheBackend(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
		Infrastructure: provisioner.InfrastructureReq{
			CacheBackend: "valkey",
			CacheAddr:    "valkey:6379",
		},
	}

	vals, err := req.GenerateHelmValues()
	if err != nil {
		t.Fatalf("GenerateHelmValues error: %v", err)
	}
	mustContain(t, vals, "backend: valkey")
	mustContain(t, vals, `addr: "valkey:6379"`)
}

func TestGenerateHelmValues_RateLimiting(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
		Infrastructure: provisioner.InfrastructureReq{
			RateLimiting: &provisioner.RateLimitReq{
				Enabled: true,
				RPS:     100,
				Burst:   200,
			},
		},
	}

	vals, err := req.GenerateHelmValues()
	if err != nil {
		t.Fatalf("GenerateHelmValues error: %v", err)
	}
	mustContain(t, vals, "rateLimit:")
	mustContain(t, vals, "rps: 100")
	mustContain(t, vals, "burst: 200")
}

func TestGenerateHelmValues_NetworkPolicyDisabled(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
		Infrastructure: provisioner.InfrastructureReq{
			NetworkPolicy: false,
		},
	}

	vals, err := req.GenerateHelmValues()
	if err != nil {
		t.Fatalf("GenerateHelmValues error: %v", err)
	}
	mustContain(t, vals, "enabled: false")
}

func TestGenerateHelmValues_Gateway(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name:        "my-node",
		Identifiers: []provisioner.ModuleEntry{{Name: "jwt", Type: "jwt"}},
		Authorizers: []provisioner.ModuleEntry{{Name: "rbac", Type: "rbac"}},
		Infrastructure: provisioner.InfrastructureReq{
			NetworkPolicy: true,
			Gateway: &provisioner.GatewayReq{
				Enabled:      true,
				UpstreamHost: "app-svc.default.svc",
				UpstreamPort: 9000,
			},
		},
	}

	vals, err := req.GenerateHelmValues()
	if err != nil {
		t.Fatalf("GenerateHelmValues error: %v", err)
	}
	mustContain(t, vals, "gateway:")
	mustContain(t, vals, "enabled: true")
	mustContain(t, vals, `service: "app-svc.default.svc"`)
	mustContain(t, vals, "port: 9000")
}

func TestGenerateHelmValues_ContainsInlineConfig(t *testing.T) {
	req := &provisioner.CreateNodeRequest{
		Name: "my-node",
		Identifiers: []provisioner.ModuleEntry{
			{Name: "jwt", Type: "jwt", Config: map[string]any{"issuer": "https://issuer.example.com"}},
		},
		Authorizers: []provisioner.ModuleEntry{
			{Name: "rbac", Type: "rbac"},
		},
	}

	vals, err := req.GenerateHelmValues()
	if err != nil {
		t.Fatalf("GenerateHelmValues error: %v", err)
	}
	mustContain(t, vals, "config:")
	mustContain(t, vals, "inline: |")
	mustContain(t, vals, "identifiers:")
}

// ── Presets ─────────────────────────────────────────────────────────────────────

func TestBuiltInPresets_AllHaveRequiredFields(t *testing.T) {
	for _, p := range provisioner.BuiltInPresets() {
		if p.Name == "" {
			t.Error("preset has empty Name")
		}
		if p.DisplayName == "" {
			t.Errorf("preset %q has empty DisplayName", p.Name)
		}
		if len(p.Identifiers) == 0 {
			t.Errorf("preset %q has no identifiers", p.Name)
		}
		if len(p.Authorizers) == 0 {
			t.Errorf("preset %q has no authorizers", p.Name)
		}
	}
}

func TestApplyPreset_ApiGateway(t *testing.T) {
	req := &provisioner.CreateNodeRequest{Name: "test-node"}
	if !provisioner.ApplyPreset(req, "api-gateway") {
		t.Fatal("ApplyPreset returned false for known preset")
	}
	if len(req.Identifiers) == 0 {
		t.Error("expected identifiers after preset apply")
	}
	if len(req.Authorizers) == 0 {
		t.Error("expected authorizers after preset apply")
	}
}

func TestApplyPreset_Unknown(t *testing.T) {
	req := &provisioner.CreateNodeRequest{Name: "test-node"}
	if provisioner.ApplyPreset(req, "nonexistent-preset") {
		t.Fatal("expected false for unknown preset")
	}
}

func TestApplyPreset_AllPresetsGenerateValidConfig(t *testing.T) {
	for _, p := range provisioner.BuiltInPresets() {
		req := &provisioner.CreateNodeRequest{Name: "test-" + p.Name}
		provisioner.ApplyPreset(req, p.Name)

		result := req.Validate()
		if !result.Valid {
			t.Errorf("preset %q: validation failed: %v", p.Name, result.Errors)
			continue
		}

		cfg, err := req.GenerateAuthConfig()
		if err != nil {
			t.Errorf("preset %q: GenerateAuthConfig error: %v", p.Name, err)
			continue
		}
		if cfg == "" {
			t.Errorf("preset %q: empty config generated", p.Name)
		}

		_, err = req.GenerateHelmValues()
		if err != nil {
			t.Errorf("preset %q: GenerateHelmValues error: %v", p.Name, err)
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────────────

func mustContain(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected output to contain %q\ngot:\n%s", substr, s)
	}
}

func containsField(errs []provisioner.ValidationError, field string) bool {
	for _, e := range errs {
		if e.Field == field {
			return true
		}
	}
	return false
}
