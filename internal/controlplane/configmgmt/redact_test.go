// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package configmgmt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// authConfig builds a minimal AuthConfig-shaped JSON document with a
// single module entry in the given section ("identifiers", "authorizers",
// or "response").
func authConfig(t *testing.T, section, name, typ string, config map[string]any) string {
	t.Helper()
	doc := map[string]any{
		section: []any{
			map[string]any{"name": name, "type": typ, "config": config},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return string(b)
}

// moduleConfig extracts the redacted document's single module's config
// map for inspection.
func moduleConfig(t *testing.T, content, section string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatalf("unmarshal result: %v\ncontent: %s", err, content)
	}
	entries, ok := doc[section].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("expected exactly one %s entry, got: %#v", section, doc[section])
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatalf("entry is not an object: %#v", entries[0])
	}
	cfg, ok := entry["config"].(map[string]any)
	if !ok {
		t.Fatalf("entry.config is not an object: %#v", entry["config"])
	}
	return cfg
}

func getPath(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, seg := range path {
		cm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %q is not an object at %q (got %#v)", path, path, seg, cur)
		}
		cur, ok = cm[seg]
		if !ok {
			t.Fatalf("path %v: missing key %q", path, seg)
		}
	}
	return cur
}

// ── Per-module-type redaction correctness ──────────────────────────────

func TestRedactConfigJSON_ValueSecrets(t *testing.T) {
	cases := []struct {
		name    string
		section string
		typ     string
		config  map[string]any
		path    []string
	}{
		{"hmac.keys.*.secret", "identifiers", "hmac", map[string]any{
			"keys": map[string]any{"k1": map[string]any{"secret": "shh", "subject": "alice"}},
		}, []string{"keys", "k1", "secret"}},
		{"oauth2.clientSecret", "identifiers", "oauth2", map[string]any{
			"clientSecret": "shh", "clientId": "public-id",
		}, []string{"clientSecret"}},
		{"oauth2.cookie.secret", "identifiers", "oauth2", map[string]any{
			"cookie": map[string]any{"secret": "shh", "name": "sess"},
		}, []string{"cookie", "secret"}},
		{"oauth2-introspection.clientSecret", "identifiers", "oauth2-introspection", map[string]any{
			"clientSecret": "shh",
		}, []string{"clientSecret"}},
		{"scim.bearerToken", "identifiers", "scim", map[string]any{
			"bearerToken": "shh",
		}, []string{"bearerToken"}},
		{"openfga.apiToken", "authorizers", "openfga", map[string]any{
			"apiToken": "shh",
		}, []string{"apiToken"}},
		{"spicedb.token", "authorizers", "spicedb", map[string]any{
			"token": "shh",
		}, []string{"token"}},
		{"jwt-issue.key", "response", "jwt-issue", map[string]any{
			"key": "hex:deadbeef",
		}, []string{"key"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := authConfig(t, tc.section, "m1", tc.typ, tc.config)
			out, err := RedactConfigJSON(content)
			if err != nil {
				t.Fatalf("RedactConfigJSON: %v", err)
			}
			cfg := moduleConfig(t, out, tc.section)
			got := getPath(t, cfg, tc.path...)
			if got != secretValueSentinel {
				t.Errorf("expected sentinel at %v, got %#v", tc.path, got)
			}
		})
	}
}

func TestRedactConfigJSON_SecretsArrayByKid(t *testing.T) {
	config := map[string]any{
		"secrets": []any{
			map[string]any{"kid": "v1", "secret": "old-secret", "notAfter": "2026-01-01T00:00:00Z"},
			map[string]any{"kid": "v2", "secret": "new-secret"},
		},
	}
	content := authConfig(t, "identifiers", "m1", "hmac", config)
	out, err := RedactConfigJSON(content)
	if err != nil {
		t.Fatalf("RedactConfigJSON: %v", err)
	}
	cfg := moduleConfig(t, out, "identifiers")
	secrets := cfg["secrets"].([]any)
	for _, s := range secrets {
		m := s.(map[string]any)
		if m["secret"] != secretValueSentinel {
			t.Errorf("kid %v: expected secret redacted, got %#v", m["kid"], m["secret"])
		}
		// notAfter and kid must survive untouched.
	}
	if secrets[0].(map[string]any)["notAfter"] != "2026-01-01T00:00:00Z" {
		t.Error("non-secret sibling field notAfter was altered")
	}
}

func TestRedactConfigJSON_HashPassesThroughUnredacted(t *testing.T) {
	config := map[string]any{
		"hashed": map[string]any{
			"entries": map[string]any{
				"op1": map[string]any{"hash": "$argon2id$v=19$...", "subject": "alice"},
			},
		},
	}
	content := authConfig(t, "identifiers", "m1", "apikey", config)
	out, err := RedactConfigJSON(content)
	if err != nil {
		t.Fatalf("RedactConfigJSON: %v", err)
	}
	cfg := moduleConfig(t, out, "identifiers")
	got := getPath(t, cfg, "hashed", "entries", "op1", "hash")
	if got != "$argon2id$v=19$..." {
		t.Errorf("expected hash to pass through unredacted (ClassHash is a documented no-op), got %#v", got)
	}
}

func TestRedactConfigJSON_ApikeyStaticCollapsesToBlock(t *testing.T) {
	config := map[string]any{
		"static": map[string]any{
			"sk_live_abc123": map[string]any{"subject": "alice", "roles": []any{"admin"}},
			"sk_live_def456": map[string]any{"subject": "bob"},
		},
	}
	content := authConfig(t, "identifiers", "m1", "apikey", config)
	out, err := RedactConfigJSON(content)
	if err != nil {
		t.Fatalf("RedactConfigJSON: %v", err)
	}
	cfg := moduleConfig(t, out, "identifiers")
	static, ok := cfg["static"].(string)
	if !ok {
		t.Fatalf("expected static to collapse to a single string, got %T: %#v", cfg["static"], cfg["static"])
	}
	if !strings.HasPrefix(static, secretBlockSentinelPrefix) {
		t.Errorf("expected block sentinel prefix, got %q", static)
	}
	if strings.Contains(static, "sk_live_abc123") || strings.Contains(static, "sk_live_def456") {
		t.Errorf("raw API key leaked into block sentinel: %q", static)
	}
	if !strings.Contains(static, "2-entries") {
		t.Errorf("expected entry count in block sentinel, got %q", static)
	}
}

func TestRedactConfigJSON_GrpcPluginLifecycleEnv(t *testing.T) {
	t.Run("collapses when secret-shaped", func(t *testing.T) {
		config := map[string]any{
			"lifecycle": map[string]any{"env": []any{"HOST=example.com", "API_TOKEN=sk_abc123"}},
		}
		content := authConfig(t, "response", "m1", "grpc-plugin", config)
		out, err := RedactConfigJSON(content)
		if err != nil {
			t.Fatalf("RedactConfigJSON: %v", err)
		}
		cfg := moduleConfig(t, out, "response")
		env, ok := getPath(t, cfg, "lifecycle", "env").(string)
		if !ok || !strings.HasPrefix(env, secretBlockSentinelPrefix) {
			t.Errorf("expected env to collapse to a block sentinel, got %#v", cfg["lifecycle"])
		}
	})

	t.Run("passes through when nothing secret-shaped", func(t *testing.T) {
		config := map[string]any{
			"lifecycle": map[string]any{"env": []any{"HOST=example.com", "LOG_LEVEL=debug"}},
		}
		content := authConfig(t, "response", "m1", "grpc-plugin", config)
		out, err := RedactConfigJSON(content)
		if err != nil {
			t.Fatalf("RedactConfigJSON: %v", err)
		}
		cfg := moduleConfig(t, out, "response")
		env := getPath(t, cfg, "lifecycle", "env").([]any)
		if len(env) != 2 || env[0] != "HOST=example.com" {
			t.Errorf("expected env untouched, got %#v", env)
		}
	})
}

func TestRedactConfigJSON_GrpcPluginSigningKeysByID(t *testing.T) {
	config := map[string]any{
		"signing": map[string]any{
			"keys": []any{
				map[string]any{"id": "k1", "hmacSecret": "shh1"},
				map[string]any{"id": "k2", "hmacSecret": "shh2"},
			},
		},
	}
	content := authConfig(t, "response", "m1", "grpc-plugin", config)
	out, err := RedactConfigJSON(content)
	if err != nil {
		t.Fatalf("RedactConfigJSON: %v", err)
	}
	cfg := moduleConfig(t, out, "response")
	keys := getPath(t, cfg, "signing", "keys").([]any)
	for _, k := range keys {
		if k.(map[string]any)["hmacSecret"] != secretValueSentinel {
			t.Errorf("expected hmacSecret redacted, got %#v", k)
		}
	}
}

// ── Regression guard: public reference fields must NOT be redacted ─────

func TestRedactConfigJSON_PublicReferencesUntouched(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		config  map[string]any
	}{
		{"mtls trustedCAs", "mtls", map[string]any{"trustedCAs": "-----BEGIN CERTIFICATE-----\n..."}},
		{"dpop thumbprint", "dpop", map[string]any{"pinnedKeys": []any{map[string]any{"thumbprint": "abc123"}}}},
		{"saml idpCertPEM", "saml", map[string]any{"idpCertPEM": "-----BEGIN CERTIFICATE-----\n..."}},
		{"wasm path", "wasm", map[string]any{"path": "/etc/lwauth/plugins/foo.wasm"}},
		{"rbac allow", "rbac", map[string]any{"rolesFrom": "claims.roles", "allow": []any{"admin"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := authConfig(t, "identifiers", "m1", tc.typ, tc.config)
			out, err := RedactConfigJSON(content)
			if err != nil {
				t.Fatalf("RedactConfigJSON: %v", err)
			}
			cfg := moduleConfig(t, out, "identifiers")
			gotJSON, _ := json.Marshal(cfg)
			wantJSON, _ := json.Marshal(tc.config)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("expected byte-identical config, got %s want %s", gotJSON, wantJSON)
			}
		})
	}
}

// ── Top-level rules ──────────────────────────────────────────────────

func TestRedactConfigJSON_TopLevelRules(t *testing.T) {
	doc := map[string]any{
		"identifiers": []any{},
		"secrets": map[string]any{
			"backends": map[string]any{
				"vault": map[string]any{"token": "shh", "address": "https://vault:8200"},
			},
		},
		"cache": map[string]any{
			"password":      "shh",
			"sharedHmacKey": "shh2",
			"addr":          "redis:6379",
		},
		"revocation": map[string]any{
			"password": "shh3",
		},
		"caches": []any{
			map[string]any{"name": "c1", "password": "shh4", "addr": "redis1:6379"},
		},
	}
	b, _ := json.Marshal(doc)
	out, err := RedactConfigJSON(string(b))
	if err != nil {
		t.Fatalf("RedactConfigJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if v := getPath(t, got, "secrets", "backends", "vault", "token"); v != secretValueSentinel {
		t.Errorf("secrets.backends.vault.token: got %#v", v)
	}
	if v := getPath(t, got, "secrets", "backends", "vault", "address"); v != "https://vault:8200" {
		t.Errorf("secrets.backends.vault.address should be untouched, got %#v", v)
	}
	if v := getPath(t, got, "cache", "password"); v != secretValueSentinel {
		t.Errorf("cache.password: got %#v", v)
	}
	if v := getPath(t, got, "cache", "sharedHmacKey"); v != secretValueSentinel {
		t.Errorf("cache.sharedHmacKey: got %#v", v)
	}
	if v := getPath(t, got, "cache", "addr"); v != "redis:6379" {
		t.Errorf("cache.addr should be untouched, got %#v", v)
	}
	if v := getPath(t, got, "revocation", "password"); v != secretValueSentinel {
		t.Errorf("revocation.password: got %#v", v)
	}
	caches := got["caches"].([]any)
	if caches[0].(map[string]any)["password"] != secretValueSentinel {
		t.Errorf("caches[0].password: got %#v", caches[0])
	}
	if caches[0].(map[string]any)["addr"] != "redis1:6379" {
		t.Errorf("caches[0].addr should be untouched, got %#v", caches[0])
	}
}

// ── Unknown/plugin module type heuristic fallback ───────────────────────

func TestRedactConfigJSON_UnknownTypeHeuristicFallback(t *testing.T) {
	config := map[string]any{
		"signingKey": "shh",
		"endpoint":   "https://example.com",
	}
	content := authConfig(t, "identifiers", "m1", "some-future-plugin-type", config)
	out, err := RedactConfigJSON(content)
	if err != nil {
		t.Fatalf("RedactConfigJSON: %v", err)
	}
	cfg := moduleConfig(t, out, "identifiers")
	if cfg["signingKey"] != secretValueSentinel {
		t.Errorf("expected heuristic fallback to redact signingKey, got %#v", cfg["signingKey"])
	}
	if cfg["endpoint"] != "https://example.com" {
		t.Errorf("expected non-secret-shaped field untouched, got %#v", cfg["endpoint"])
	}
}

// ── Merge-on-write ──────────────────────────────────────────────────────

func TestStore_PushConfig_MergePreservesUnchangedSecret(t *testing.T) {
	s := NewStore()
	ctx := t.Context()

	v1Content := authConfig(t, "identifiers", "a", "hmac", map[string]any{
		"keys": map[string]any{"k1": map[string]any{"secret": "real-secret-v1", "subject": "alice"}},
	})
	v1, err := s.PushConfig(ctx, "local", "inst", v1Content, "op", "initial")
	if err != nil {
		t.Fatalf("push v1: %v", err)
	}

	// Simulate: GET v1 (redacted), edit an unrelated field, leave the
	// secret as the sentinel, push v2.
	redactedV1, err := RedactConfigVersion(v1)
	if err != nil {
		t.Fatalf("redact v1: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(redactedV1.Content), &doc); err != nil {
		t.Fatalf("unmarshal redacted v1: %v", err)
	}
	entries := doc["identifiers"].([]any)
	cfg := entries[0].(map[string]any)["config"].(map[string]any)
	if getPath(t, cfg, "keys", "k1", "secret") != secretValueSentinel {
		t.Fatalf("precondition: expected redacted v1 to show sentinel")
	}
	cfg["keys"].(map[string]any)["k1"].(map[string]any)["subject"] = "alice-renamed"
	v2Bytes, _ := json.Marshal(doc)

	if _, err := s.PushConfig(ctx, "local", "inst", string(v2Bytes), "op", "rename subject"); err != nil {
		t.Fatalf("push v2: %v", err)
	}

	stored, ok := s.Current("local", "inst")
	if !ok {
		t.Fatal("expected a current version")
	}
	storedCfg := moduleConfig(t, stored.Content, "identifiers")
	if got := getPath(t, storedCfg, "keys", "k1", "secret"); got != "real-secret-v1" {
		t.Errorf("real secret was not preserved across merge, got %#v", got)
	}
	if got := getPath(t, storedCfg, "keys", "k1", "subject"); got != "alice-renamed" {
		t.Errorf("unrelated edit was not applied, got %#v", got)
	}
}

func TestStore_PushConfig_MergeSurvivesModuleReordering(t *testing.T) {
	s := NewStore()
	ctx := t.Context()

	v1Content, _ := json.Marshal(map[string]any{
		"identifiers": []any{
			map[string]any{"name": "a", "type": "hmac", "config": map[string]any{
				"keys": map[string]any{"k1": map[string]any{"secret": "real-secret"}},
			}},
		},
	})
	if _, err := s.PushConfig(ctx, "local", "inst", string(v1Content), "op", "initial"); err != nil {
		t.Fatalf("push v1: %v", err)
	}

	// v2: insert a new identifier BEFORE "a" (an entirely ordinary console
	// edit) while leaving "a"'s secret as the sentinel. Positional pairing
	// would misattribute the restore to the wrong module; pairing by name
	// must not.
	v2Content, _ := json.Marshal(map[string]any{
		"identifiers": []any{
			map[string]any{"name": "b", "type": "scim", "config": map[string]any{"bearerToken": "new-token"}},
			map[string]any{"name": "a", "type": "hmac", "config": map[string]any{
				"keys": map[string]any{"k1": map[string]any{"secret": secretValueSentinel}},
			}},
		},
	})
	if _, err := s.PushConfig(ctx, "local", "inst", string(v2Content), "op", "add b before a"); err != nil {
		t.Fatalf("push v2: %v", err)
	}

	stored, _ := s.Current("local", "inst")
	var doc map[string]any
	if err := json.Unmarshal([]byte(stored.Content), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entries := doc["identifiers"].([]any)
	for _, e := range entries {
		em := e.(map[string]any)
		if em["name"] == "a" {
			cfg := em["config"].(map[string]any)
			if got := getPath(t, cfg, "keys", "k1", "secret"); got != "real-secret" {
				t.Errorf("module 'a' secret not restored correctly (name-based pairing failed), got %#v", got)
			}
		}
	}
}

func TestStore_PushConfig_MergeSurvivesArrayReorderingByKid(t *testing.T) {
	s := NewStore()
	ctx := t.Context()

	v1Content := authConfig(t, "identifiers", "a", "hmac", map[string]any{
		"secrets": []any{
			map[string]any{"kid": "v1", "secret": "secret-v1"},
			map[string]any{"kid": "v2", "secret": "secret-v2"},
		},
	})
	if _, err := s.PushConfig(ctx, "local", "inst", v1Content, "op", "initial"); err != nil {
		t.Fatalf("push v1: %v", err)
	}

	// v2: reorder the secrets array (v2 first now) and leave both as
	// sentinels -- ArrayIDKey ("kid") pairing must still restore correctly.
	v2Content := authConfig(t, "identifiers", "a", "hmac", map[string]any{
		"secrets": []any{
			map[string]any{"kid": "v2", "secret": secretValueSentinel},
			map[string]any{"kid": "v1", "secret": secretValueSentinel},
		},
	})
	if _, err := s.PushConfig(ctx, "local", "inst", v2Content, "op", "reorder"); err != nil {
		t.Fatalf("push v2: %v", err)
	}

	stored, _ := s.Current("local", "inst")
	cfg := moduleConfig(t, stored.Content, "identifiers")
	secrets := cfg["secrets"].([]any)
	byKid := map[string]string{}
	for _, s := range secrets {
		m := s.(map[string]any)
		byKid[m["kid"].(string)] = m["secret"].(string)
	}
	if byKid["v1"] != "secret-v1" {
		t.Errorf("kid v1: expected secret-v1, got %q", byKid["v1"])
	}
	if byKid["v2"] != "secret-v2" {
		t.Errorf("kid v2: expected secret-v2, got %q", byKid["v2"])
	}
}

func TestStore_PushConfig_ApikeyStaticBlockRestoreVsReplace(t *testing.T) {
	s := NewStore()
	ctx := t.Context()

	v1Content := authConfig(t, "identifiers", "a", "apikey", map[string]any{
		"static": map[string]any{"sk_original": map[string]any{"subject": "alice"}},
	})
	if _, err := s.PushConfig(ctx, "local", "inst", v1Content, "op", "initial"); err != nil {
		t.Fatalf("push v1: %v", err)
	}

	t.Run("sentinel restores prior map verbatim", func(t *testing.T) {
		redacted, _ := RedactConfigVersion(mustCurrent(t, s))
		if _, err := s.PushConfig(ctx, "local", "inst", redacted.Content, "op", "no-op edit"); err != nil {
			t.Fatalf("push with block sentinel: %v", err)
		}
		stored := mustCurrent(t, s)
		cfg := moduleConfig(t, stored.Content, "identifiers")
		static := cfg["static"].(map[string]any)
		if _, ok := static["sk_original"]; !ok {
			t.Errorf("expected original static map restored, got %#v", static)
		}
	})

	t.Run("real map submitted is accepted as full replacement", func(t *testing.T) {
		v3Content := authConfig(t, "identifiers", "a", "apikey", map[string]any{
			"static": map[string]any{"sk_new_key": map[string]any{"subject": "bob"}},
		})
		if _, err := s.PushConfig(ctx, "local", "inst", v3Content, "op", "rotate key"); err != nil {
			t.Fatalf("push replacement: %v", err)
		}
		stored := mustCurrent(t, s)
		cfg := moduleConfig(t, stored.Content, "identifiers")
		static := cfg["static"].(map[string]any)
		if _, ok := static["sk_new_key"]; !ok {
			t.Errorf("expected new static map accepted verbatim, got %#v", static)
		}
		if _, ok := static["sk_original"]; ok {
			t.Errorf("expected old key gone after deliberate replacement, got %#v", static)
		}
	})
}

func mustCurrent(t *testing.T, s *Store) ConfigVersion {
	t.Helper()
	v, ok := s.Current("local", "inst")
	if !ok {
		t.Fatal("expected a current version")
	}
	return v
}

func TestStore_PushConfig_FirstPushWithSentinelRejected(t *testing.T) {
	s := NewStore()
	content := authConfig(t, "identifiers", "a", "hmac", map[string]any{
		"keys": map[string]any{"k1": map[string]any{"secret": secretValueSentinel}},
	})
	_, err := s.PushConfig(t.Context(), "local", "inst", content, "op", "first push")
	if !errors.Is(err, errFirstPushSentinel) {
		t.Fatalf("expected errFirstPushSentinel, got %v", err)
	}
	if _, ok := s.Current("local", "inst"); ok {
		t.Error("expected nothing to be persisted after a rejected first push")
	}
}

// ── Rollback interaction ─────────────────────────────────────────────

func TestStore_Rollback_StoresRealSecretRedactsOnlyOnResponse(t *testing.T) {
	s := NewStore()
	ctx := t.Context()

	v1Content := authConfig(t, "identifiers", "a", "hmac", map[string]any{
		"keys": map[string]any{"k1": map[string]any{"secret": "secret-v1"}},
	})
	v1, err := s.PushConfig(ctx, "local", "inst", v1Content, "op", "v1")
	if err != nil {
		t.Fatalf("push v1: %v", err)
	}

	v2Content := authConfig(t, "identifiers", "a", "hmac", map[string]any{
		"keys": map[string]any{"k1": map[string]any{"secret": "secret-v2"}},
	})
	if _, err := s.PushConfig(ctx, "local", "inst", v2Content, "op", "v2"); err != nil {
		t.Fatalf("push v2: %v", err)
	}

	v3, err := s.Rollback("local", "inst", v1.Version, "op")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// Store internals: real secret, unredacted.
	storedCfg := moduleConfig(t, v3.Content, "identifiers")
	if got := getPath(t, storedCfg, "keys", "k1", "secret"); got != "secret-v1" {
		t.Errorf("expected Store to hold the real rolled-back secret, got %#v", got)
	}

	// HTTP-response boundary: same version, redacted.
	redacted, err := RedactConfigVersion(v3)
	if err != nil {
		t.Fatalf("redact v3: %v", err)
	}
	redactedCfg := moduleConfig(t, redacted.Content, "identifiers")
	if got := getPath(t, redactedCfg, "keys", "k1", "secret"); got != secretValueSentinel {
		t.Errorf("expected redacted response to show sentinel, got %#v", got)
	}
}

// ── Fast path ────────────────────────────────────────────────────────

func TestStore_PushConfig_NoSentinelIsByteIdentical(t *testing.T) {
	s := NewStore()
	ctx := t.Context()

	// Deliberately unusual key order/spacing survives untouched — proves
	// the fast path returns the submitted bytes rather than
	// re-marshaling through map[string]any (which would reorder keys).
	content := `{"identifiers":[{"name":"a","type":"rbac","config":{"rolesFrom":"claims.roles","allow":["admin"]}}]}`
	v, err := s.PushConfig(ctx, "local", "inst", content, "op", "no secrets here")
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if v.Content != content {
		t.Errorf("expected byte-identical content on the no-sentinel fast path\ngot:  %s\nwant: %s", v.Content, content)
	}
}
