// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package scim

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func TestFactory_Valid(t *testing.T) {
	raw := map[string]any{
		"bearerToken":  "secret-token-that-is-long-enough",
		"subjectClaim": "userName",
		"groupsClaim":  "groups",
	}
	id, err := factory("scim-test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if id.Name() != "scim-test" {
		t.Errorf("Name = %q, want scim-test", id.Name())
	}
}

func TestFactory_MissingToken(t *testing.T) {
	raw := map[string]any{}
	_, err := factory("x", raw)
	if err == nil {
		t.Fatal("expected error for missing bearerToken")
	}
}

func TestFactory_UnknownKey(t *testing.T) {
	raw := map[string]any{
		"bearerToken": "x",
		"bogus":       "y",
	}
	_, err := factory("x", raw)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestIdentify_NoHeader(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "tok-is-now-long-enough!!"})
	r := &module.Request{Headers: map[string][]string{}}
	_, err := id.Identify(nil, r)
	if err != module.ErrNoMatch {
		t.Fatalf("expected ErrNoMatch, got %v", err)
	}
}

func TestIdentify_WrongScheme(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "tok-is-now-long-enough!!"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"Basic dXNlcjpwYXNz"},
	}}
	_, err := id.Identify(nil, r)
	if err != module.ErrNoMatch {
		t.Fatalf("expected ErrNoMatch, got %v", err)
	}
}

func TestIdentify_InvalidToken(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "correct-token-long-ok!"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"Bearer wrong-token-definitely"},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestIdentify_ValidToken_NoBody(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "my-secret-long-enough!!"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"Bearer my-secret-long-enough!!"},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "scim-provisioner" {
		t.Errorf("Subject = %q, want scim-provisioner", identity.Subject)
	}
	if identity.Source != "test" {
		t.Errorf("Source = %q, want test", identity.Source)
	}
	if identity.Claims["provisioning"] != true {
		t.Error("expected provisioning=true in claims")
	}
}

func TestIdentify_ValidToken_WithUserPayload(t *testing.T) {
	id, _ := factory("scim-prod", map[string]any{
		"bearerToken":  "secret-long-enough-now!",
		"subjectClaim": "userName",
		"groupsClaim":  "groups",
	})
	payload := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":    "alice@example.com",
		"displayName": "Alice Smith",
		"active":      true,
		"id":          "user-123",
		"groups":      []string{"admins", "users"},
	}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer secret-long-enough-now!"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "scim:alice@example.com" {
		t.Errorf("Subject = %q, want scim:alice@example.com", identity.Subject)
	}
	if identity.Claims["userName"] != "alice@example.com" {
		t.Errorf("userName claim = %v", identity.Claims["userName"])
	}
	if identity.Claims["displayName"] != "Alice Smith" {
		t.Errorf("displayName = %v", identity.Claims["displayName"])
	}
	if identity.Claims["scimId"] != "user-123" {
		t.Errorf("scimId = %v", identity.Claims["scimId"])
	}
	if identity.Claims["active"] != true {
		t.Errorf("active = %v", identity.Claims["active"])
	}
}

func TestIdentify_ValidToken_WithGroupPayload(t *testing.T) {
	id, _ := factory("scim-prod", map[string]any{
		"bearerToken":  "secret-long-enough-now!",
		"subjectClaim": "displayName",
	})
	payload := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineering",
		"id":          "group-456",
	}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer secret-long-enough-now!"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "scim:Engineering" {
		t.Errorf("Subject = %q, want scim:Engineering", identity.Subject)
	}
}

func TestIdentify_CaseInsensitiveScheme(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "tok-is-now-long-enough!!"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"bearer tok-is-now-long-enough!!"},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "scim-provisioner" {
		t.Errorf("Subject = %q, want scim-provisioner", identity.Subject)
	}
}

func TestIdentify_CustomHeader(t *testing.T) {
	id, _ := factory("test", map[string]any{
		"bearerToken": "tok-is-now-long-enough!!",
		"header":      "X-SCIM-Token",
		"scheme":      "Token",
	})
	r := &module.Request{Headers: map[string][]string{
		"X-Scim-Token": {"Token tok-is-now-long-enough!!"},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "scim-provisioner" {
		t.Errorf("Subject = %q", identity.Subject)
	}
}

func TestIdentify_EmptyBearer(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "tok-is-now-long-enough!!"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"Bearer "},
	}}
	_, err := id.Identify(nil, r)
	if err != module.ErrNoMatch {
		t.Fatalf("expected ErrNoMatch for empty token, got %v", err)
	}
}

func TestIdentify_InvalidJSON(t *testing.T) {
	// Invalid body JSON should still succeed (just uses default subject).
	id, _ := factory("test", map[string]any{"bearerToken": "tok-is-now-long-enough!!"})
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer tok-is-now-long-enough!!"},
		},
		Body: []byte("{invalid json"),
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "scim-provisioner" {
		t.Errorf("Subject = %q, want scim-provisioner", identity.Subject)
	}
}

func TestIdentify_BodyTooLarge(t *testing.T) {
	// G9-VULN-05: Oversized body must be rejected to prevent OOM.
	id, _ := factory("test", map[string]any{"bearerToken": "tok-is-now-long-enough!!"})
	largeBody := make([]byte, maxSCIMBodySize+1)
	for i := range largeBody {
		largeBody[i] = 'A'
	}
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer tok-is-now-long-enough!!"},
		},
		Body: largeBody,
	}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for oversized body")
	}
}

func TestIdentify_BodyAtLimit(t *testing.T) {
	// Body exactly at the limit should be accepted.
	id, _ := factory("test", map[string]any{"bearerToken": "tok-is-now-long-enough!!"})
	// Build valid JSON that is exactly at the size limit.
	prefix := `{"userName":"alice","padding":"`
	suffix := `"}`
	padLen := maxSCIMBodySize - len(prefix) - len(suffix)
	body := make([]byte, 0, maxSCIMBodySize)
	body = append(body, []byte(prefix)...)
	for i := 0; i < padLen; i++ {
		body = append(body, 'x')
	}
	body = append(body, []byte(suffix)...)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer tok-is-now-long-enough!!"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify at limit: %v", err)
	}
	if identity.Subject != "scim:alice" {
		t.Errorf("Subject = %q, want scim:alice", identity.Subject)
	}
}

func TestIdentify_TokenNotStoredPlaintext(t *testing.T) {
	// G9-VULN-10: The bearer token should be stored as a hash, not plaintext.
	// Verify the identifier struct does not contain the original token.
	id, _ := factory("test", map[string]any{"bearerToken": "super-secret-token-12345"})
	samlID := id.(*identifier)

	// The tokenHash field should be non-zero (it's the SHA-256 of the token).
	zeroHash := [32]byte{}
	if samlID.tokenHash == zeroHash {
		t.Fatal("tokenHash should not be zero after factory")
	}

	// Verify that authentication still works (the hash comparison is correct).
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"Bearer super-secret-token-12345"},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify with correct token: %v", err)
	}
	if identity.Subject != "scim-provisioner" {
		t.Errorf("Subject = %q, want scim-provisioner", identity.Subject)
	}

	// Wrong token must still be rejected.
	r2 := &module.Request{Headers: map[string][]string{
		"Authorization": {"Bearer wrong-token-definitely"},
	}}
	_, err = id.Identify(nil, r2)
	if err == nil {
		t.Fatal("expected rejection for wrong token")
	}
}

func TestSCIM_VULN01_RejectsShortBearerToken(t *testing.T) {
	// SCIM-VULN-01: Bearer tokens shorter than minTokenLen must be rejected
	// at configuration time to prevent brute-force attacks.
	short := "short-token" // 11 chars < 20
	_, err := factory("test", map[string]any{"bearerToken": short})
	if err == nil {
		t.Fatal("expected factory error for short bearer token")
	}
	if !strings.Contains(err.Error(), "at least") {
		t.Errorf("error = %v, want mention of minimum length", err)
	}
}

func TestSCIM_VULN02_SubjectPrefixPreventsCollision(t *testing.T) {
	// SCIM-VULN-02: Body-derived subjects must be namespaced with a prefix
	// so they cannot collide with subjects from other identifiers (JWT, HMAC).
	id, err := factory("scim-prod", map[string]any{
		"bearerToken":  "provisioning-token-xxxx",
		"subjectClaim": "userName",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	payload := map[string]any{"userName": "admin"}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer provisioning-token-xxxx"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	// Subject must be "scim:admin", NOT "admin" — preventing collision
	// with a real "admin" identity from JWT/HMAC.
	if identity.Subject != "scim:admin" {
		t.Errorf("Subject = %q, want \"scim:admin\" (prefixed)", identity.Subject)
	}
}

func TestSCIM_VULN02_DefaultSubjectNotPrefixed(t *testing.T) {
	// When no body userName is present, default subject stays as-is
	// (no prefix needed — "scim-provisioner" is already unique).
	id, _ := factory("test", map[string]any{
		"bearerToken": "long-enough-token-here!",
	})
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer long-enough-token-here!"},
		},
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "scim-provisioner" {
		t.Errorf("Subject = %q, want scim-provisioner", identity.Subject)
	}
}

func TestSCIM_VULN03_RejectsControlCharsInSubject(t *testing.T) {
	// SCIM-VULN-03: Subjects with control characters must be rejected
	// to prevent log injection and audit evasion.
	id, _ := factory("test", map[string]any{
		"bearerToken":  "provisioning-token-xxxx",
		"subjectClaim": "userName",
	})

	tests := []struct {
		name    string
		subject string
	}{
		{"newline", "alice\nadmin"},
		{"carriage-return", "alice\radmin"},
		{"null-byte", "alice\x00admin"},
		{"tab", "alice\tadmin"},
		{"CRLF-injection", "alice\r\nINFO [auth] user=root action=grant"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"userName": tc.subject}
			body, _ := json.Marshal(payload)
			r := &module.Request{
				Headers: map[string][]string{
					"Authorization": {"Bearer provisioning-token-xxxx"},
				},
				Body: body,
			}
			_, err := id.Identify(nil, r)
			if err == nil {
				t.Fatal("expected rejection for control character in subject")
			}
			if !strings.Contains(err.Error(), "control") {
				t.Errorf("error = %v, want mention of control characters", err)
			}
		})
	}
}

func TestSCIM_VULN03_AcceptsValidUnicode(t *testing.T) {
	// Valid unicode characters (including accented, CJK, etc.) should be accepted.
	id, _ := factory("test", map[string]any{
		"bearerToken":  "provisioning-token-xxxx",
		"subjectClaim": "userName",
	})

	payload := map[string]any{"userName": "ålice.sørensen@例え.jp"}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer provisioning-token-xxxx"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "scim:ålice.sørensen@例え.jp" {
		t.Errorf("Subject = %q", identity.Subject)
	}
}

func TestSCIM_VULN04_RejectsOversizedSubject(t *testing.T) {
	// SCIM-VULN-04: Subjects exceeding maxSubjectLen must be rejected
	// to prevent memory exhaustion in identity caches.
	id, _ := factory("test", map[string]any{
		"bearerToken":  "provisioning-token-xxxx",
		"subjectClaim": "userName",
	})

	longSubject := strings.Repeat("a", maxSubjectLen+1)
	payload := map[string]any{"userName": longSubject}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer provisioning-token-xxxx"},
		},
		Body: body,
	}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for oversized subject")
	}
	if !strings.Contains(err.Error(), "maximum length") {
		t.Errorf("error = %v, want mention of maximum length", err)
	}
}

func TestSCIM_VULN04_AcceptsSubjectAtLimit(t *testing.T) {
	// Subject at exactly the maximum length should be accepted.
	id, _ := factory("test", map[string]any{
		"bearerToken":  "provisioning-token-xxxx",
		"subjectClaim": "userName",
	})

	exactSubject := strings.Repeat("b", maxSubjectLen)
	payload := map[string]any{"userName": exactSubject}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer provisioning-token-xxxx"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify at limit: %v", err)
	}
	if identity.Subject != "scim:"+exactSubject {
		t.Error("subject mismatch at limit")
	}
}

func TestSCIM_VULN05_RejectsNonArrayGroups(t *testing.T) {
	// SCIM-VULN-05: Groups must be a JSON array. Objects, numbers, strings
	// as the groups value must be rejected to prevent type confusion.
	id, _ := factory("test", map[string]any{
		"bearerToken": "provisioning-token-xxxx",
		"groupsClaim": "groups",
	})

	tests := []struct {
		name   string
		groups any
	}{
		{"object", map[string]any{"nested": "value"}},
		{"number", 42.0},
		{"string", "admin"},
		{"boolean", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"groups": tc.groups}
			body, _ := json.Marshal(payload)
			r := &module.Request{
				Headers: map[string][]string{
					"Authorization": {"Bearer provisioning-token-xxxx"},
				},
				Body: body,
			}
			_, err := id.Identify(nil, r)
			if err == nil {
				t.Fatalf("expected rejection for groups of type %T", tc.groups)
			}
			if !strings.Contains(err.Error(), "groups") {
				t.Errorf("error = %v, want mention of groups", err)
			}
		})
	}
}

func TestSCIM_VULN05_RejectsNonStringGroupEntries(t *testing.T) {
	// SCIM-VULN-05: Group array entries must all be strings.
	id, _ := factory("test", map[string]any{
		"bearerToken": "provisioning-token-xxxx",
		"groupsClaim": "groups",
	})

	payload := map[string]any{"groups": []any{"admins", 123, "users"}}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer provisioning-token-xxxx"},
		},
		Body: body,
	}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for non-string group entry")
	}
}

func TestSCIM_VULN05_RejectsExcessiveGroupCount(t *testing.T) {
	// SCIM-VULN-05: More than maxGroupsCount groups must be rejected.
	id, _ := factory("test", map[string]any{
		"bearerToken": "provisioning-token-xxxx",
		"groupsClaim": "groups",
	})

	groups := make([]any, maxGroupsCount+1)
	for i := range groups {
		groups[i] = "group-" + strings.Repeat("x", 5)
	}
	payload := map[string]any{"groups": groups}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer provisioning-token-xxxx"},
		},
		Body: body,
	}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for excessive group count")
	}
	if !strings.Contains(err.Error(), "maximum count") {
		t.Errorf("error = %v, want mention of maximum count", err)
	}
}

func TestSCIM_VULN05_AcceptsValidGroups(t *testing.T) {
	// Valid string arrays within limits should be accepted and properly typed.
	id, _ := factory("test", map[string]any{
		"bearerToken": "provisioning-token-xxxx",
		"groupsClaim": "groups",
	})

	payload := map[string]any{
		"userName": "alice",
		"groups":   []string{"admins", "users", "developers"},
	}
	body, _ := json.Marshal(payload)
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer provisioning-token-xxxx"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	groups, ok := identity.Claims["groups"].([]string)
	if !ok {
		t.Fatalf("groups claim type = %T, want []string", identity.Claims["groups"])
	}
	if len(groups) != 3 {
		t.Errorf("groups count = %d, want 3", len(groups))
	}
}
