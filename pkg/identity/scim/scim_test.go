// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package scim

import (
	"encoding/json"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func TestFactory_Valid(t *testing.T) {
	raw := map[string]any{
		"bearerToken":  "secret-token",
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
	id, _ := factory("test", map[string]any{"bearerToken": "tok"})
	r := &module.Request{Headers: map[string][]string{}}
	_, err := id.Identify(nil, r)
	if err != module.ErrNoMatch {
		t.Fatalf("expected ErrNoMatch, got %v", err)
	}
}

func TestIdentify_WrongScheme(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "tok"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"Basic dXNlcjpwYXNz"},
	}}
	_, err := id.Identify(nil, r)
	if err != module.ErrNoMatch {
		t.Fatalf("expected ErrNoMatch, got %v", err)
	}
}

func TestIdentify_InvalidToken(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "correct-token"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"Bearer wrong-token"},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestIdentify_ValidToken_NoBody(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "my-secret"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"Bearer my-secret"},
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
		"bearerToken":  "secret",
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
			"Authorization": {"Bearer secret"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "alice@example.com" {
		t.Errorf("Subject = %q, want alice@example.com", identity.Subject)
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
		"bearerToken":  "secret",
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
			"Authorization": {"Bearer secret"},
		},
		Body: body,
	}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "Engineering" {
		t.Errorf("Subject = %q, want Engineering", identity.Subject)
	}
}

func TestIdentify_CaseInsensitiveScheme(t *testing.T) {
	id, _ := factory("test", map[string]any{"bearerToken": "tok"})
	r := &module.Request{Headers: map[string][]string{
		"Authorization": {"bearer tok"},
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
		"bearerToken": "tok",
		"header":      "X-SCIM-Token",
		"scheme":      "Token",
	})
	r := &module.Request{Headers: map[string][]string{
		"X-Scim-Token": {"Token tok"},
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
	id, _ := factory("test", map[string]any{"bearerToken": "tok"})
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
	id, _ := factory("test", map[string]any{"bearerToken": "tok"})
	r := &module.Request{
		Headers: map[string][]string{
			"Authorization": {"Bearer tok"},
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
