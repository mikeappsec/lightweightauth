package rbac

import (
	"context"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func build(t *testing.T, allow ...string) module.Authorizer {
	t.Helper()
	allowAny := make([]any, len(allow))
	for i, a := range allow {
		allowAny[i] = a
	}
	a, err := factory("rbac-test", map[string]any{
		"rolesFrom": "claim:roles",
		"allow":     allowAny,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return a
}

func TestRBAC_AllowsMatchingRole(t *testing.T) {
	a := build(t, "admin", "editor")
	id := &module.Identity{Subject: "alice", Claims: map[string]any{"roles": []any{"editor"}}}
	dec, err := a.Authorize(context.Background(), &module.Request{}, id)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !dec.Allow {
		t.Errorf("Allow = false, want true")
	}
}

func TestRBAC_DeniesMissingRole(t *testing.T) {
	a := build(t, "admin")
	id := &module.Identity{Subject: "alice", Claims: map[string]any{"roles": []any{"viewer"}}}
	dec, _ := a.Authorize(context.Background(), &module.Request{}, id)
	if dec.Allow {
		t.Error("Allow = true, want false")
	}
	if dec.Status != 403 {
		t.Errorf("Status = %d, want 403", dec.Status)
	}
}

func TestRBAC_DeniesEmptyClaims(t *testing.T) {
	a := build(t, "admin")
	id := &module.Identity{Subject: "alice"}
	dec, _ := a.Authorize(context.Background(), &module.Request{}, id)
	if dec.Allow {
		t.Error("Allow = true, want false")
	}
}

func TestRBAC_StringRoleAlsoWorks(t *testing.T) {
	a := build(t, "admin")
	id := &module.Identity{Claims: map[string]any{"roles": "admin"}}
	dec, _ := a.Authorize(context.Background(), &module.Request{}, id)
	if !dec.Allow {
		t.Error("Allow = false, want true (string-form roles claim)")
	}
}
