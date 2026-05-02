// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package opa

import (
	"context"
	"errors"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

const adminOnly = `
package authz

default allow = false
allow if {
  input.identity.claims.role == "admin"
}
`

func mustBuild(t *testing.T, src string) module.Authorizer {
	t.Helper()
	a, err := factory("opa", map[string]any{"rego": src})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return a
}

func TestOPA_AdminAllowed(t *testing.T) {
	t.Parallel()
	a := mustBuild(t, adminOnly)
	dec, err := a.Authorize(context.Background(), &module.Request{}, &module.Identity{
		Subject: "alice",
		Claims:  map[string]any{"role": "admin"},
	})
	if err != nil || !dec.Allow {
		t.Fatalf("admin: got (%+v, %v)", dec, err)
	}
}

func TestOPA_NonAdminDenied(t *testing.T) {
	t.Parallel()
	a := mustBuild(t, adminOnly)
	dec, err := a.Authorize(context.Background(), &module.Request{}, &module.Identity{
		Subject: "bob",
		Claims:  map[string]any{"role": "viewer"},
	})
	if err != nil || dec.Allow {
		t.Fatalf("viewer: got (%+v, %v), want deny", dec, err)
	}
	if dec.Status != 403 {
		t.Errorf("Status = %d, want 403", dec.Status)
	}
}

func TestOPA_BadRegoFailsAtCompile(t *testing.T) {
	t.Parallel()
	_, err := factory("opa", map[string]any{"rego": "package authz\nallow { syntax error"})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestOPA_MissingRego(t *testing.T) {
	t.Parallel()
	_, err := factory("opa", map[string]any{})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}
