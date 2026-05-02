// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"context"
	"errors"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func mustBuild(t *testing.T, expr string) module.Authorizer {
	t.Helper()
	a, err := factory("cel", map[string]any{"expression": expr})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return a
}

func TestCEL_AllowOnRoleAndMethod(t *testing.T) {
	t.Parallel()
	a := mustBuild(t, `identity.claims.role == "admin" && request.method == "GET"`)
	dec, err := a.Authorize(context.Background(),
		&module.Request{Method: "GET"},
		&module.Identity{Claims: map[string]any{"role": "admin"}},
	)
	if err != nil || !dec.Allow {
		t.Fatalf("got (%+v, %v), want allow", dec, err)
	}
}

func TestCEL_DenyOnWrongMethod(t *testing.T) {
	t.Parallel()
	a := mustBuild(t, `request.method == "GET"`)
	dec, err := a.Authorize(context.Background(),
		&module.Request{Method: "DELETE"},
		&module.Identity{},
	)
	if err != nil || dec.Allow {
		t.Fatalf("got (%+v, %v), want deny", dec, err)
	}
}

func TestCEL_NonBoolExpressionRejectedAtCompile(t *testing.T) {
	t.Parallel()
	_, err := factory("cel", map[string]any{"expression": `"hello"`})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestCEL_MissingExpression(t *testing.T) {
	t.Parallel()
	_, err := factory("cel", map[string]any{})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestCEL_HeaderLookup(t *testing.T) {
	t.Parallel()
	a := mustBuild(t, `request.headers["X-Tenant"] == "acme"`)
	dec, err := a.Authorize(context.Background(),
		&module.Request{Headers: map[string][]string{"X-Tenant": {"acme"}}},
		&module.Identity{},
	)
	if err != nil || !dec.Allow {
		t.Fatalf("got (%+v, %v), want allow", dec, err)
	}
}
