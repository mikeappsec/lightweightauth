// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package assurance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func req(method, path string) *module.Request {
	return &module.Request{
		Method:  method,
		Path:    path,
		Headers: map[string][]string{},
		Context: map[string]any{},
	}
}

func id(acr string, amr []string) *module.Identity {
	return &module.Identity{
		Subject: "alice",
		Claims:  map[string]any{"sub": "alice"},
		Source:  "jwt",
		ACR:     acr,
		AMR:     amr,
	}
}

func idWithAuthTime(acr string, amr []string, authTime int64) *module.Identity {
	id := id(acr, amr)
	id.Claims["auth_time"] = authTime
	return id
}

func TestAssurance_AllowsWhenACRMatches(t *testing.T) {
	az := &authorizer{
		name: "mfa-check",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa"}},
		}},
	}

	dec, err := az.Authorize(context.Background(), req("GET", "/"), id("urn:mfa", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow {
		t.Fatalf("expected allow, got deny: %s", dec.Reason)
	}
}

func TestAssurance_DeniesWhenACRMissing(t *testing.T) {
	az := &authorizer{
		name: "mfa-check",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa"}},
		}},
	}

	dec, err := az.Authorize(context.Background(), req("GET", "/"), id("0", nil))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("expected deny when ACR doesn't match")
	}
	if dec.Status != 401 {
		t.Fatalf("expected 401, got %d", dec.Status)
	}
	if dec.StepUp == nil {
		t.Fatal("expected step-up challenge")
	}
	if len(dec.StepUp.RequiredACR) != 1 || dec.StepUp.RequiredACR[0] != "urn:mfa" {
		t.Fatalf("expected RequiredACR=[urn:mfa], got %v", dec.StepUp.RequiredACR)
	}
}

func TestAssurance_DeniesWhenAMRMissing(t *testing.T) {
	az := &authorizer{
		name: "mfa-check",
		rules: []Rule{{
			Require: Requirement{AMR: []string{"hwk", "pin"}},
		}},
	}

	// Has hwk but not pin.
	dec, err := az.Authorize(context.Background(), req("GET", "/"), id("", []string{"hwk"}))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("expected deny when AMR is incomplete")
	}
	if dec.StepUp == nil || len(dec.StepUp.RequiredAMR) != 2 {
		t.Fatalf("expected RequiredAMR=[hwk, pin], got %v", dec.StepUp)
	}
}

func TestAssurance_AllowsWhenAllAMRPresent(t *testing.T) {
	az := &authorizer{
		name: "mfa-check",
		rules: []Rule{{
			Require: Requirement{AMR: []string{"pwd", "otp"}},
		}},
	}

	dec, err := az.Authorize(context.Background(), req("GET", "/"), id("", []string{"pwd", "otp", "sms"}))
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow {
		t.Fatal("expected allow when all AMR present")
	}
}

func TestAssurance_MethodMatch(t *testing.T) {
	az := &authorizer{
		name: "write-guard",
		rules: []Rule{{
			Match:   &MatchPredicate{Methods: []string{"DELETE", "PUT"}},
			Require: Requirement{ACR: []string{"urn:mfa"}},
		}},
	}

	// GET should be allowed (rule doesn't match).
	dec, _ := az.Authorize(context.Background(), req("GET", "/resource"), id("0", nil))
	if !dec.Allow {
		t.Fatal("GET should be allowed — rule only matches DELETE/PUT")
	}

	// DELETE should be denied (ACR=0 doesn't match urn:mfa).
	dec, _ = az.Authorize(context.Background(), req("DELETE", "/resource"), id("0", nil))
	if dec.Allow {
		t.Fatal("DELETE should be denied without MFA")
	}

	// DELETE with MFA should pass.
	dec, _ = az.Authorize(context.Background(), req("DELETE", "/resource"), id("urn:mfa", nil))
	if !dec.Allow {
		t.Fatal("DELETE with MFA should be allowed")
	}
}

func TestAssurance_PathMatch(t *testing.T) {
	az := &authorizer{
		name: "admin-guard",
		rules: []Rule{{
			Match:   &MatchPredicate{Paths: []string{"/admin/**"}},
			Require: Requirement{ACR: []string{"urn:hwk"}},
		}},
	}

	// Non-admin path — rule doesn't match, allow.
	dec, _ := az.Authorize(context.Background(), req("GET", "/api/data"), id("0", nil))
	if !dec.Allow {
		t.Fatal("non-admin path should be allowed")
	}

	// Admin path without hardware key — deny.
	dec, _ = az.Authorize(context.Background(), req("GET", "/admin/users"), id("urn:mfa", nil))
	if dec.Allow {
		t.Fatal("admin path without hwk should be denied")
	}

	// Admin path with hardware key — allow.
	dec, _ = az.Authorize(context.Background(), req("GET", "/admin/users"), id("urn:hwk", nil))
	if !dec.Allow {
		t.Fatal("admin path with hwk should be allowed")
	}
}

func TestAssurance_CombinedMethodAndPath(t *testing.T) {
	az := &authorizer{
		name: "strict",
		rules: []Rule{{
			Match:   &MatchPredicate{Methods: []string{"POST"}, Paths: []string{"/admin/**"}},
			Require: Requirement{ACR: []string{"urn:mfa"}, AMR: []string{"hwk"}},
		}},
	}

	// POST /admin/config without MFA — deny.
	dec, _ := az.Authorize(context.Background(), req("POST", "/admin/config"), id("0", nil))
	if dec.Allow {
		t.Fatal("POST /admin without MFA should deny")
	}

	// POST /admin/config with MFA+hwk — allow.
	dec, _ = az.Authorize(context.Background(), req("POST", "/admin/config"), id("urn:mfa", []string{"hwk"}))
	if !dec.Allow {
		t.Fatal("POST /admin with MFA+hwk should allow")
	}

	// GET /admin/config (method doesn't match) — allow.
	dec, _ = az.Authorize(context.Background(), req("GET", "/admin/config"), id("0", nil))
	if !dec.Allow {
		t.Fatal("GET should not match POST-only rule")
	}
}

func TestAssurance_MultipleRulesFirstMatchWins(t *testing.T) {
	az := &authorizer{
		name: "multi",
		rules: []Rule{
			{
				Match:   &MatchPredicate{Methods: []string{"DELETE"}},
				Require: Requirement{ACR: []string{"urn:hwk"}},
			},
			{
				// Default: any request needs at least MFA.
				Require: Requirement{ACR: []string{"urn:mfa"}},
			},
		},
	}

	// DELETE needs hwk, not just mfa.
	dec, _ := az.Authorize(context.Background(), req("DELETE", "/x"), id("urn:mfa", nil))
	if dec.Allow {
		t.Fatal("DELETE with only MFA should deny (hwk required)")
	}

	// GET needs mfa.
	dec, _ = az.Authorize(context.Background(), req("GET", "/x"), id("urn:mfa", nil))
	if !dec.Allow {
		t.Fatal("GET with MFA should be allowed by default rule")
	}

	// GET without MFA — deny.
	dec, _ = az.Authorize(context.Background(), req("GET", "/x"), id("0", nil))
	if dec.Allow {
		t.Fatal("GET without MFA should be denied by default rule")
	}
}

func TestAssurance_NilIdentity(t *testing.T) {
	az := &authorizer{
		name: "check",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa"}},
		}},
	}

	dec, err := az.Authorize(context.Background(), req("GET", "/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("nil identity should be denied")
	}
	if dec.Status != 401 {
		t.Fatalf("expected 401, got %d", dec.Status)
	}
}

func TestAssurance_WWWAuthenticateHeader(t *testing.T) {
	az := &authorizer{
		name: "challenge",
		rules: []Rule{{
			Require: Requirement{
				ACR:    []string{"urn:mfa", "urn:hwk"},
				MaxAge: 300,
			},
		}},
	}

	dec, _ := az.Authorize(context.Background(), req("GET", "/"), id("0", nil))
	if dec.Allow {
		t.Fatal("expected deny")
	}

	wwwAuth, ok := dec.ResponseHeaders["WWW-Authenticate"]
	if !ok {
		t.Fatal("expected WWW-Authenticate header")
	}
	if !strings.Contains(wwwAuth, "insufficient_user_authentication") {
		t.Fatalf("expected error=insufficient_user_authentication, got %s", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "acr_values=") {
		t.Fatalf("expected acr_values in header, got %s", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `max_age="300"`) {
		t.Fatalf("expected max_age=300 in header, got %s", wwwAuth)
	}
}

func TestAssurance_MultipleACRAccepted(t *testing.T) {
	az := &authorizer{
		name: "flexible",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa", "urn:otp", "urn:hwk"}},
		}},
	}

	// Any one of the accepted ACR values should pass.
	for _, acr := range []string{"urn:mfa", "urn:otp", "urn:hwk"} {
		dec, _ := az.Authorize(context.Background(), req("GET", "/"), id(acr, nil))
		if !dec.Allow {
			t.Fatalf("ACR %q should be accepted", acr)
		}
	}
}

func TestAssurance_MaxAgeInChallenge(t *testing.T) {
	az := &authorizer{
		name: "age-check",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa"}, MaxAge: 600},
		}},
	}

	dec, _ := az.Authorize(context.Background(), req("GET", "/"), id("0", nil))
	if dec.StepUp == nil {
		t.Fatal("expected step-up challenge")
	}
	if dec.StepUp.MaxAge != 600 {
		t.Fatalf("expected MaxAge=600, got %d", dec.StepUp.MaxAge)
	}
}

func TestAssurance_DeniesWhenMaxAgeExceeded(t *testing.T) {
	now := time.Now().Unix()
	az := &authorizer{
		name: "age-enforced",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa"}, MaxAge: 60},
		}},
	}

	dec, err := az.Authorize(context.Background(), req("GET", "/"), idWithAuthTime("urn:mfa", nil, now-120))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("expected deny when auth_time exceeds maxAge")
	}
	if dec.StepUp == nil || dec.StepUp.MaxAge != 60 {
		t.Fatalf("expected step-up MaxAge=60, got %+v", dec.StepUp)
	}
}

func TestAssurance_DeniesWhenMaxAgeConfiguredAndAuthTimeMissing(t *testing.T) {
	az := &authorizer{
		name: "age-enforced",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa"}, MaxAge: 60},
		}},
	}

	dec, err := az.Authorize(context.Background(), req("GET", "/"), id("urn:mfa", nil))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("expected deny when auth_time is missing")
	}
	if dec.StepUp == nil || dec.StepUp.MaxAge != 60 {
		t.Fatalf("expected step-up MaxAge=60, got %+v", dec.StepUp)
	}
}

func TestAssurance_AllowsWhenMaxAgeFresh(t *testing.T) {
	now := time.Now().Unix()
	az := &authorizer{
		name: "age-enforced",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa"}, MaxAge: 300},
		}},
	}

	dec, err := az.Authorize(context.Background(), req("GET", "/"), idWithAuthTime("urn:mfa", nil, now-30))
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Allow {
		t.Fatalf("expected allow for fresh auth_time, got deny: %s", dec.Reason)
	}
}

func TestAssurance_DeniesWhenAuthTimeInFuture(t *testing.T) {
	now := time.Now().Unix()
	az := &authorizer{
		name: "age-enforced",
		rules: []Rule{{
			Require: Requirement{ACR: []string{"urn:mfa"}, MaxAge: 60},
		}},
	}

	// Future auth_time must be rejected (G5-03).
	dec, err := az.Authorize(context.Background(), req("GET", "/"), idWithAuthTime("urn:mfa", nil, now+999999))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("expected deny when auth_time is in the future")
	}
	if dec.StepUp == nil || dec.StepUp.MaxAge != 60 {
		t.Fatalf("expected step-up MaxAge=60, got %+v", dec.StepUp)
	}
}

func TestAssurance_Factory(t *testing.T) {
	raw := map[string]any{
		"rules": []any{
			map[string]any{
				"match": map[string]any{
					"methods": []any{"DELETE"},
				},
				"require": map[string]any{
					"acr":    []any{"urn:mfa"},
					"maxAge": float64(300),
				},
			},
			map[string]any{
				"require": map[string]any{
					"acr": []any{"urn:otp"},
					"amr": []any{"otp"},
				},
			},
		},
	}

	az, err := factory("test-az", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if az.Name() != "test-az" {
		t.Fatalf("expected name test-az, got %s", az.Name())
	}

	// DELETE without MFA should deny.
	dec, _ := az.Authorize(context.Background(), req("DELETE", "/x"), id("0", nil))
	if dec.Allow {
		t.Fatal("DELETE without MFA should deny")
	}
}

func TestAssurance_FactoryRejectsEmpty(t *testing.T) {
	_, err := factory("bad", map[string]any{})
	if err == nil {
		t.Fatal("expected error for empty rules")
	}
}

func TestAssurance_FactoryRejectsUnknownKeys(t *testing.T) {
	_, err := factory("bad", map[string]any{
		"rules":   []any{map[string]any{"require": map[string]any{"acr": []any{"x"}}}},
		"unknown": "value",
	})
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestAssurance_FactoryRejectsEmptyRequire(t *testing.T) {
	_, err := factory("bad", map[string]any{
		"rules": []any{map[string]any{"require": map[string]any{}}},
	})
	if err == nil {
		t.Fatal("expected error for empty require")
	}
}

func TestAssurance_FactoryRejectsUnknownRuleKey(t *testing.T) {
	_, err := factory("bad", map[string]any{
		"rules": []any{map[string]any{
			"require": map[string]any{"acr": []any{"urn:mfa"}},
			"oops":    true,
		}},
	})
	if err == nil {
		t.Fatal("expected error for unknown rule key")
	}
}

func TestAssurance_FactoryRejectsUnknownMatchKey(t *testing.T) {
	_, err := factory("bad", map[string]any{
		"rules": []any{map[string]any{
			"match":   map[string]any{"methodz": []any{"GET"}},
			"require": map[string]any{"acr": []any{"urn:mfa"}},
		}},
	})
	if err == nil {
		t.Fatal("expected error for unknown match key")
	}
}

func TestAssurance_FactoryRejectsUnknownRequireKey(t *testing.T) {
	_, err := factory("bad", map[string]any{
		"rules": []any{map[string]any{
			"require": map[string]any{"acr": []any{"urn:mfa"}, "acrr": []any{"urn:otp"}},
		}},
	})
	if err == nil {
		t.Fatal("expected error for unknown require key")
	}
}
