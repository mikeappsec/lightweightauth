// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package assurance implements the step-up MFA / assurance-level authorizer
// (G5 — ID-MFA-1). It checks the identity's ACR and AMR against
// configurable requirements and returns a step-up challenge on mismatch.
//
// Example config:
//
//	type: assurance
//	rules:
//	  - match:
//	      methods: ["DELETE", "PUT"]
//	    require:
//	      acr: ["urn:mfa"]
//	  - match:
//	      paths: ["/admin/**"]
//	    require:
//	      acr: ["urn:hwk"]
//	      amr: ["hwk"]
//	      maxAge: 300
//	  - require:           # default rule (no match = all requests)
//	      acr: ["urn:mfa", "urn:otp"]
package assurance

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Rule is one assurance requirement with an optional match predicate.
type Rule struct {
	// Match restricts when this rule applies. If nil/empty, applies to all.
	Match *MatchPredicate `json:"match,omitempty" yaml:"match,omitempty"`
	// Require specifies the assurance level the identity must meet.
	Require Requirement `json:"require" yaml:"require"`
}

// MatchPredicate selects which requests a rule applies to.
type MatchPredicate struct {
	// Methods matches HTTP methods (e.g. ["DELETE", "PUT", "PATCH"]).
	Methods []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	// Paths matches request paths using glob patterns (e.g. ["/admin/**"]).
	Paths []string `json:"paths,omitempty" yaml:"paths,omitempty"`
}

// Requirement describes the minimum assurance the identity must provide.
type Requirement struct {
	// ACR lists acceptable acr values. The identity must have at least
	// one of these. If empty, acr is not checked.
	ACR []string `json:"acr,omitempty" yaml:"acr,omitempty"`
	// AMR lists required amr methods. The identity must have ALL of
	// these present in its AMR set. If empty, amr is not checked.
	AMR []string `json:"amr,omitempty" yaml:"amr,omitempty"`
	// MaxAge is the maximum acceptable authentication age in seconds.
	// Checked against the "auth_time" claim. Zero means no constraint.
	MaxAge int `json:"maxAge,omitempty" yaml:"maxAge,omitempty"`
}

type authorizer struct {
	name  string
	rules []Rule
}

func (a *authorizer) Name() string { return a.name }

func (a *authorizer) Authorize(_ context.Context, r *module.Request, id *module.Identity) (*module.Decision, error) {
	if id == nil {
		return &module.Decision{
			Allow:  false,
			Status: 401,
			Reason: "assurance: no identity",
		}, nil
	}

	for _, rule := range a.rules {
		if !ruleMatches(rule.Match, r) {
			continue
		}
		if ok, stepUp := checkRequirement(id, rule.Require); !ok {
			return &module.Decision{
				Allow:  false,
				Status: 401,
				Reason: fmt.Sprintf("assurance: step-up required for %s %s", r.Method, r.Path),
				StepUp: stepUp,
				ResponseHeaders: map[string]string{
					"WWW-Authenticate": buildWWWAuthenticate(stepUp),
				},
			}, nil
		}
		// First matching rule that passes — allow.
		return &module.Decision{Allow: true}, nil
	}
	// No rules matched — allow (no assurance constraint).
	return &module.Decision{Allow: true}, nil
}

// ruleMatches returns true if the request matches the rule's predicates,
// or if the rule has no predicates (catch-all).
func ruleMatches(m *MatchPredicate, r *module.Request) bool {
	if m == nil {
		return true
	}
	methodOK := len(m.Methods) == 0
	for _, method := range m.Methods {
		if strings.EqualFold(r.Method, method) {
			methodOK = true
			break
		}
	}
	if !methodOK {
		return false
	}
	pathOK := len(m.Paths) == 0
	for _, pattern := range m.Paths {
		if matched, _ := path.Match(pattern, r.Path); matched {
			pathOK = true
			break
		}
		// Support "**" suffix for prefix matching.
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "/**")
			if strings.HasPrefix(r.Path, prefix) {
				pathOK = true
				break
			}
		}
	}
	return pathOK
}

// checkRequirement verifies the identity meets the requirement.
// Returns (true, nil) on success, (false, challenge) on failure.
func checkRequirement(id *module.Identity, req Requirement) (bool, *module.StepUpChallenge) {
	challenge := &module.StepUpChallenge{
		MaxAge: req.MaxAge,
	}
	failed := false

	// Check ACR: identity must have at least one of the required values.
	if len(req.ACR) > 0 {
		acrOK := false
		for _, required := range req.ACR {
			if id.ACR == required {
				acrOK = true
				break
			}
		}
		if !acrOK {
			challenge.RequiredACR = req.ACR
			failed = true
		}
	}

	// Check AMR: identity must have ALL required methods.
	if len(req.AMR) > 0 {
		amrSet := make(map[string]struct{}, len(id.AMR))
		for _, m := range id.AMR {
			amrSet[m] = struct{}{}
		}
		var missing []string
		for _, required := range req.AMR {
			if _, ok := amrSet[required]; !ok {
				missing = append(missing, required)
			}
		}
		if len(missing) > 0 {
			challenge.RequiredAMR = req.AMR
			failed = true
		}
	}

	// Check MaxAge: require a valid auth_time claim that is recent enough.
	// A negative age (auth_time in the future) is treated as invalid to
	// prevent bypass via clock-skewed or forged tokens (G5-03).
	if req.MaxAge > 0 {
		authTime, ok := authTimeUnix(id)
		if !ok || authTime <= 0 {
			failed = true
		} else {
			if age := time.Now().Unix() - authTime; age < 0 || age > int64(req.MaxAge) {
				failed = true
			}
		}
	}

	if failed {
		return false, challenge
	}
	return true, nil
}

func authTimeUnix(id *module.Identity) (int64, bool) {
	if id == nil || id.Claims == nil {
		return 0, false
	}
	v, ok := id.Claims["auth_time"]
	if !ok {
		return 0, false
	}

	switch t := v.(type) {
	case int:
		return int64(t), true
	case int8:
		return int64(t), true
	case int16:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case uint:
		if t > math.MaxInt64 {
			return 0, false
		}
		return int64(t), true
	case uint8:
		return int64(t), true
	case uint16:
		return int64(t), true
	case uint32:
		return int64(t), true
	case uint64:
		if t > math.MaxInt64 {
			return 0, false
		}
		return int64(t), true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) || math.Trunc(t) != t || t < 0 || t > math.MaxInt64 {
			return 0, false
		}
		return int64(t), true
	case float32:
		f := float64(t)
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Trunc(f) != f || f < 0 || f > math.MaxInt64 {
			return 0, false
		}
		return int64(f), true
	case json.Number:
		i, err := t.Int64()
		if err == nil {
			return i, true
		}
		f, err := t.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Trunc(f) != f || f < 0 || f > math.MaxInt64 {
			return 0, false
		}
		return int64(f), true
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

// buildWWWAuthenticate constructs a WWW-Authenticate header value per
// RFC 6750 §3 with OIDC step-up extensions.
func buildWWWAuthenticate(s *module.StepUpChallenge) string {
	parts := []string{`Bearer realm="lwauth"`}
	parts = append(parts, `error="insufficient_user_authentication"`)

	if len(s.RequiredACR) > 0 {
		parts = append(parts, fmt.Sprintf(`acr_values="%s"`, strings.Join(s.RequiredACR, " ")))
	}
	if s.MaxAge > 0 {
		parts = append(parts, fmt.Sprintf(`max_age="%d"`, s.MaxAge))
	}
	return strings.Join(parts, ", ")
}

// --- Module registration ---

var knownKeys = map[string]struct{}{
	"rules": {},
}

var knownRuleKeys = map[string]struct{}{
	"match":   {},
	"require": {},
}

var knownMatchKeys = map[string]struct{}{
	"methods": {},
	"paths":   {},
}

var knownRequireKeys = map[string]struct{}{
	"acr":    {},
	"amr":    {},
	"maxAge": {},
}

func factory(name string, raw map[string]any) (module.Authorizer, error) {
	if err := module.CheckUnknownKeys("assurance", name, raw, knownKeys); err != nil {
		return nil, err
	}

	rulesRaw, ok := raw["rules"].([]any)
	if !ok || len(rulesRaw) == 0 {
		return nil, fmt.Errorf("%w: assurance %q: at least one rule is required", module.ErrConfig, name)
	}

	rules, err := parseRules(rulesRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: assurance %q: %v", module.ErrConfig, name, err)
	}

	return &authorizer{name: name, rules: rules}, nil
}

func parseRules(raw []any) ([]Rule, error) {
	var rules []Rule
	for i, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rule[%d]: expected map", i)
		}
		if err := module.CheckUnknownKeys("assurance", fmt.Sprintf("rule[%d]", i), m, knownRuleKeys); err != nil {
			return nil, err
		}
		var rule Rule

		if matchRaw, ok := m["match"].(map[string]any); ok {
			if err := module.CheckUnknownKeys("assurance", fmt.Sprintf("rule[%d].match", i), matchRaw, knownMatchKeys); err != nil {
				return nil, err
			}
			rule.Match = &MatchPredicate{}
			methods, err := parseStringSlice(matchRaw, "methods")
			if err != nil {
				return nil, fmt.Errorf("rule[%d].match: %v", i, err)
			}
			rule.Match.Methods = methods
			paths, err := parseStringSlice(matchRaw, "paths")
			if err != nil {
				return nil, fmt.Errorf("rule[%d].match: %v", i, err)
			}
			rule.Match.Paths = paths
		}

		reqRaw, ok := m["require"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rule[%d]: 'require' is required", i)
		}
		if err := module.CheckUnknownKeys("assurance", fmt.Sprintf("rule[%d].require", i), reqRaw, knownRequireKeys); err != nil {
			return nil, err
		}
		acr, err := parseStringSlice(reqRaw, "acr")
		if err != nil {
			return nil, fmt.Errorf("rule[%d].require: %v", i, err)
		}
		rule.Require.ACR = acr
		amr, err := parseStringSlice(reqRaw, "amr")
		if err != nil {
			return nil, fmt.Errorf("rule[%d].require: %v", i, err)
		}
		rule.Require.AMR = amr
		maxAge, err := parseMaxAge(reqRaw)
		if err != nil {
			return nil, fmt.Errorf("rule[%d].require: %v", i, err)
		}
		rule.Require.MaxAge = maxAge
		if len(rule.Require.ACR) == 0 && len(rule.Require.AMR) == 0 && rule.Require.MaxAge <= 0 {
			return nil, fmt.Errorf("rule[%d].require: at least one of acr, amr, or maxAge>0 is required", i)
		}

		rules = append(rules, rule)
	}
	return rules, nil
}

func parseStringSlice(m map[string]any, key string) ([]string, error) {
	raw, ok := m[key]
	if !ok {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", key)
	}
	out := make([]string, 0, len(items))
	for i, v := range items {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", key, i)
		}
		out = append(out, s)
	}
	return out, nil
}

func parseMaxAge(m map[string]any) (int, error) {
	v, ok := m["maxAge"]
	if !ok {
		return 0, nil
	}
	switch t := v.(type) {
	case int:
		if t < 0 {
			return 0, fmt.Errorf("maxAge must be >= 0")
		}
		return t, nil
	case int8:
		if t < 0 {
			return 0, fmt.Errorf("maxAge must be >= 0")
		}
		return int(t), nil
	case int16:
		if t < 0 {
			return 0, fmt.Errorf("maxAge must be >= 0")
		}
		return int(t), nil
	case int32:
		if t < 0 {
			return 0, fmt.Errorf("maxAge must be >= 0")
		}
		return int(t), nil
	case int64:
		if t < 0 || t > math.MaxInt {
			return 0, fmt.Errorf("maxAge is out of range")
		}
		return int(t), nil
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) || math.Trunc(t) != t || t < 0 || t > math.MaxInt {
			return 0, fmt.Errorf("maxAge must be a non-negative integer")
		}
		return int(t), nil
	case float32:
		f := float64(t)
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Trunc(f) != f || f < 0 || f > math.MaxInt {
			return 0, fmt.Errorf("maxAge must be a non-negative integer")
		}
		return int(f), nil
	default:
		return 0, fmt.Errorf("maxAge must be a non-negative integer")
	}
}

func init() { module.RegisterAuthorizer("assurance", factory) }
