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
	"fmt"
	"path"
	"strings"

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

	if failed {
		return false, challenge
	}
	return true, nil
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
		var rule Rule

		if matchRaw, ok := m["match"].(map[string]any); ok {
			rule.Match = &MatchPredicate{}
			if methods, ok := matchRaw["methods"].([]any); ok {
				for _, v := range methods {
					if s, ok := v.(string); ok {
						rule.Match.Methods = append(rule.Match.Methods, s)
					}
				}
			}
			if paths, ok := matchRaw["paths"].([]any); ok {
				for _, v := range paths {
					if s, ok := v.(string); ok {
						rule.Match.Paths = append(rule.Match.Paths, s)
					}
				}
			}
		}

		reqRaw, ok := m["require"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rule[%d]: 'require' is required", i)
		}
		if acr, ok := reqRaw["acr"].([]any); ok {
			for _, v := range acr {
				if s, ok := v.(string); ok {
					rule.Require.ACR = append(rule.Require.ACR, s)
				}
			}
		}
		if amr, ok := reqRaw["amr"].([]any); ok {
			for _, v := range amr {
				if s, ok := v.(string); ok {
					rule.Require.AMR = append(rule.Require.AMR, s)
				}
			}
		}
		if v, ok := reqRaw["maxAge"].(float64); ok {
			rule.Require.MaxAge = int(v)
		} else if v, ok := reqRaw["maxAge"].(int); ok {
			rule.Require.MaxAge = v
		}

		rules = append(rules, rule)
	}
	return rules, nil
}

func init() { module.RegisterAuthorizer("assurance", factory) }
