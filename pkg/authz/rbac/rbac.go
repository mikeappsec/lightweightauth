// Package rbac is the built-in role-based authorizer. Zero-dependency,
// hash-lookup decision path. See DESIGN.md §5.
//
// M0 implements the full data model; later milestones add hot-reload of
// role bindings from external sources.
package rbac

import (
	"context"
	"fmt"

	"github.com/yourorg/lightweightauth/pkg/module"
)

// Config is the YAML/CRD shape.
//
//	type: rbac
//	rolesFrom: claim:roles      # where to read the subject's roles from
//	allow:                       # roles permitted to access this AuthConfig
//	  - admin
//	  - editor
type Config struct {
	RolesFrom string   `yaml:"rolesFrom" json:"rolesFrom"`
	Allow     []string `yaml:"allow" json:"allow"`
}

type authorizer struct {
	name      string
	rolesFrom string
	allow     map[string]struct{}
}

func (a *authorizer) Name() string { return a.name }

func (a *authorizer) Authorize(ctx context.Context, r *module.Request, id *module.Identity) (*module.Decision, error) {
	roles := a.extractRoles(id)
	for _, role := range roles {
		if _, ok := a.allow[role]; ok {
			return &module.Decision{Allow: true}, nil
		}
	}
	return &module.Decision{
		Allow:  false,
		Status: 403,
		Reason: fmt.Sprintf("rbac: subject %q has no allowed role", id.Subject),
	}, nil
}

func (a *authorizer) extractRoles(id *module.Identity) []string {
	if id == nil || id.Claims == nil {
		return nil
	}
	// rolesFrom format: "claim:<name>"
	const prefix = "claim:"
	if len(a.rolesFrom) <= len(prefix) || a.rolesFrom[:len(prefix)] != prefix {
		return nil
	}
	key := a.rolesFrom[len(prefix):]
	v, ok := id.Claims[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
}

func factory(name string, raw map[string]any) (module.Authorizer, error) {
	cfg := Config{RolesFrom: "claim:roles"}
	if v, ok := raw["rolesFrom"].(string); ok && v != "" {
		cfg.RolesFrom = v
	}
	if v, ok := raw["allow"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok {
				cfg.Allow = append(cfg.Allow, s)
			}
		}
	}
	allow := make(map[string]struct{}, len(cfg.Allow))
	for _, r := range cfg.Allow {
		allow[r] = struct{}{}
	}
	return &authorizer{name: name, rolesFrom: cfg.RolesFrom, allow: allow}, nil
}

func init() { module.RegisterAuthorizer("rbac", factory) }
