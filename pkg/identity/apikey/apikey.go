// Package apikey is the default API-key identifier module.
//
// M0 ships an in-memory store; Redis / K8s Secret / external secret
// manager backends are added later milestones. Keys MUST be stored hashed
// (argon2id) — DESIGN.md §4. This in-memory map is for tests/dev only and
// stores plaintext to keep M0 dependency-light; do not ship to production.
package apikey

import (
	"context"

	"github.com/yourorg/lightweightauth/pkg/module"
)

// Config is the YAML/CRD shape.
//
// Two `static` value shapes are accepted:
//
//	static:
//	  k1: alice                              # short form: subject only
//	  k2: { subject: bob, roles: [admin] }   # long form: subject + roles
type Config struct {
	HeaderName string         `yaml:"headerName" json:"headerName"` // default "X-Api-Key"
	Static     map[string]any `yaml:"static" json:"static"`         // key -> subject | {subject, roles}
}

type entry struct {
	subject string
	roles   []string
}

type identifier struct {
	name   string
	header string
	keys   map[string]entry
}

func (i *identifier) Name() string { return i.name }

func (i *identifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	v := r.Header(i.header)
	if v == "" {
		return nil, module.ErrNoMatch
	}
	e, ok := i.keys[v]
	if !ok {
		return nil, module.ErrInvalidCredential
	}
	claims := map[string]any{"sub": e.subject}
	if len(e.roles) > 0 {
		// Use []any so RBAC's `[]any` branch matches.
		rs := make([]any, len(e.roles))
		for i, r := range e.roles {
			rs[i] = r
		}
		claims["roles"] = rs
	}
	return &module.Identity{
		Subject: e.subject,
		Source:  i.name,
		Claims:  claims,
	}, nil
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	hdr := "X-Api-Key"
	if v, ok := raw["headerName"].(string); ok && v != "" {
		hdr = v
	}
	keys := map[string]entry{}
	if v, ok := raw["static"].(map[string]any); ok {
		for k, val := range v {
			switch t := val.(type) {
			case string:
				keys[k] = entry{subject: t}
			case map[string]any:
				e := entry{}
				if s, ok := t["subject"].(string); ok {
					e.subject = s
				}
				if rs, ok := t["roles"].([]any); ok {
					for _, r := range rs {
						if s, ok := r.(string); ok {
							e.roles = append(e.roles, s)
						}
					}
				}
				keys[k] = e
			}
		}
	}
	return &identifier{name: name, header: hdr, keys: keys}, nil
}

func init() { module.RegisterIdentifier("apikey", factory) }
