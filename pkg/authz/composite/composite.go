// Package composite is the all-of / any-of authorizer that lets operators
// mix RBAC, OPA, CEL, and ReBAC in a single AuthConfig (DESIGN.md §5).
//
// Config shape:
//
//	authorizers:
//	  - name: combined
//	    type: composite
//	    config:
//	      anyOf:                        # at least one child must allow
//	        - { name: rbac-admin, type: rbac, config: {...} }
//	        - { name: opa,        type: opa,  config: {...} }
//	      # OR
//	      allOf:                        # every child must allow
//	        - { name: rbac, type: rbac, config: {...} }
//	        - { name: cel,  type: cel,  config: {...} }
//
// Exactly one of anyOf / allOf must be set. Children are themselves built
// via module.BuildAuthorizer so composites can nest.
package composite

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/yourorg/lightweightauth/pkg/module"
)

type kind int

const (
	kindAny kind = iota
	kindAll
)

type authorizer struct {
	name     string
	kind     kind
	children []module.Authorizer
}

func (a *authorizer) Name() string { return a.name }

func (a *authorizer) Authorize(ctx context.Context, r *module.Request, id *module.Identity) (*module.Decision, error) {
	switch a.kind {
	case kindAny:
		var lastDeny *module.Decision
		var lastErr error
		var reasons []string
		for _, c := range a.children {
			dec, err := c.Authorize(ctx, r, id)
			if err != nil {
				if errors.Is(err, module.ErrUpstream) {
					// Upstream errors short-circuit: we cannot make a
					// safe allow/deny call if a child can't decide.
					return nil, err
				}
				lastErr = err
				reasons = append(reasons, fmt.Sprintf("%s: %v", c.Name(), err))
				continue
			}
			if dec != nil && dec.Allow {
				return dec, nil
			}
			lastDeny = dec
			if dec != nil && dec.Reason != "" {
				reasons = append(reasons, fmt.Sprintf("%s: %s", c.Name(), dec.Reason))
			}
		}
		if lastDeny == nil {
			lastDeny = &module.Decision{Allow: false, Status: 403}
		}
		lastDeny.Reason = "composite anyOf: " + strings.Join(reasons, "; ")
		if lastDeny.Status == 0 {
			lastDeny.Status = 403
		}
		return lastDeny, lastErr

	case kindAll:
		var merged *module.Decision
		for _, c := range a.children {
			dec, err := c.Authorize(ctx, r, id)
			if err != nil {
				return nil, err
			}
			if dec == nil || !dec.Allow {
				if dec == nil {
					dec = &module.Decision{Allow: false, Status: 403}
				}
				dec.Reason = fmt.Sprintf("composite allOf: %s denied: %s", c.Name(), dec.Reason)
				if dec.Status == 0 {
					dec.Status = 403
				}
				return dec, nil
			}
			merged = mergeAllow(merged, dec)
		}
		if merged == nil {
			// No children — treat as deny rather than implicit allow.
			return &module.Decision{Allow: false, Status: 403, Reason: "composite allOf: no children"}, nil
		}
		return merged, nil
	}
	return nil, fmt.Errorf("%w: composite: unknown kind", module.ErrConfig)
}

// mergeAllow combines two allowed decisions: union the header maps,
// preserve any non-empty reason as a debug breadcrumb.
func mergeAllow(a, b *module.Decision) *module.Decision {
	if a == nil {
		return b
	}
	out := &module.Decision{Allow: true, Status: a.Status}
	if a.ResponseHeaders != nil || b.ResponseHeaders != nil {
		out.ResponseHeaders = map[string]string{}
		for k, v := range a.ResponseHeaders {
			out.ResponseHeaders[k] = v
		}
		for k, v := range b.ResponseHeaders {
			out.ResponseHeaders[k] = v
		}
	}
	if a.UpstreamHeaders != nil || b.UpstreamHeaders != nil {
		out.UpstreamHeaders = map[string]string{}
		for k, v := range a.UpstreamHeaders {
			out.UpstreamHeaders[k] = v
		}
		for k, v := range b.UpstreamHeaders {
			out.UpstreamHeaders[k] = v
		}
	}
	return out
}

// factory builds a composite from a config map. The children are arrays
// of {name, type, config} objects, which we forward to module.BuildAuthorizer.
func factory(name string, raw map[string]any) (module.Authorizer, error) {
	anyOf, hasAny := raw["anyOf"].([]any)
	allOf, hasAll := raw["allOf"].([]any)
	if hasAny == hasAll {
		return nil, fmt.Errorf("%w: composite %q must set exactly one of anyOf / allOf", module.ErrConfig, name)
	}
	srcs := anyOf
	k := kindAny
	if hasAll {
		srcs = allOf
		k = kindAll
	}
	if len(srcs) == 0 {
		return nil, fmt.Errorf("%w: composite %q has empty children", module.ErrConfig, name)
	}
	children := make([]module.Authorizer, 0, len(srcs))
	for i, s := range srcs {
		spec, ok := s.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: composite %q child[%d] is not an object", module.ErrConfig, name, i)
		}
		typ, _ := spec["type"].(string)
		cn, _ := spec["name"].(string)
		cfg, _ := spec["config"].(map[string]any)
		if typ == "" {
			return nil, fmt.Errorf("%w: composite %q child[%d] missing type", module.ErrConfig, name, i)
		}
		if cn == "" {
			cn = fmt.Sprintf("%s-%d", typ, i)
		}
		child, err := module.BuildAuthorizer(typ, cn, cfg)
		if err != nil {
			return nil, fmt.Errorf("composite %q child %q: %w", name, cn, err)
		}
		children = append(children, child)
	}
	return &authorizer{name: name, kind: k, children: children}, nil
}

func init() { module.RegisterAuthorizer("composite", factory) }
