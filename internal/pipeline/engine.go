// Package pipeline composes module.Identifiers, module.Authorizer, and
// module.ResponseMutators into a single Engine that the server layer calls
// per request.
//
// An Engine is immutable. Config reload constructs a new Engine and swaps
// it via atomic.Pointer (see config.Compiler) so live requests never see a
// half-applied config. See docs/ARCHITECTURE.md.
package pipeline

import (
	"context"
	"errors"
	"fmt"

	"github.com/yourorg/lightweightauth/pkg/module"
)

// Engine is the per-request entry point. Construct via New and never
// mutate after construction.
type Engine struct {
	identifiers []module.Identifier
	authorizer  module.Authorizer // single composite (and/or) at the top
	mutators    []module.ResponseMutator

	// IdentifierMode controls how multiple identifiers compose.
	identifierMode IdentifierMode
}

// IdentifierMode controls multi-identifier composition. See DESIGN.md §2.
type IdentifierMode int

const (
	// FirstMatch tries identifiers in order and uses the first one that
	// returns a non-nil Identity (default).
	FirstMatch IdentifierMode = iota
	// AllMust requires every configured identifier to succeed; the
	// produced Identity is the merge of all claims maps.
	AllMust
)

// Options bundle Engine construction options.
type Options struct {
	Identifiers    []module.Identifier
	Authorizer     module.Authorizer
	Mutators       []module.ResponseMutator
	IdentifierMode IdentifierMode
}

// New builds an Engine. Returns an error if required components are missing.
func New(o Options) (*Engine, error) {
	if len(o.Identifiers) == 0 {
		return nil, fmt.Errorf("%w: pipeline needs at least one identifier", module.ErrConfig)
	}
	if o.Authorizer == nil {
		return nil, fmt.Errorf("%w: pipeline needs an authorizer", module.ErrConfig)
	}
	return &Engine{
		identifiers:    o.Identifiers,
		authorizer:     o.Authorizer,
		mutators:       o.Mutators,
		identifierMode: o.IdentifierMode,
	}, nil
}

// Evaluate runs the full identify → authorize → mutate pipeline.
//
// On allow, the returned Decision has Allow=true and any headers the
// mutators added. On deny, Decision.Allow=false and Status carries the
// HTTP status the server layer should surface (401/403/503).
func (e *Engine) Evaluate(ctx context.Context, r *module.Request) (*module.Decision, *module.Identity, error) {
	if r.Context == nil {
		r.Context = make(map[string]any)
	}

	id, err := e.identify(ctx, r)
	if err != nil {
		return denyFromError(err), nil, err
	}
	r.Context["identity"] = id

	dec, err := e.authorizer.Authorize(ctx, r, id)
	if err != nil {
		return denyFromError(err), id, err
	}
	if dec == nil || !dec.Allow {
		if dec == nil {
			dec = &module.Decision{Allow: false, Status: 403, Reason: "denied"}
		}
		return dec, id, nil
	}

	for _, m := range e.mutators {
		if err := m.Mutate(ctx, r, id, dec); err != nil {
			return denyFromError(err), id, err
		}
	}
	return dec, id, nil
}

func (e *Engine) identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	switch e.identifierMode {
	case AllMust:
		merged := &module.Identity{Claims: map[string]any{}, Source: "all"}
		for _, idr := range e.identifiers {
			id, err := idr.Identify(ctx, r)
			if err != nil {
				return nil, err
			}
			if id == nil {
				return nil, fmt.Errorf("%w: identifier %q produced no identity in AllMust mode", module.ErrInvalidCredential, idr.Name())
			}
			if merged.Subject == "" {
				merged.Subject = id.Subject
			}
			for k, v := range id.Claims {
				merged.Claims[k] = v
			}
		}
		return merged, nil
	default: // FirstMatch
		var lastErr error
		for _, idr := range e.identifiers {
			id, err := idr.Identify(ctx, r)
			if err != nil {
				if errors.Is(err, module.ErrNoMatch) {
					continue
				}
				lastErr = err
				continue
			}
			if id != nil {
				if id.Source == "" {
					id.Source = idr.Name()
				}
				return id, nil
			}
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("%w: no identifier matched", module.ErrInvalidCredential)
	}
}

// denyFromError maps a module error to a Decision the server layer can
// translate to an HTTP/gRPC response.
func denyFromError(err error) *module.Decision {
	switch {
	case errors.Is(err, module.ErrInvalidCredential), errors.Is(err, module.ErrNoMatch):
		return &module.Decision{Allow: false, Status: 401, Reason: err.Error()}
	case errors.Is(err, module.ErrForbidden):
		return &module.Decision{Allow: false, Status: 403, Reason: err.Error()}
	case errors.Is(err, module.ErrUpstream):
		return &module.Decision{Allow: false, Status: 503, Reason: err.Error()}
	case errors.Is(err, module.ErrConfig):
		return &module.Decision{Allow: false, Status: 500, Reason: err.Error()}
	default:
		return &module.Decision{Allow: false, Status: 500, Reason: err.Error()}
	}
}
