package config

import (
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yourorg/lightweightauth/internal/cache"
	"github.com/yourorg/lightweightauth/internal/pipeline"
	"github.com/yourorg/lightweightauth/pkg/module"
)

// Source produces successive AuthConfig snapshots. The server layer
// subscribes to a Source, hands each snapshot to Compile, and atomically
// swaps the resulting Engine. See DESIGN.md §6.
type Source interface {
	// Watch streams snapshots until ctx is cancelled. The first snapshot
	// MUST be sent before Watch returns nil.
	Watch(ctx context.Context, out chan<- []AuthConfig) error
}

// LoadFile reads a single YAML file as one AuthConfig. Used by the local /
// dev mode (M1).
func LoadFile(path string) (*AuthConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var ac AuthConfig
	if err := yaml.Unmarshal(b, &ac); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &ac, nil
}

// Compile turns an AuthConfig into a runnable pipeline.Engine using the
// compile-time module registry. Every error here is fatal for *this*
// snapshot; the previous Engine keeps serving (handled by the caller).
func Compile(ac *AuthConfig) (*pipeline.Engine, error) {
	if ac == nil {
		return nil, fmt.Errorf("%w: nil AuthConfig", module.ErrConfig)
	}

	idents := make([]module.Identifier, 0, len(ac.Identifiers))
	for _, spec := range ac.Identifiers {
		m, err := module.BuildIdentifier(spec.Type, spec.Name, spec.Config)
		if err != nil {
			return nil, fmt.Errorf("identifier %q: %w", spec.Name, err)
		}
		idents = append(idents, m)
	}

	if len(ac.Authorizers) == 0 {
		return nil, fmt.Errorf("%w: no authorizers configured", module.ErrConfig)
	}
	// First authorizer is the top-level. Composite authorizers are spelled
	// in config (type: composite) and built by their own factory.
	top, err := module.BuildAuthorizer(ac.Authorizers[0].Type, ac.Authorizers[0].Name, ac.Authorizers[0].Config)
	if err != nil {
		return nil, fmt.Errorf("authorizer %q: %w", ac.Authorizers[0].Name, err)
	}

	muts := make([]module.ResponseMutator, 0, len(ac.Response))
	for _, spec := range ac.Response {
		m, err := module.BuildMutator(spec.Type, spec.Name, spec.Config)
		if err != nil {
			return nil, fmt.Errorf("mutator %q: %w", spec.Name, err)
		}
		muts = append(muts, m)
	}

	mode := pipeline.FirstMatch
	if ac.Identifier == IdentifierAllMust {
		mode = pipeline.AllMust
	}

	dc, err := buildDecisionCache(ac.Cache)
	if err != nil {
		return nil, err
	}
	return pipeline.New(pipeline.Options{
		Identifiers:    idents,
		Authorizer:     top,
		Mutators:       muts,
		IdentifierMode: mode,
		DecisionCache:  dc,
	})
}

// buildDecisionCache turns the YAML CacheSpec into a *cache.Decision. A
// nil spec or zero TTL disables caching.
func buildDecisionCache(spec *CacheSpec) (*cache.Decision, error) {
	if spec == nil || spec.TTL == "" {
		return nil, nil
	}
	pos, err := time.ParseDuration(spec.TTL)
	if err != nil {
		return nil, fmt.Errorf("%w: cache.ttl: %v", module.ErrConfig, err)
	}
	if pos <= 0 {
		return nil, nil
	}
	var neg time.Duration
	if spec.NegativeTTL != "" {
		neg, err = time.ParseDuration(spec.NegativeTTL)
		if err != nil {
			return nil, fmt.Errorf("%w: cache.negativeTtl: %v", module.ErrConfig, err)
		}
	}
	return cache.NewDecision(cache.DecisionOptions{
		PositiveTTL: pos,
		NegativeTTL: neg,
		KeyFields:   spec.Key,
	})
}
