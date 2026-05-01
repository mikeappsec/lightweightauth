package config

import (
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mikeappsec/lightweightauth/internal/cache"
	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/ratelimit"
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
	var lim *ratelimit.Limiter
	if ac.RateLimit != nil {
		var err error
		lim, err = ratelimit.New(*ac.RateLimit)
		if err != nil {
			return nil, fmt.Errorf("%w: rateLimit: %v", module.ErrConfig, err)
		}
	}
	var canaryAz module.Authorizer
	var canaryEnforce bool
	var canaryWeight int
	var canarySample string
	if ac.Canary != nil {
		// CAN2: Validate weight in [1, 100].
		if ac.Canary.Weight < 1 || ac.Canary.Weight > 100 {
			return nil, fmt.Errorf("%w: canary.weight must be 1-100, got %d", module.ErrConfig, ac.Canary.Weight)
		}
		// CAN4: Validate sample against recognized values.
		switch {
		case ac.Canary.Sample == "":
		case ac.Canary.Sample == "hash:sub":
		case len(ac.Canary.Sample) > 7 && ac.Canary.Sample[:7] == "header:":
		default:
			return nil, fmt.Errorf("%w: canary.sample must be \"\", \"hash:sub\", or \"header:<name>\"; got %q", module.ErrConfig, ac.Canary.Sample)
		}
		// CAN3: Reject header-based routing with enforce (client-controllable).
		if ac.Canary.Enforce && len(ac.Canary.Sample) > 7 && ac.Canary.Sample[:7] == "header:" {
			return nil, fmt.Errorf("%w: canary.enforce with sample=\"header:*\" is unsafe — clients can self-select into enforced canary", module.ErrConfig)
		}
		// CAN1: Require enforceAfter when enforce is true.
		if ac.Canary.Enforce {
			if ac.Canary.EnforceAfter == "" {
				return nil, fmt.Errorf("%w: canary.enforce requires canary.enforceAfter (RFC3339) to ensure minimum observation period", module.ErrConfig)
			}
			eat, err := time.Parse(time.RFC3339, ac.Canary.EnforceAfter)
			if err != nil {
				return nil, fmt.Errorf("%w: canary.enforceAfter: %v", module.ErrConfig, err)
			}
			if time.Now().Before(eat) {
				// Not yet past the enforce-after time — downgrade to observe-only.
				canaryEnforce = false
			} else {
				canaryEnforce = true
			}
		}
		az, err := module.BuildAuthorizer(ac.Canary.Authorizer.Type, ac.Canary.Authorizer.Name, ac.Canary.Authorizer.Config)
		if err != nil {
			return nil, fmt.Errorf("canary authorizer %q: %w", ac.Canary.Authorizer.Name, err)
		}
		canaryAz = az
		canaryWeight = ac.Canary.Weight
		canarySample = ac.Canary.Sample
	}

	// PM1: Parse shadowExpiry and enforce that shadow mode requires it.
	var shadowExpiry time.Time
	if ac.Mode.IsShadow() {
		if ac.ShadowExpiry == "" {
			return nil, fmt.Errorf("%w: mode=shadow requires shadowExpiry (RFC3339) to prevent permanent bypass", module.ErrConfig)
		}
		t, err := time.Parse(time.RFC3339, ac.ShadowExpiry)
		if err != nil {
			return nil, fmt.Errorf("%w: shadowExpiry: %v", module.ErrConfig, err)
		}
		shadowExpiry = t
	}

	return pipeline.New(pipeline.Options{
		Identifiers:    idents,
		Authorizer:     top,
		Mutators:       muts,
		IdentifierMode: mode,
		DecisionCache:  dc,
		RateLimiter:    lim,
		Shadow:         ac.Mode.IsShadow(),
		ShadowExpiry:   shadowExpiry,
		PolicyVersion:  ac.Version,
		Canary:         canaryAz,
		CanaryEnforce:  canaryEnforce,
		CanaryWeight:   canaryWeight,
		CanarySample:   canarySample,
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
		Backend: cache.BackendSpec{
			Type:      spec.Backend,
			Addr:      spec.Addr,
			Username:  spec.Username,
			Password:  spec.Password,
			KeyPrefix: spec.KeyPrefix,
			TLS:       spec.TLS,
		},
	})
}
