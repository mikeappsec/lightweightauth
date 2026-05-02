package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mikeappsec/lightweightauth/internal/cache"
	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/ratelimit"
	"github.com/mikeappsec/lightweightauth/pkg/revocation"
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
	// Warn if multi-tenant config omits "tenant" from cache key fields.
	// Without "tenant" in the key, one tenant's cached decision may serve
	// another tenant's request (cross-tenant data leakage via cache).
	if dc != nil && ac.TenantID != "" && ac.Cache != nil {
		hasTenant := false
		for _, k := range ac.Cache.Key {
			if k == "tenant" {
				hasTenant = true
				break
			}
		}
		if !hasTenant {
			slog.Warn("cache.key omits 'tenant' in a multi-tenant config — cached decisions may be shared across tenants",
				"tenantId", ac.TenantID)
		}
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
		// Validate weight in [1, 100].
		if ac.Canary.Weight < 1 || ac.Canary.Weight > 100 {
			return nil, fmt.Errorf("%w: canary.weight must be 1-100, got %d", module.ErrConfig, ac.Canary.Weight)
		}
		// Validate sample against recognized values.
		switch {
		case ac.Canary.Sample == "":
		case ac.Canary.Sample == "hash:sub":
		case len(ac.Canary.Sample) > 7 && ac.Canary.Sample[:7] == "header:":
		default:
			return nil, fmt.Errorf("%w: canary.sample must be \"\", \"hash:sub\", or \"header:<name>\"; got %q", module.ErrConfig, ac.Canary.Sample)
		}
		// Reject header-based routing with enforce (client-controllable).
		if ac.Canary.Enforce && len(ac.Canary.Sample) > 7 && ac.Canary.Sample[:7] == "header:" {
			return nil, fmt.Errorf("%w: canary.enforce with sample=\"header:*\" is unsafe — clients can self-select into enforced canary", module.ErrConfig)
		}
		// Require enforceAfter when enforce is true.
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

	// Parse shadowExpiry and enforce that shadow mode requires it.
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

	// E2: Build revocation store (opt-in).
	revStore, revFailOpen, err := buildRevocationStore(ac.Revocation)
	if err != nil {
		return nil, err
	}

	return pipeline.New(pipeline.Options{
		Identifiers:        idents,
		Authorizer:         top,
		Mutators:           muts,
		IdentifierMode:     mode,
		DecisionCache:      dc,
		RateLimiter:        lim,
		Shadow:             ac.Mode.IsShadow(),
		ShadowExpiry:       shadowExpiry,
		PolicyVersion:      ac.Version,
		Canary:             canaryAz,
		CanaryEnforce:      canaryEnforce,
		CanaryWeight:       canaryWeight,
		CanarySample:       canarySample,
		RevocationStore:    revStore,
		RevocationFailOpen: revFailOpen,
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

	backend := spec.Backend
	// "tiered" is handled specially: we build L1 + L2 ourselves and
	// pass a pre-built tiered.Backend into the Decision cache.
	if backend == "tiered" {
		l1Size := spec.L1Size
		if l1Size <= 0 {
			l1Size = 10_000
		}
		tieredBackend, tieredStats, aggStats, err := buildTieredBackend(l1Size, spec)
		if err != nil {
			return nil, err
		}
		return cache.NewDecisionWithTiered(cache.DecisionOptions{
			PositiveTTL: pos,
			NegativeTTL: neg,
			KeyFields:   spec.Key,
		}, tieredBackend, tieredStats, aggStats)
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

// buildTieredBackend constructs the L1+L2 tiered backend.
func buildTieredBackend(l1Size int, spec *CacheSpec) (*cache.Tiered, *cache.TieredStats, *cache.Stats, error) {
	l1Stats := &cache.Stats{}
	l1, err := cache.NewLRU(l1Size, 0, l1Stats)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: cache.tiered.l1: %v", module.ErrConfig, err)
	}
	l2Stats := &cache.Stats{}
	l2, err := cache.BuildBackend(cache.BackendSpec{
		Type:      "valkey",
		Addr:      spec.Addr,
		Username:  spec.Username,
		Password:  spec.Password,
		KeyPrefix: spec.KeyPrefix,
		TLS:       spec.TLS,
	}, l2Stats)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: cache.tiered.l2: %v", module.ErrConfig, err)
	}
	tieredStats := &cache.TieredStats{}
	aggStats := &cache.Stats{}
	tiered, err := cache.NewTiered(cache.TieredOptions{
		L1:       l1,
		L2:       l2,
		Stats:    tieredStats,
		AggStats: aggStats,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: cache.tiered: %v", module.ErrConfig, err)
	}
	return tiered, tieredStats, aggStats, nil
}

// buildRevocationStore constructs the revocation store from the spec (E2).
// Returns (nil, false, nil) when revocation is disabled.
func buildRevocationStore(spec *RevocationSpec) (revocation.Store, bool, error) {
	if spec == nil || !spec.Enabled {
		return nil, false, nil
	}

	failOpen := spec.OnStoreError == "allow"

	defaultTTL := 24 * time.Hour
	if spec.DefaultTTL != "" {
		d, err := time.ParseDuration(spec.DefaultTTL)
		if err != nil {
			return nil, false, fmt.Errorf("%w: revocation.defaultTTL: %v", module.ErrConfig, err)
		}
		defaultTTL = d
	}

	negCacheTTL := 2 * time.Second
	if spec.NegCacheTTL != "" {
		d, err := time.ParseDuration(spec.NegCacheTTL)
		if err != nil {
			return nil, false, fmt.Errorf("%w: revocation.negCacheTTL: %v", module.ErrConfig, err)
		}
		negCacheTTL = d
	}

	var store revocation.Store

	switch spec.Backend {
	case "", "memory":
		store = revocation.NewMemoryStore(revocation.WithDefaultTTL(defaultTTL))
	case "valkey":
		if spec.Addr == "" {
			return nil, false, fmt.Errorf("%w: revocation.addr is required for backend=valkey", module.ErrConfig)
		}
		vs, err := revocation.NewValkeyStore(revocation.ValkeyConfig{
			Addr:       spec.Addr,
			Username:   spec.Username,
			Password:   spec.Password,
			TLS:        spec.TLS,
			KeyPrefix:  spec.KeyPrefix,
			DefaultTTL: defaultTTL,
		})
		if err != nil {
			return nil, false, fmt.Errorf("revocation: %w", err)
		}
		store = vs
	default:
		return nil, false, fmt.Errorf("%w: revocation.backend: unknown %q (want \"memory\" or \"valkey\")", module.ErrConfig, spec.Backend)
	}

	// Wrap with negative cache for the Valkey backend to reduce network hops.
	if spec.Backend == "valkey" {
		store = revocation.NewNegCache(store, revocation.WithNegCacheTTL(negCacheTTL))
	}

	return store, failOpen, nil
}
