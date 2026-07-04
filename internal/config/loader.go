// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mikeappsec/lightweightauth/internal/cache"
	cachevalkey "github.com/mikeappsec/lightweightauth/internal/cache/valkey"
	"github.com/mikeappsec/lightweightauth/internal/pipeline"
	pkgcache "github.com/mikeappsec/lightweightauth/pkg/cache"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
	"github.com/mikeappsec/lightweightauth/pkg/ratelimit"
	"github.com/mikeappsec/lightweightauth/pkg/revocation"
	"github.com/mikeappsec/lightweightauth/pkg/secrets"
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

	// G1: resolve external secret references in module configs.
	if ac.Secrets != nil {
		resolver, err := buildSecretResolver(ac.Secrets)
		if err != nil {
			return nil, fmt.Errorf("%w: secrets: %v", module.ErrConfig, err)
		}
		defer resolver.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := resolveModuleSecrets(ctx, resolver, ac.Identifiers); err != nil {
			return nil, fmt.Errorf("%w: resolve identifier secrets: %v", module.ErrConfig, err)
		}
		if err := resolveModuleSecrets(ctx, resolver, ac.Authorizers); err != nil {
			return nil, fmt.Errorf("%w: resolve authorizer secrets: %v", module.ErrConfig, err)
		}
		if err := resolveModuleSecrets(ctx, resolver, ac.Response); err != nil {
			return nil, fmt.Errorf("%w: resolve mutator secrets: %v", module.ErrConfig, err)
		}
		// Resolve cache password if it's a secretRef.
		if ac.Cache != nil && secrets.IsSecretRef(ac.Cache.Password) {
			val, err := resolver.ResolveString(ctx, ac.Cache.Password)
			if err != nil {
				return nil, fmt.Errorf("%w: resolve cache.password: %v", module.ErrConfig, err)
			}
			ac.Cache.Password = val
		}
		if ac.Cache != nil && secrets.IsSecretRef(ac.Cache.SharedHMACKey) {
			val, err := resolver.ResolveString(ctx, ac.Cache.SharedHMACKey)
			if err != nil {
				return nil, fmt.Errorf("%w: resolve cache.sharedHmacKey: %v", module.ErrConfig, err)
			}
			ac.Cache.SharedHMACKey = val
		}
		// Resolve revocation password if it's a secretRef.
		if ac.Revocation != nil && secrets.IsSecretRef(ac.Revocation.Password) {
			val, err := resolver.ResolveString(ctx, ac.Revocation.Password)
			if err != nil {
				return nil, fmt.Errorf("%w: resolve revocation.password: %v", module.ErrConfig, err)
			}
			ac.Revocation.Password = val
		}
		// Resolve cache pool passwords if they're secretRefs.
		for i := range ac.Caches {
			if secrets.IsSecretRef(ac.Caches[i].Password) {
				val, err := resolver.ResolveString(ctx, ac.Caches[i].Password)
				if err != nil {
					return nil, fmt.Errorf("%w: resolve caches[%q].password: %v", module.ErrConfig, ac.Caches[i].Name, err)
				}
				ac.Caches[i].Password = val
			}
		}
	}

	// P3: build the module-native cache pools from the caches: block. When
	// no pools are declared an implicit in-memory "default" pool is
	// synthesized, so configs that predate this block are unaffected.
	pools, err := buildCachePools(ac)
	if err != nil {
		return nil, err
	}

	// Fail fast on undeclared cache-pool references before constructing any
	// module. Module construction may perform network I/O (e.g. the jwt
	// identifier fetches its JWKS), so a typo'd cache.pool must error here
	// rather than after a half-built engine.
	referenced, err := referencedPools(ac)
	if err != nil {
		return nil, err
	}
	if err := pkgcache.ValidatePools(poolNames(ac.Caches), referenced); err != nil {
		return nil, fmt.Errorf("%w: %v", module.ErrConfig, err)
	}

	// Engine-lifecycle context: handed to modules via module.Deps.Ctx so
	// their background goroutines (JWKS pollers, refreshers) are bound to the
	// engine's lifetime. Engine.Close cancels it on hot-reload swap. We
	// cancel here only on the error paths below (engineOK stays false).
	engCtx, engCancel := context.WithCancel(context.Background())
	engineOK := false
	defer func() {
		if !engineOK {
			engCancel()
		}
	}()

	logger := slog.Default()
	// depsFor builds the dependency bundle for one module instance. kind is a
	// short namespace discriminator ("i", "a", "m") so identifiers,
	// authorizers, and mutators that share a type/name never collide on cache
	// keys. pool is the module's selected cache pool (from its cache.pool
	// selector); an empty value falls back to the implicit default pool.
	depsFor := func(kind, typ, name, pool string) module.Deps {
		return module.Deps{
			Caches: pools.For(kind+"/"+typ+"/"+name, pool, nil),
			Logger: logger,
			Ctx:    engCtx,
		}
	}

	idents := make([]module.Identifier, 0, len(ac.Identifiers))
	for _, spec := range ac.Identifiers {
		pool, cfg, err := extractPoolSelector(spec.Config)
		if err != nil {
			return nil, fmt.Errorf("identifier %q: %w", spec.Name, err)
		}
		m, err := module.BuildIdentifierWithDeps(spec.Type, spec.Name, cfg, depsFor("i", spec.Type, spec.Name, pool))
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
	topPool, topCfg, err := extractPoolSelector(ac.Authorizers[0].Config)
	if err != nil {
		return nil, fmt.Errorf("authorizer %q: %w", ac.Authorizers[0].Name, err)
	}
	top, err := module.BuildAuthorizerWithDeps(ac.Authorizers[0].Type, ac.Authorizers[0].Name, topCfg, depsFor("a", ac.Authorizers[0].Type, ac.Authorizers[0].Name, topPool))
	if err != nil {
		return nil, fmt.Errorf("authorizer %q: %w", ac.Authorizers[0].Name, err)
	}

	muts := make([]module.ResponseMutator, 0, len(ac.Response))
	for _, spec := range ac.Response {
		pool, cfg, err := extractPoolSelector(spec.Config)
		if err != nil {
			return nil, fmt.Errorf("mutator %q: %w", spec.Name, err)
		}
		m, err := module.BuildMutatorWithDeps(spec.Type, spec.Name, cfg, depsFor("m", spec.Type, spec.Name, pool))
		if err != nil {
			return nil, fmt.Errorf("mutator %q: %w", spec.Name, err)
		}
		muts = append(muts, m)
	}

	mode := pipeline.FirstMatch
	if ac.Identifier == IdentifierAllMust {
		mode = pipeline.AllMust
	}

	dc, err := buildDecisionCache(ac.Cache, pools)
	if err != nil {
		return nil, err
	}
	// Security hardening: reject config when multi-tenant mode is active but
	// "tenant" is missing from cache key fields. Without "tenant" in the key,
	// one tenant's cached decision may serve another tenant's request.
	if dc != nil && ac.TenantID != "" && ac.Cache != nil {
		hasTenant := false
		for _, k := range ac.Cache.Key {
			if k == "tenant" {
				hasTenant = true
				break
			}
		}
		if !hasTenant {
			return nil, fmt.Errorf("%w: cache.key must include 'tenant' when tenantId is configured to prevent cross-tenant cache sharing",
				module.ErrConfig)
		}
	}
	var lim *ratelimit.Limiter
	if ac.RateLimit != nil {
		var err error
		lim, err = ratelimit.New(*ac.RateLimit)
		if err != nil {
			return nil, fmt.Errorf("%w: rateLimit: %v", module.ErrConfig, err)
		}
		ratelimit.LogUnlimitedOverrides(slog.Default(), *ac.RateLimit)
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
		canaryPool, canaryCfg, err := extractPoolSelector(ac.Canary.Authorizer.Config)
		if err != nil {
			return nil, fmt.Errorf("canary authorizer %q: %w", ac.Canary.Authorizer.Name, err)
		}
		az, err := module.BuildAuthorizerWithDeps(ac.Canary.Authorizer.Type, ac.Canary.Authorizer.Name, canaryCfg, depsFor("a", ac.Canary.Authorizer.Type, ac.Canary.Authorizer.Name, canaryPool))
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
	revStore, revFailOpen, err := buildRevocationStore(ac.Revocation, pools)
	if err != nil {
		return nil, err
	}

	eng, err := pipeline.New(pipeline.Options{
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
		LifecycleCancel:    engCancel,
	})
	if err != nil {
		return nil, err
	}
	// Ownership of engCancel transfers to the Engine; it cancels engCtx on
	// Close. Suppress the deferred error-path cancel.
	engineOK = true
	return eng, nil
}

// extractPoolSelector pulls an optional cache.pool selector out of a module
// config. The loader owns pool selection, so it returns a copy of the config
// with the "cache" key stripped — modules never see it and their
// CheckUnknownKeys guards stay intact. A module with no cache block (or no
// cache.pool) selects the implicit default pool (empty pool name).
func extractPoolSelector(cfg map[string]any) (pool string, cleaned map[string]any, err error) {
	raw, ok := cfg["cache"]
	if !ok {
		return "", cfg, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("%w: cache: must be a mapping of pool/ttl settings", module.ErrConfig)
	}
	if p, ok := m["pool"]; ok {
		s, ok := p.(string)
		if !ok {
			return "", nil, fmt.Errorf("%w: cache.pool must be a string", module.ErrConfig)
		}
		pool = strings.TrimSpace(s)
	}
	cleaned = make(map[string]any, len(cfg))
	for k, v := range cfg {
		if k == "cache" {
			continue
		}
		cleaned[k] = v
	}
	return pool, cleaned, nil
}

// poolNames returns the declared pool names from the caches: block. The
// implicit "default" pool is always considered declared by ValidatePools, so
// it need not appear here.
func poolNames(caches []CachePoolSpec) []string {
	out := make([]string, 0, len(caches))
	for _, p := range caches {
		out = append(out, p.Name)
	}
	return out
}

// referencedPools collects every cache pool named by a module's cache.pool
// selector across identifiers, the top + canary authorizers, and response
// mutators. It powers fail-fast validation against the declared pools.
func referencedPools(ac *AuthConfig) ([]string, error) {
	var refs []string
	add := func(kind, name string, cfg map[string]any) error {
		pool, _, err := extractPoolSelector(cfg)
		if err != nil {
			return fmt.Errorf("%s %q: %w", kind, name, err)
		}
		if pool != "" {
			refs = append(refs, pool)
		}
		return nil
	}
	for _, s := range ac.Identifiers {
		if err := add("identifier", s.Name, s.Config); err != nil {
			return nil, err
		}
	}
	if len(ac.Authorizers) > 0 {
		if err := add("authorizer", ac.Authorizers[0].Name, ac.Authorizers[0].Config); err != nil {
			return nil, err
		}
	}
	for _, s := range ac.Response {
		if err := add("mutator", s.Name, s.Config); err != nil {
			return nil, err
		}
	}
	if ac.Canary != nil {
		if err := add("canary authorizer", ac.Canary.Authorizer.Name, ac.Canary.Authorizer.Config); err != nil {
			return nil, err
		}
	}
	// The decision cache may draw its backend from a declared pool too.
	if ac.Cache != nil && ac.Cache.Pool != "" {
		refs = append(refs, ac.Cache.Pool)
	}
	// The revocation store may also be routed to a declared pool.
	if ac.Revocation != nil && ac.Revocation.Pool != "" {
		refs = append(refs, ac.Revocation.Pool)
	}
	return refs, nil
}

// buildCachePools maps the operator's caches: block onto pkg/cache pool
// configs and constructs them. A nil/empty list is valid: BuildPools
// synthesizes an implicit in-memory "default" pool so configs that predate
// the module-native cache layer keep working unchanged. Fail-fast validation
// of per-module pool references happens separately in Compile via
// [referencedPools] + cache.ValidatePools.
func buildCachePools(ac *AuthConfig) (*pkgcache.Pools, error) {
	cfgs := make([]pkgcache.PoolConfig, 0, len(ac.Caches))
	for _, p := range ac.Caches {
		cfgs = append(cfgs, pkgcache.PoolConfig{
			Name: p.Name,
			BackendSpec: pkgcache.BackendSpec{
				Type:      p.Backend,
				Size:      p.Size,
				Addr:      p.Addr,
				Username:  p.Username,
				Password:  p.Password,
				KeyPrefix: p.KeyPrefix,
				TLS:       p.TLS,
				MaxTTL:    p.MaxTTL,
				AllowPII:  p.AllowPII,
				Encrypt:   p.Encrypt,
				Codec:     p.Codec,
			},
		})
	}
	pools, err := pkgcache.BuildPools(cfgs)
	if err != nil {
		return nil, fmt.Errorf("%w: caches: %v", module.ErrConfig, err)
	}
	return pools, nil
}

// buildDecisionCache turns the YAML CacheSpec into a *cache.Decision. A
// nil spec or zero TTL disables caching. When spec.Pool is set, the backend
// is drawn from that declared pkg/cache pool (pools) instead of being built
// from the inline backend fields.
func buildDecisionCache(spec *CacheSpec, pools *pkgcache.Pools) (*cache.Decision, error) {
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

	var maxStale time.Duration
	if spec.MaxStaleness != "" {
		maxStale, err = time.ParseDuration(spec.MaxStaleness)
		if err != nil {
			return nil, fmt.Errorf("%w: cache.maxStaleness: %v", module.ErrConfig, err)
		}
	}

	// Pool-routed backend: draw the decision cache's storage from a declared
	// pool instead of building a standalone backend. The pool owns backend
	// infrastructure, so the inline backend fields and the tiered/distributed-
	// singleflight path are mutually exclusive with it.
	if spec.Pool != "" {
		if spec.Backend != "" || spec.Addr != "" || spec.DistributedSingleflight {
			return nil, fmt.Errorf("%w: cache.pool cannot be combined with cache.backend/addr/distributedSingleflight; the pool owns backend infrastructure", module.ErrConfig)
		}
		// pools is non-nil in normal operation (Compile builds it before
		// calling here); guard defensively for direct callers/tests.
		if pools == nil {
			return nil, fmt.Errorf("%w: cache.pool set but no cache pools are configured", module.ErrConfig)
		}
		backend := pools.For("decision", spec.Pool, nil).Cache("decisions")
		return cache.NewDecisionWithBackend(cache.DecisionOptions{
			PositiveTTL:       pos,
			NegativeTTL:       neg,
			KeyFields:         spec.Key,
			ServeStaleOnError: spec.ServeStaleOnError,
			MaxStaleness:      maxStale,
		}, backend, &cache.Stats{})
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

		// E4: build distributed singleflight if enabled.
		var distSF *cache.DistSF
		var sharedKey []byte
		if spec.DistributedSingleflight {
			distSF, sharedKey, err = buildDistSF(spec, tieredBackend)
			if err != nil {
				return nil, err
			}
		}

		return cache.NewDecisionWithTiered(cache.DecisionOptions{
			PositiveTTL:       pos,
			NegativeTTL:       neg,
			KeyFields:         spec.Key,
			ServeStaleOnError: spec.ServeStaleOnError,
			MaxStaleness:      maxStale,
			DistSF:            distSF,
			SharedHMACKey:     sharedKey,
		}, tieredBackend, tieredStats, aggStats)
	}

	return cache.NewDecision(cache.DecisionOptions{
		PositiveTTL:       pos,
		NegativeTTL:       neg,
		KeyFields:         spec.Key,
		ServeStaleOnError: spec.ServeStaleOnError,
		MaxStaleness:      maxStale,
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

// buildDistSF constructs the distributed singleflight coordinator (E4).
// Returns (nil, nil, nil) if configuration is invalid (logged as warning).
func buildDistSF(spec *CacheSpec, tiered *cache.Tiered) (*cache.DistSF, []byte, error) {
	// Parse hold duration.
	var holdDuration time.Duration
	if spec.SFHoldDuration != "" {
		var err error
		holdDuration, err = time.ParseDuration(spec.SFHoldDuration)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: cache.sfHoldDuration: %v", module.ErrConfig, err)
		}
	}

	// Decode shared HMAC key (base64). If absent, generate one per-instance
	// (cross-replica HMAC verification will fail gracefully but each replica
	// still benefits from local dedup via the distributed lock).
	var sharedKey []byte
	if spec.SharedHMACKey != "" {
		var err error
		sharedKey, err = base64.StdEncoding.DecodeString(spec.SharedHMACKey)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: cache.sharedHmacKey: invalid base64: %v", module.ErrConfig, err)
		}
		if len(sharedKey) < 16 {
			return nil, nil, fmt.Errorf("%w: cache.sharedHmacKey: must be at least 16 bytes (128-bit)", module.ErrConfig)
		}
	}

	// The SFLocker needs the Valkey client from the L2 backend.
	l2 := tiered.L2()
	locker := cachevalkey.NewSFLockerFromBackend(l2, spec.KeyPrefix)
	if locker == nil {
		slog.Warn("distributedSingleflight enabled but L2 is not Valkey; falling back to per-pod singleflight")
		return nil, nil, nil
	}

	distSF := cache.NewDistSF(cache.DistSFOptions{
		Locker:       locker,
		L2:           l2,
		HoldDuration: holdDuration,
		OnFallback: func() {
			metrics.RecordCacheDistSF("fallback")
		},
	})
	return distSF, sharedKey, nil
}

// buildRevocationStore constructs the revocation store from the spec (E2).
// Returns (nil, false, nil) when revocation is disabled.
func buildRevocationStore(spec *RevocationSpec, pools *pkgcache.Pools) (revocation.Store, bool, error) {
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

	// Pool routing (P6): fold storage onto a declared pool behind the Store
	// facade. Opt-in and mutually exclusive with the inline backend fields.
	if spec.Pool != "" {
		if spec.Backend != "" || spec.Addr != "" {
			return nil, false, fmt.Errorf("%w: revocation.pool cannot be combined with revocation.backend/addr; the pool owns backend infrastructure", module.ErrConfig)
		}
		if pools == nil {
			return nil, false, fmt.Errorf("%w: revocation.pool set but no cache pools are configured", module.ErrConfig)
		}
		backend := pools.For("revocation", spec.Pool, nil).Cache("revocations")
		store := revocation.Store(revocation.NewCacheStore(backend, defaultTTL))
		// A pool is shared/remote infrastructure, so wrap with the negative
		// cache to spare the hot path a round-trip on the common not-revoked
		// case (Add evicts the local entry, preserving revoke-then-check).
		store = revocation.NewNegCache(store, revocation.WithNegCacheTTL(negCacheTTL))
		return store, failOpen, nil
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

// --- G1: External secret resolver helpers ---

// buildSecretResolver constructs a secrets.Resolver from the SecretsSpec.
func buildSecretResolver(spec *SecretsSpec) (*secrets.Resolver, error) {
	ttl := 5 * time.Minute
	if spec.DefaultTTL != "" {
		d, err := time.ParseDuration(spec.DefaultTTL)
		if err != nil {
			return nil, fmt.Errorf("secrets.defaultTtl: %v", err)
		}
		ttl = d
	}

	return secrets.New(secrets.Options{
		DefaultTTL:     ttl,
		BackendConfigs: spec.Backends,
	}), nil
}

// resolveModuleSecrets walks a slice of ModuleSpecs and resolves any
// string values in their Config maps that look like secret references.
func resolveModuleSecrets(ctx context.Context, resolver *secrets.Resolver, specs []ModuleSpec) error {
	for i := range specs {
		if specs[i].Config == nil {
			continue
		}
		if err := resolveMapSecrets(ctx, resolver, specs[i].Config); err != nil {
			return fmt.Errorf("module %q: %w", specs[i].Name, err)
		}
	}
	return nil
}

// resolveMapSecrets recursively resolves secret references in a config map.
func resolveMapSecrets(ctx context.Context, resolver *secrets.Resolver, m map[string]any) error {
	for k, v := range m {
		switch val := v.(type) {
		case string:
			if secrets.IsSecretRef(val) {
				resolved, err := resolver.ResolveString(ctx, val)
				if err != nil {
					return fmt.Errorf("key %q: %w", k, err)
				}
				m[k] = resolved
			}
		case map[string]any:
			if err := resolveMapSecrets(ctx, resolver, val); err != nil {
				return fmt.Errorf("key %q: %w", k, err)
			}
		case map[any]any:
			// YAML sometimes produces map[any]any; convert and resolve.
			typed := make(map[string]any, len(val))
			for mk, mv := range val {
				typed[fmt.Sprint(mk)] = mv
			}
			if err := resolveMapSecrets(ctx, resolver, typed); err != nil {
				return fmt.Errorf("key %q: %w", k, err)
			}
			m[k] = typed
		}
	}
	return nil
}
