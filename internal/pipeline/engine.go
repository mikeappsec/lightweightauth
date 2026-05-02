// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

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
	"hash/fnv"
	rand2 "math/rand/v2"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/mikeappsec/lightweightauth/internal/cache"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
	"github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
	"github.com/mikeappsec/lightweightauth/pkg/observability/tracing"
	"github.com/mikeappsec/lightweightauth/pkg/ratelimit"
	"github.com/mikeappsec/lightweightauth/pkg/revocation"
)

// Engine is the per-request entry point. Construct via New and never
// mutate after construction.
type Engine struct {
	identifiers []module.Identifier
	authorizer  module.Authorizer // single composite (and/or) at the top
	mutators    []module.ResponseMutator

	// IdentifierMode controls how multiple identifiers compose.
	identifierMode IdentifierMode

	// decisionCache is optional; nil means "no caching".
	decisionCache *cache.Decision

	// rateLimiter is optional; nil means "no rate limiting". Applied
	// at the entry of Evaluate (M11 multi-tenancy hardening).
	rateLimiter *ratelimit.Limiter

	// shadow is true when spec.mode=shadow (D2). The pipeline runs
	// normally but Evaluate always returns allow; disagreements are
	// emitted to metrics and audit.
	shadow bool

	// shadowExpiry is the time after which shadow mode is ignored and
	// the engine enforces normally. Zero means no expiry.
	shadowExpiry time.Time

	// policyVersion is the operator-assigned spec.version tag, carried
	// through to metrics and audit events as policy_version (D2).
	policyVersion string

	// canary is the optional canary authorizer (D3). When non-nil the
	// engine evaluates it concurrently with production and reports the
	// agreement. If canaryEnforce is true, the canary verdict replaces
	// the production verdict.
	canary        module.Authorizer
	canaryEnforce bool
	canaryWeight  int
	canarySample  string

	// revocationStore is optional (E2). When non-nil AND the active
	// identifier implements module.RevocationChecker, the pipeline
	// checks whether the credential is revoked after identification
	// but before authorization. Nil means no revocation checking.
	revocationStore revocation.Store

	// revocationFailOpen controls behaviour when the store is unreachable.
	// When true, the pipeline skips the check (fail-open). When false
	// (default), the pipeline returns 401 on store errors (fail-closed).
	revocationFailOpen bool
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
	// DecisionCache is optional; when non-nil the engine consults it
	// before invoking the authorizer and caches the result.
	DecisionCache *cache.Decision
	// RateLimiter is optional; nil disables rate limiting. The engine
	// calls RateLimiter.Allow(r.TenantID) before any module work; on
	// rejection it returns a 429 deny without consulting modules or
	// the decision cache.
	RateLimiter *ratelimit.Limiter
	// Shadow enables shadow/observe-only mode (D2). The engine runs
	// the full pipeline but always returns allow; disagreements are
	// emitted to metrics and audit.
	Shadow bool
	// ShadowExpiry auto-disables shadow mode after this time.
	ShadowExpiry time.Time
	// PolicyVersion is the operator-assigned spec.version tag.
	PolicyVersion string
	// Canary is the optional canary authorizer (D3). Nil disables.
	Canary module.Authorizer
	// CanaryEnforce makes the canary verdict authoritative (cutover).
	CanaryEnforce bool
	// CanaryWeight is the % of traffic to evaluate (0 = all). Default 100.
	CanaryWeight int
	// CanarySample is the routing strategy ("" = random, "header:X", "hash:sub").
	CanarySample string

	// RevocationStore is optional (E2). When non-nil, the pipeline checks
	// for credential revocation after identification.
	RevocationStore revocation.Store
	// RevocationFailOpen controls behaviour on store errors. When true,
	// revocation check is skipped on errors (fail-open). Default false
	// (fail-closed: return 401).
	RevocationFailOpen bool
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
		identifiers:        o.Identifiers,
		authorizer:         o.Authorizer,
		mutators:           o.Mutators,
		identifierMode:     o.IdentifierMode,
		decisionCache:      o.DecisionCache,
		rateLimiter:        o.RateLimiter,
		shadow:             o.Shadow,
		shadowExpiry:       o.ShadowExpiry,
		policyVersion:      o.PolicyVersion,
		canary:             o.Canary,
		canaryEnforce:      o.CanaryEnforce,
		canaryWeight:       o.CanaryWeight,
		canarySample:       o.CanarySample,
		revocationStore:    o.RevocationStore,
		revocationFailOpen: o.RevocationFailOpen,
	}, nil
}

// DecisionCacheStats returns the live atomic counters of the engine's
// decision cache, or nil if caching is disabled. Used by the
// observability layer to surface cache hits/misses/evictions as
// Prometheus CounterFunc metrics — the values are read at scrape time
// so a hot-reload that builds a new cache simply updates what the
// closure dereferences.
func (e *Engine) DecisionCacheStats() *cache.Stats {
	if e == nil || e.decisionCache == nil {
		return nil
	}
	return e.decisionCache.Stats()
}

// DecisionCacheTieredStats returns the per-layer stats of a two-tier
// decision cache, or nil if the cache is disabled or not tiered (E1).
func (e *Engine) DecisionCacheTieredStats() *cache.TieredStats {
	if e == nil || e.decisionCache == nil {
		return nil
	}
	t := e.decisionCache.TieredBackend()
	if t == nil {
		return nil
	}
	return t.TieredLayerStats()
}

// InvalidateCacheByTags evicts all decision cache entries matching any of
// the given tags. If tags is nil/empty, invalidates all entries.
// Returns the number of evicted entries. (E3)
func (e *Engine) InvalidateCacheByTags(ctx context.Context, tags []string) int {
	if e == nil || e.decisionCache == nil {
		return 0
	}
	if len(tags) == 0 {
		e.decisionCache.InvalidateAll(ctx)
		return -1 // unknown count for full flush
	}
	return e.decisionCache.InvalidateByTags(ctx, tags)
}

// Evaluate runs the full identify → authorize → mutate pipeline.
//
// On allow, the returned Decision has Allow=true and any headers the
// mutators added. On deny, Decision.Allow=false and Status carries the
// HTTP status the server layer should surface (401/403/503).
//
// Observability (M9): every call emits one OTel span tree, one
// lwauth_decisions_total + lwauth_decision_latency_seconds sample, and
// one audit.Event via the package defaults. All three are no-ops when
// not configured, so the cost is a few atomic loads on the hot path.
func (e *Engine) Evaluate(ctx context.Context, r *module.Request) (*module.Decision, *module.Identity, error) {
	start := time.Now()
	if r.Context == nil {
		r.Context = make(map[string]any)
	}

	ctx, span := tracing.Tracer().Start(ctx, "pipeline.Evaluate")
	defer span.End()
	span.SetAttributes(
		attribute.String("lwauth.method", r.Method),
		attribute.String("lwauth.host", r.Host),
		attribute.String("lwauth.path", r.Path),
		attribute.String("lwauth.tenant", r.TenantID),
	)
	if e.policyVersion != "" {
		span.SetAttributes(attribute.String("lwauth.policy_version", e.policyVersion))
	}

	dec, id, cacheHit, evalErr := e.evaluate(ctx, r)

	// D3: canary evaluation — run concurrently with prod (already done),
	// compare verdicts, emit agreement metric + audit fields.
	var canaryAgreement string
	if e.canary != nil && e.shouldCanary(r, id) {
		canaryDec, canaryErr := e.canary.Authorize(ctx, r, id)
		canaryAgreement = e.classifyAgreement(dec, evalErr, canaryDec, canaryErr)
		metrics.Default().ObserveCanaryAgreement(e.policyVersion, r.TenantID, canaryAgreement)
		// If enforce mode, swap canary verdict in as production.
		if e.canaryEnforce && canaryErr == nil && canaryDec != nil {
			dec = canaryDec
			evalErr = nil
			cacheHit = false
		}
	}

	// D2: shadow mode — run pipeline but always allow.
	shadowDisagreement := false
	if e.shadow && !e.shadowExpired() && (evalErr != nil || dec == nil || !dec.Allow) {
		shadowDisagreement = true
		metrics.Default().ObserveShadowDisagreement(e.policyVersion, r.TenantID)
		// Override to allow so upstream traffic is not affected.
		// Security: Do not expose operational mode in reason string on the wire.
		dec = &module.Decision{Allow: true, Status: 200, Reason: ""}
		evalErr = nil
	}

	e.report(ctx, r, id, dec, cacheHit, evalErr, time.Since(start), span, shadowDisagreement, canaryAgreement)

	if shadowDisagreement {
		span.SetAttributes(attribute.Bool("lwauth.shadow_disagreement", true))
	}

	return dec, id, evalErr
}

// evaluate is the stage runner; Evaluate wraps it with observability
// emission. Returns (decision, identity, cacheHit, error).
func (e *Engine) evaluate(ctx context.Context, r *module.Request) (*module.Decision, *module.Identity, bool, error) {
	if e.rateLimiter != nil && !e.rateLimiter.Allow(r.TenantID) {
		metrics.RecordRateLimitDenied(r.TenantID)
		return &module.Decision{
			Allow:  false,
			Status: 429,
			Reason: "rate limit exceeded",
		}, nil, false, nil
	}
	id, err := e.identifyWithSpan(ctx, r)
	if err != nil {
		return denyFromError(err), nil, false, err
	}
	r.Context["identity"] = id

	// E2: Revocation check — runs after identify, before decision cache.
	if e.revocationStore != nil && id != nil {
		if revoked, revErr := e.checkRevocation(ctx, r, id); revoked {
			return &module.Decision{
				Allow:  false,
				Status: 401,
				Reason: "credential revoked",
			}, id, false, revErr
		}
	}

	dec, hit, err := e.runAuthorize(ctx, r, id)
	if err != nil {
		return denyFromError(err), id, false, err
	}
	if dec == nil || !dec.Allow {
		if dec == nil {
			dec = &module.Decision{Allow: false, Status: 403, Reason: "denied"}
		}
		return dec, id, hit, nil
	}

	for _, m := range e.mutators {
		if err := e.mutateWithSpan(ctx, m, r, id, dec); err != nil {
			return denyFromError(err), id, hit, err
		}
	}
	return dec, id, hit, nil
}

// identifyWithSpan wraps identify with an OTel span.
func (e *Engine) identifyWithSpan(ctx context.Context, r *module.Request) (*module.Identity, error) {
	ctx, span := tracing.Tracer().Start(ctx, "pipeline.Identify")
	defer span.End()
	id, err := e.identify(ctx, r)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if id != nil {
		span.SetAttributes(
			attribute.String("lwauth.identity.subject", id.Subject),
			attribute.String("lwauth.identity.source", id.Source),
		)
	}
	return id, nil
}

// mutateWithSpan wraps a single mutator invocation with an OTel span.
func (e *Engine) mutateWithSpan(ctx context.Context, m module.ResponseMutator, r *module.Request, id *module.Identity, d *module.Decision) error {
	ctx, span := tracing.Tracer().Start(ctx, "pipeline.Mutate")
	defer span.End()
	span.SetAttributes(attribute.String("lwauth.mutator", m.Name()))
	if err := m.Mutate(ctx, r, id, d); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// checkRevocation queries the revocation store for the credential's keys.
// Returns (true, nil) if revoked, (false, nil) if not revoked, or handles
// store errors according to the failOpen setting.
func (e *Engine) checkRevocation(ctx context.Context, r *module.Request, id *module.Identity) (bool, error) {
	// Find the identifier that produced this identity and check if it
	// implements RevocationChecker.
	var checker module.RevocationChecker
	for _, ident := range e.identifiers {
		if ident.Name() == id.Source {
			if rc, ok := ident.(module.RevocationChecker); ok {
				checker = rc
			}
			break
		}
	}
	if checker == nil {
		return false, nil
	}

	keys := checker.RevocationKeys(id, r.TenantID)
	if len(keys) == 0 {
		return false, nil
	}

	ctx, span := tracing.Tracer().Start(ctx, "pipeline.RevocationCheck")
	defer span.End()
	span.SetAttributes(attribute.Int("lwauth.revocation.keys_checked", len(keys)))

	for _, key := range keys {
		revoked, err := e.revocationStore.Exists(ctx, key)
		if err != nil {
			span.SetAttributes(attribute.String("lwauth.revocation.error", err.Error()))
			if e.revocationFailOpen {
				// Fail-open: skip check on store error. Emit metric so
				// operators detect this immediately.
				span.SetAttributes(attribute.Bool("lwauth.revocation.fail_open", true))
				metrics.RecordRevocation(r.TenantID, "fail_open")
				return false, nil
			}
			// Fail-closed (default): treat store error as revoked.
			span.SetStatus(codes.Error, "revocation store error")
			metrics.RecordRevocation(r.TenantID, "fail_closed")
			return true, nil
		}
		if revoked {
			span.SetAttributes(
				attribute.String("lwauth.revocation.matched_key", key),
				attribute.Bool("lwauth.revocation.revoked", true),
			)
			metrics.RecordRevocation(r.TenantID, "revoked")
			return true, nil
		}
	}

	metrics.RecordRevocation(r.TenantID, "not_revoked")
	return false, nil
}

// report fans out the terminal decision to metrics + audit + span.
// Tolerates nil Recorder / Discard sink so tests and embedders pay nothing.
func (e *Engine) report(ctx context.Context, r *module.Request, id *module.Identity,
	dec *module.Decision, cacheHit bool, evalErr error, latency time.Duration, span trace.Span, shadowDisagreement bool, canaryAgreement string) {

	outcome := "allow"
	switch {
	case evalErr != nil:
		outcome = "error"
	case dec == nil || !dec.Allow:
		outcome = "deny"
	}

	azName := ""
	if e.authorizer != nil {
		azName = e.authorizer.Name()
	}

	metrics.Default().ObserveDecision(outcome, azName, r.TenantID, latency)

	subject, source := "", ""
	if id != nil {
		subject, source = id.Subject, id.Source
	}
	denyReason := ""
	httpStatus := 200
	if dec != nil {
		denyReason = dec.Reason
		if !dec.Allow {
			httpStatus = dec.Status
		}
	}
	if evalErr != nil && denyReason == "" {
		denyReason = evalErr.Error()
	}

	audit.Default().Record(ctx, &audit.Event{
		Timestamp:      time.Now().UTC(),
		Tenant:         r.TenantID,
		Subject:        subject,
		IdentitySource: source,
		Authorizer:     azName,
		Decision:       outcome,
		DenyReason:     denyReason,
		HTTPStatus:     httpStatus,
		Method:         r.Method,
		Host:           r.Host,
		Path:           r.Path,
		LatencyMs:      float64(latency.Microseconds()) / 1000.0,
		CacheHit:       cacheHit,
		TraceID:        tracing.TraceIDFromContext(ctx),
		PolicyVersion:      e.policyVersion,
		ShadowDisagreement: shadowDisagreement,
		CanaryAgreement:    canaryAgreement,
	})

	span.SetAttributes(
		attribute.String("lwauth.decision", outcome),
		attribute.Bool("lwauth.cache_hit", cacheHit),
	)
	if evalErr != nil {
		span.SetStatus(codes.Error, evalErr.Error())
	}
}

// runAuthorize calls the configured authorizer, optionally going through
// the decision cache. The bool return indicates a cache hit (useful for
// tests and metrics).
func (e *Engine) runAuthorize(ctx context.Context, r *module.Request, id *module.Identity) (*module.Decision, bool, error) {
	if e.decisionCache == nil {
		dec, err := e.authorizer.Authorize(ctx, r, id)
		return dec, false, err
	}
	key := e.decisionCache.Key(r, id)
	tags := e.deriveCacheTags(r, id)
	return e.decisionCache.Do(ctx, key, tags, func() (*module.Decision, error) {
		return e.authorizer.Authorize(ctx, r, id)
	})
}

// deriveCacheTags produces the tag set for a cache entry. Tags enable
// targeted invalidation (E3): e.g. invalidate all entries for tenant "acme"
// or subject "user:42" without flushing the entire cache.
func (e *Engine) deriveCacheTags(r *module.Request, id *module.Identity) []string {
	var tags []string
	if r.TenantID != "" {
		tags = append(tags, "tenant:"+r.TenantID)
	}
	if id != nil && id.Subject != "" {
		tags = append(tags, "subject:"+id.Subject)
	}
	if e.policyVersion != "" {
		tags = append(tags, "policy_version:"+e.policyVersion)
	}
	return tags
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
		// Security: only ErrNoMatch falls through. The error taxonomy
		// in pkg/module/errors.go documents that ErrInvalidCredential
		// "stops trying further identifiers"; this loop honours that
		// contract for every non-ErrNoMatch outcome so a request with
		// an *invalid* DPoP / mTLS / HMAC credential cannot silently
		// downgrade to a weaker later identifier (plain JWT, API key,
		// ...) and authenticate that way.
		//
		//   - ErrNoMatch         -> identifier didn't apply, try next.
		//   - any other error    -> terminal; the request is rejected.
		//   - id != nil          -> success; return the match.
		//   - id == nil, err nil -> identifier abstained, try next.
		//
		// Deployments that genuinely need "try the next identifier on
		// invalid credential" (e.g. running two JWT issuers in
		// parallel during a migration) should compose the two behind a
		// single identifier or use AllMust mode — it must not be the
		// silent default.
		for _, idr := range e.identifiers {
			id, err := idr.Identify(ctx, r)
			if err != nil {
				if errors.Is(err, module.ErrNoMatch) {
					metrics.Default().ObserveIdentifier(idr.Name(), "no_match")
					continue
				}
				metrics.Default().ObserveIdentifier(idr.Name(), "error")
				return nil, err
			}
			if id != nil {
				if id.Source == "" {
					id.Source = idr.Name()
				}
				metrics.Default().ObserveIdentifier(idr.Name(), "match")
				return id, nil
			}
			metrics.Default().ObserveIdentifier(idr.Name(), "no_match")
		}
		return nil, fmt.Errorf("%w: no identifier matched", module.ErrInvalidCredential)
	}
}

// shadowExpired returns true if shadowExpiry is set and has passed.
func (e *Engine) shadowExpired() bool {
	return !e.shadowExpiry.IsZero() && time.Now().After(e.shadowExpiry)
}

// shouldCanary returns true if this request should be evaluated by the
// canary authorizer based on weight/sample config.
func (e *Engine) shouldCanary(r *module.Request, id *module.Identity) bool {
	switch {
	case e.canarySample != "" && len(e.canarySample) > 7 && e.canarySample[:7] == "header:":
		// Route requests carrying the named header to canary.
		hdr := e.canarySample[7:]
		_, ok := r.Headers[hdr]
		return ok
	case e.canarySample == "hash:sub" && id != nil && id.Subject != "":
		// Sticky by subject hash — FNV-1a for uniform distribution.
		h := fnv.New32a()
		h.Write([]byte(id.Subject))
		return int(h.Sum32()%100) < e.canaryWeight
	default:
		// Random by weight using a proper PRNG.
		if e.canaryWeight <= 0 || e.canaryWeight >= 100 {
			return true
		}
		return rand2.IntN(100) < e.canaryWeight
	}
}

// classifyAgreement compares production and canary verdicts into one of:
// "match", "prod_allow_canary_deny", "prod_deny_canary_allow".
func (e *Engine) classifyAgreement(prodDec *module.Decision, prodErr error, canaryDec *module.Decision, canaryErr error) string {
	prodAllow := prodErr == nil && prodDec != nil && prodDec.Allow
	canaryAllow := canaryErr == nil && canaryDec != nil && canaryDec.Allow
	switch {
	case prodAllow == canaryAllow:
		return "match"
	case prodAllow && !canaryAllow:
		return "prod_allow_canary_deny"
	default:
		return "prod_deny_canary_allow"
	}
}

// HTTPMounts returns every (prefix, handler) pair registered by modules
// that implement module.HTTPMounter. Used by the HTTP server to expose
// flow endpoints like /oauth2/start. Each prefix appears at most once;
// duplicates are caller-visible (returned as-is) so the server can warn.
func (e *Engine) HTTPMounts() []module.HTTPMounter {	var out []module.HTTPMounter
	walk := func(v any) {
		if m, ok := v.(module.HTTPMounter); ok {
			out = append(out, m)
		}
	}
	for _, i := range e.identifiers {
		walk(i)
	}
	walk(e.authorizer)
	for _, m := range e.mutators {
		walk(m)
	}
	return out
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
