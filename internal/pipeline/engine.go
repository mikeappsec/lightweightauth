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
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/mikeappsec/lightweightauth/internal/cache"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
	"github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
	"github.com/mikeappsec/lightweightauth/pkg/observability/tracing"
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
		decisionCache:  o.DecisionCache,
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

	dec, id, cacheHit, evalErr := e.evaluate(ctx, r)
	e.report(ctx, r, id, dec, cacheHit, evalErr, time.Since(start), span)
	return dec, id, evalErr
}

// evaluate is the stage runner; Evaluate wraps it with observability
// emission. Returns (decision, identity, cacheHit, error).
func (e *Engine) evaluate(ctx context.Context, r *module.Request) (*module.Decision, *module.Identity, bool, error) {
	id, err := e.identifyWithSpan(ctx, r)
	if err != nil {
		return denyFromError(err), nil, false, err
	}
	r.Context["identity"] = id

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

// report fans out the terminal decision to metrics + audit + span.
// Tolerates nil Recorder / Discard sink so tests and embedders pay nothing.
func (e *Engine) report(ctx context.Context, r *module.Request, id *module.Identity,
	dec *module.Decision, cacheHit bool, evalErr error, latency time.Duration, span trace.Span) {

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
	return e.decisionCache.Do(ctx, key, func() (*module.Decision, error) {
		return e.authorizer.Authorize(ctx, r, id)
	})
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
					metrics.Default().ObserveIdentifier(idr.Name(), "no_match")
					continue
				}
				metrics.Default().ObserveIdentifier(idr.Name(), "error")
				lastErr = err
				continue
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
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("%w: no identifier matched", module.ErrInvalidCredential)
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
