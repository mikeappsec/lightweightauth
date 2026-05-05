// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracingIdentifier is an Identifier decorator that wraps Identify with
// an OTel span. It captures the module name, identity subject/source on
// success, and sets error status on failure.
type TracingIdentifier struct {
	inner  Identifier
	tracer trace.Tracer
}

func (t *TracingIdentifier) Name() string { return t.inner.Name() }

func (t *TracingIdentifier) Identify(ctx context.Context, r *Request) (*Identity, error) {
	ctx, span := t.tracer.Start(ctx, "identifier."+t.inner.Name())
	defer span.End()

	id, err := t.inner.Identify(ctx, r)
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

// WithIdentifierTracing returns an IdentifierDecorator that adds OTel
// spans to every Identify call.
func WithIdentifierTracing(tracer trace.Tracer) IdentifierDecorator {
	return func(inner Identifier) Identifier {
		return &TracingIdentifier{inner: inner, tracer: tracer}
	}
}

// TracingAuthorizer is an Authorizer decorator that wraps Authorize
// with an OTel span.
type TracingAuthorizer struct {
	inner  Authorizer
	tracer trace.Tracer
}

func (t *TracingAuthorizer) Name() string { return t.inner.Name() }

func (t *TracingAuthorizer) Authorize(ctx context.Context, r *Request, id *Identity) (*Decision, error) {
	ctx, span := t.tracer.Start(ctx, "authorizer."+t.inner.Name())
	defer span.End()

	dec, err := t.inner.Authorize(ctx, r, id)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if dec != nil {
		span.SetAttributes(
			attribute.Bool("lwauth.decision.allow", dec.Allow),
			attribute.Int("lwauth.decision.status", dec.Status),
		)
	}
	return dec, nil
}

// WithAuthorizerTracing returns an AuthorizerDecorator that adds OTel
// spans to every Authorize call.
func WithAuthorizerTracing(tracer trace.Tracer) AuthorizerDecorator {
	return func(inner Authorizer) Authorizer {
		return &TracingAuthorizer{inner: inner, tracer: tracer}
	}
}

// TracingMutator is a ResponseMutator decorator that wraps Mutate with
// an OTel span.
type TracingMutator struct {
	inner  ResponseMutator
	tracer trace.Tracer
}

func (t *TracingMutator) Name() string { return t.inner.Name() }

func (t *TracingMutator) Mutate(ctx context.Context, r *Request, id *Identity, d *Decision) error {
	ctx, span := t.tracer.Start(ctx, "mutator."+t.inner.Name())
	defer span.End()
	span.SetAttributes(attribute.String("lwauth.mutator", t.inner.Name()))

	if err := t.inner.Mutate(ctx, r, id, d); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// WithMutatorTracing returns a MutatorDecorator that adds OTel spans
// to every Mutate call.
func WithMutatorTracing(tracer trace.Tracer) MutatorDecorator {
	return func(inner ResponseMutator) ResponseMutator {
		return &TracingMutator{inner: inner, tracer: tracer}
	}
}

// MetricsIdentifier is an Identifier decorator that records per-call
// latency and outcome metrics.
type MetricsIdentifier struct {
	inner   Identifier
	observe func(name, outcome string, d time.Duration)
}

func (m *MetricsIdentifier) Name() string { return m.inner.Name() }

func (m *MetricsIdentifier) Identify(ctx context.Context, r *Request) (*Identity, error) {
	start := time.Now()
	id, err := m.inner.Identify(ctx, r)
	outcome := "match"
	if err != nil {
		outcome = "error"
	} else if id == nil {
		outcome = "no_match"
	}
	if m.observe != nil {
		m.observe(m.inner.Name(), outcome, time.Since(start))
	}
	return id, err
}

// WithIdentifierMetrics returns an IdentifierDecorator that calls
// observe after each Identify with the module name, outcome string
// ("match"/"no_match"/"error"), and elapsed duration.
func WithIdentifierMetrics(observe func(name, outcome string, d time.Duration)) IdentifierDecorator {
	return func(inner Identifier) Identifier {
		return &MetricsIdentifier{inner: inner, observe: observe}
	}
}

// MetricsAuthorizer is an Authorizer decorator that records per-call
// latency and outcome metrics.
type MetricsAuthorizer struct {
	inner   Authorizer
	observe func(name, outcome string, d time.Duration)
}

func (m *MetricsAuthorizer) Name() string { return m.inner.Name() }

func (m *MetricsAuthorizer) Authorize(ctx context.Context, r *Request, id *Identity) (*Decision, error) {
	start := time.Now()
	dec, err := m.inner.Authorize(ctx, r, id)
	outcome := "allow"
	if err != nil {
		outcome = "error"
	} else if dec != nil && !dec.Allow {
		outcome = "deny"
	}
	if m.observe != nil {
		m.observe(m.inner.Name(), outcome, time.Since(start))
	}
	return dec, err
}

// WithAuthorizerMetrics returns an AuthorizerDecorator that calls observe
// after each Authorize invocation.
func WithAuthorizerMetrics(observe func(name, outcome string, d time.Duration)) AuthorizerDecorator {
	return func(inner Authorizer) Authorizer {
		return &MetricsAuthorizer{inner: inner, observe: observe}
	}
}
