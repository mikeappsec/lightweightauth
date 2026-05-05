// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package observability provides a unified singleton access point for
// the three observability pillars: metrics, audit logging, and tracing.
//
// Rather than importing three separate packages and calling three
// different Default() functions, pipeline code and modules can use:
//
//	obs := observability.Get()
//	obs.Metrics().RecordDecision(...)
//	obs.Audit().Emit(ctx, event)
//	span := obs.Tracer().Start(ctx, "my-op")
//
// The singleton is configured once at startup via Configure(). Before
// Configure is called, Get() returns a no-op facade that silently
// discards all events (safe for tests and library use).
package observability

import (
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/trace"

	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
	"github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
	"github.com/mikeappsec/lightweightauth/pkg/observability/tracing"
)

// Facade provides unified access to all observability subsystems.
// It is the single interface modules need to emit telemetry.
type Facade struct {
	metrics *metrics.Recorder
	audit   audit.Sink
	tracer  trace.Tracer
}

// Metrics returns the process-wide metrics recorder.
func (f *Facade) Metrics() *metrics.Recorder { return f.metrics }

// Audit returns the process-wide audit sink.
func (f *Facade) Audit() audit.Sink { return f.audit }

// Tracer returns the lwauth OpenTelemetry tracer.
func (f *Facade) Tracer() trace.Tracer { return f.tracer }

// global is the process-wide singleton. Defaults to a zero Facade
// (nil metrics, Discard audit, no-op tracer) until Configure is called.
var global atomic.Pointer[Facade]

var configureOnce sync.Once

// Get returns the process-wide observability Facade. Before Configure()
// is called, returns a safe no-op facade. Safe for concurrent use.
func Get() *Facade {
	if f := global.Load(); f != nil {
		return f
	}
	// Return safe defaults if not yet configured.
	return defaultFacade()
}

// Configure sets up the process-wide observability singleton. It may be
// called at most once (subsequent calls are no-ops). This is typically
// called in cmd/lwauth/main.go after flag parsing.
func Configure(opts ...Option) {
	configureOnce.Do(func() {
		f := &Facade{
			metrics: metrics.Default(),
			audit:   audit.Default(),
			tracer:  tracing.Tracer(),
		}
		for _, o := range opts {
			o(f)
		}
		global.Store(f)
	})
}

// Option configures the observability Facade.
type Option func(*Facade)

// WithMetrics overrides the metrics recorder.
func WithMetrics(r *metrics.Recorder) Option {
	return func(f *Facade) { f.metrics = r }
}

// WithAudit overrides the audit sink.
func WithAudit(s audit.Sink) Option {
	return func(f *Facade) { f.audit = s }
}

// WithTracer overrides the OTel tracer.
func WithTracer(t trace.Tracer) Option {
	return func(f *Facade) { f.tracer = t }
}

func defaultFacade() *Facade {
	return &Facade{
		metrics: metrics.Default(),
		audit:   audit.Default(),
		tracer:  tracing.Tracer(),
	}
}

// ResetForTest clears the singleton so tests can reconfigure. NOT safe
// for concurrent use; call only in test setup.
func ResetForTest() {
	global.Store(nil)
	configureOnce = sync.Once{}
}
