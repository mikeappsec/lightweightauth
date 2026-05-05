// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"context"
	"sync"
)

// IdentifierDecorator wraps an Identifier with cross-cutting behavior
// (observability, revocation checks, rotation tracking, etc.).
// Decorators are applied in order after the base factory builds the
// module, so they compose cleanly without factories knowing about each
// other.
type IdentifierDecorator func(Identifier) Identifier

// AuthorizerDecorator wraps an Authorizer with cross-cutting behavior.
type AuthorizerDecorator func(Authorizer) Authorizer

// MutatorDecorator wraps a ResponseMutator with cross-cutting behavior.
type MutatorDecorator func(ResponseMutator) ResponseMutator

// DecoratedRegistry extends Registry with a decorator chain that is
// automatically applied to every module built through it.
type DecoratedRegistry[T any] struct {
	*Registry[T]
	mu         sync.RWMutex
	decorators []func(T) T
}

// NewDecoratedRegistry creates a registry that applies decorators on Build.
func NewDecoratedRegistry[T any](kind string) *DecoratedRegistry[T] {
	return &DecoratedRegistry[T]{
		Registry: NewRegistry[T](kind),
	}
}

// AddDecorator appends a decorator that will wrap every module produced
// by Build. Decorators are applied in the order they are added (first
// added = innermost wrapper).
func (r *DecoratedRegistry[T]) AddDecorator(d func(T) T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decorators = append(r.decorators, d)
}

// Build constructs the module via the registered factory, then applies
// all decorators in order.
func (r *DecoratedRegistry[T]) Build(typeName, instanceName string, cfg map[string]any) (T, error) {
	base, err := r.Registry.Build(typeName, instanceName, cfg)
	if err != nil {
		return base, err
	}
	r.mu.RLock()
	decs := r.decorators
	r.mu.RUnlock()
	for _, d := range decs {
		base = d(base)
	}
	return base, nil
}

// ─── Example Decorator: Observability Wrapper ─────────────────────

// ObservableIdentifier is an Identifier decorator that records metrics
// around Identify calls. Modules do not need to import this; it is
// applied centrally by the pipeline builder.
type ObservableIdentifier struct {
	inner  Identifier
	onCall func(name string, err error)
}

func (o *ObservableIdentifier) Name() string { return o.inner.Name() }

func (o *ObservableIdentifier) Identify(ctx context.Context, r *Request) (*Identity, error) {
	id, err := o.inner.Identify(ctx, r)
	if o.onCall != nil {
		o.onCall(o.inner.Name(), err)
	}
	return id, err
}

// WithObservability returns an IdentifierDecorator that calls onCall
// after every Identify invocation with the module name and error (or nil).
func WithObservability(onCall func(name string, err error)) IdentifierDecorator {
	return func(inner Identifier) Identifier {
		return &ObservableIdentifier{inner: inner, onCall: onCall}
	}
}
