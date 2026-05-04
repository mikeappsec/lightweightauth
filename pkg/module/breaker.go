// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"context"
	"fmt"

	"github.com/mikeappsec/lightweightauth/pkg/upstream"
)

// BreakerIdentifier wraps an Identifier with a circuit breaker. When the
// breaker is open, Identify fails fast without invoking the inner module.
type BreakerIdentifier struct {
	inner Identifier
	guard *upstream.Guard
}

func (b *BreakerIdentifier) Name() string { return b.inner.Name() }

func (b *BreakerIdentifier) Identify(ctx context.Context, r *Request) (*Identity, error) {
	var id *Identity
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		var innerErr error
		id, innerErr = b.inner.Identify(ctx, r)
		return innerErr
	})
	if err != nil {
		return nil, fmt.Errorf("identifier %q: %w", b.inner.Name(), err)
	}
	return id, nil
}

// WithIdentifierBreaker returns an IdentifierDecorator that wraps the
// module with a circuit breaker + retry budget via upstream.Guard.
func WithIdentifierBreaker(guard *upstream.Guard) IdentifierDecorator {
	return func(inner Identifier) Identifier {
		if guard == nil {
			return inner
		}
		return &BreakerIdentifier{inner: inner, guard: guard}
	}
}

// BreakerAuthorizer wraps an Authorizer with a circuit breaker.
type BreakerAuthorizer struct {
	inner Authorizer
	guard *upstream.Guard
}

func (b *BreakerAuthorizer) Name() string { return b.inner.Name() }

func (b *BreakerAuthorizer) Authorize(ctx context.Context, r *Request, id *Identity) (*Decision, error) {
	var dec *Decision
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		var innerErr error
		dec, innerErr = b.inner.Authorize(ctx, r, id)
		return innerErr
	})
	if err != nil {
		return nil, fmt.Errorf("authorizer %q: %w", b.inner.Name(), err)
	}
	return dec, nil
}

// WithAuthorizerBreaker returns an AuthorizerDecorator that wraps the
// module with a circuit breaker + retry budget.
func WithAuthorizerBreaker(guard *upstream.Guard) AuthorizerDecorator {
	return func(inner Authorizer) Authorizer {
		if guard == nil {
			return inner
		}
		return &BreakerAuthorizer{inner: inner, guard: guard}
	}
}

// BreakerMutator wraps a ResponseMutator with a circuit breaker.
type BreakerMutator struct {
	inner ResponseMutator
	guard *upstream.Guard
}

func (b *BreakerMutator) Name() string { return b.inner.Name() }

func (b *BreakerMutator) Mutate(ctx context.Context, r *Request, id *Identity, d *Decision) error {
	return b.guard.Do(ctx, func(ctx context.Context) error {
		return b.inner.Mutate(ctx, r, id, d)
	})
}

// WithMutatorBreaker returns a MutatorDecorator that wraps the module
// with a circuit breaker + retry budget.
func WithMutatorBreaker(guard *upstream.Guard) MutatorDecorator {
	return func(inner ResponseMutator) ResponseMutator {
		if guard == nil {
			return inner
		}
		return &BreakerMutator{inner: inner, guard: guard}
	}
}
