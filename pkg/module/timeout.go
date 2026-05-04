// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"context"
	"fmt"
	"time"
)

// timeoutIdentifier wraps an Identifier with a per-call deadline.
type timeoutIdentifier struct {
	inner   Identifier
	timeout time.Duration
}

func (t *timeoutIdentifier) Name() string { return t.inner.Name() }

func (t *timeoutIdentifier) Identify(ctx context.Context, r *Request) (*Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	id, err := t.inner.Identify(ctx, r)
	if ctx.Err() == context.DeadlineExceeded && err != nil {
		return nil, fmt.Errorf("identifier %q timed out after %s: %w", t.inner.Name(), t.timeout, err)
	}
	return id, err
}

// WithIdentifierTimeout returns an IdentifierDecorator that enforces a
// per-call deadline on Identify. If the inner module's context expires
// due to this timeout, the error is wrapped with the module name and
// duration for diagnostics.
func WithIdentifierTimeout(d time.Duration) IdentifierDecorator {
	return func(inner Identifier) Identifier {
		if d <= 0 {
			return inner
		}
		return &timeoutIdentifier{inner: inner, timeout: d}
	}
}

// timeoutAuthorizer wraps an Authorizer with a per-call deadline.
type timeoutAuthorizer struct {
	inner   Authorizer
	timeout time.Duration
}

func (t *timeoutAuthorizer) Name() string { return t.inner.Name() }

func (t *timeoutAuthorizer) Authorize(ctx context.Context, r *Request, id *Identity) (*Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	dec, err := t.inner.Authorize(ctx, r, id)
	if ctx.Err() == context.DeadlineExceeded && err != nil {
		return nil, fmt.Errorf("authorizer %q timed out after %s: %w", t.inner.Name(), t.timeout, err)
	}
	return dec, err
}

// WithAuthorizerTimeout returns an AuthorizerDecorator that enforces a
// per-call deadline on Authorize.
func WithAuthorizerTimeout(d time.Duration) AuthorizerDecorator {
	return func(inner Authorizer) Authorizer {
		if d <= 0 {
			return inner
		}
		return &timeoutAuthorizer{inner: inner, timeout: d}
	}
}

// timeoutMutator wraps a ResponseMutator with a per-call deadline.
type timeoutMutator struct {
	inner   ResponseMutator
	timeout time.Duration
}

func (t *timeoutMutator) Name() string { return t.inner.Name() }

func (t *timeoutMutator) Mutate(ctx context.Context, r *Request, id *Identity, d *Decision) error {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	err := t.inner.Mutate(ctx, r, id, d)
	if ctx.Err() == context.DeadlineExceeded && err != nil {
		return fmt.Errorf("mutator %q timed out after %s: %w", t.inner.Name(), t.timeout, err)
	}
	return err
}

// WithMutatorTimeout returns a MutatorDecorator that enforces a per-call
// deadline on Mutate.
func WithMutatorTimeout(d time.Duration) MutatorDecorator {
	return func(inner ResponseMutator) ResponseMutator {
		if d <= 0 {
			return inner
		}
		return &timeoutMutator{inner: inner, timeout: d}
	}
}
