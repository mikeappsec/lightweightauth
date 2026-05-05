// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package module_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// stubIdentifier is a test double for Identifier.
type stubIdentifier struct {
	name    string
	delay   time.Duration
	id      *module.Identity
	err     error
}

func (s *stubIdentifier) Name() string { return s.name }

func (s *stubIdentifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.id, s.err
}

func TestWithIdentifierTimeout_Success(t *testing.T) {
	inner := &stubIdentifier{
		name:  "fast",
		delay: 1 * time.Millisecond,
		id:    &module.Identity{Subject: "alice"},
	}
	wrapped := module.WithIdentifierTimeout(100 * time.Millisecond)(inner)
	id, err := wrapped.Identify(context.Background(), &module.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Subject != "alice" {
		t.Fatalf("got subject %q, want alice", id.Subject)
	}
}

func TestWithIdentifierTimeout_Expires(t *testing.T) {
	inner := &stubIdentifier{
		name:  "slow",
		delay: 500 * time.Millisecond,
	}
	wrapped := module.WithIdentifierTimeout(10 * time.Millisecond)(inner)
	_, err := wrapped.Identify(context.Background(), &module.Request{})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got: %v", err)
	}
}

func TestWithIdentifierTimeout_ZeroDuration(t *testing.T) {
	inner := &stubIdentifier{name: "raw", id: &module.Identity{Subject: "bob"}}
	wrapped := module.WithIdentifierTimeout(0)(inner)
	// Should return inner unchanged.
	if wrapped.Name() != "raw" {
		t.Fatalf("expected raw, got %s", wrapped.Name())
	}
}

// stubAuthorizer is a test double for Authorizer.
type stubAuthorizer struct {
	name  string
	delay time.Duration
	dec   *module.Decision
	err   error
}

func (s *stubAuthorizer) Name() string { return s.name }

func (s *stubAuthorizer) Authorize(ctx context.Context, _ *module.Request, _ *module.Identity) (*module.Decision, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.dec, s.err
}

func TestWithAuthorizerTimeout_Success(t *testing.T) {
	inner := &stubAuthorizer{
		name: "fast-az",
		dec:  &module.Decision{Allow: true, Status: 200},
	}
	wrapped := module.WithAuthorizerTimeout(100 * time.Millisecond)(inner)
	dec, err := wrapped.Authorize(context.Background(), &module.Request{}, &module.Identity{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Allow {
		t.Fatal("expected allow")
	}
}

func TestWithAuthorizerTimeout_Expires(t *testing.T) {
	inner := &stubAuthorizer{
		name:  "slow-az",
		delay: 500 * time.Millisecond,
	}
	wrapped := module.WithAuthorizerTimeout(10 * time.Millisecond)(inner)
	_, err := wrapped.Authorize(context.Background(), &module.Request{}, &module.Identity{})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
