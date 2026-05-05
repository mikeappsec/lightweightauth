// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"sync"
)

// TenantAwareSink applies per-tenant redaction policies before
// forwarding events to the inner sink. Tenant redaction rules are
// registered dynamically as AuthConfig CRDs are reconciled.
type TenantAwareSink struct {
	mu    sync.RWMutex
	rules map[string]*RedactingSink // tenant ID → redacting wrapper
	inner Sink
}

// NewTenantAwareSink creates a sink that applies per-tenant redaction
// before forwarding to inner. Tenants without registered redaction
// rules pass through unmodified.
func NewTenantAwareSink(inner Sink) *TenantAwareSink {
	return &TenantAwareSink{
		rules: make(map[string]*RedactingSink),
		inner: inner,
	}
}

// SetTenantRedaction registers or updates redaction rules for a tenant.
// Pass nil fields to remove redaction for the tenant.
func (t *TenantAwareSink) SetTenantRedaction(tenantID string, fields []RedactionField, hmacKey []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(fields) == 0 {
		delete(t.rules, tenantID)
		return
	}
	t.rules[tenantID] = NewRedactingSink(t.inner, fields, hmacKey)
}

// RemoveTenant removes redaction rules for a tenant.
func (t *TenantAwareSink) RemoveTenant(tenantID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.rules, tenantID)
}

// Record applies tenant-specific redaction if configured, then
// forwards to the inner sink.
func (t *TenantAwareSink) Record(ctx context.Context, e *Event) {
	t.mu.RLock()
	rs, ok := t.rules[e.Tenant]
	t.mu.RUnlock()

	if ok {
		rs.Record(ctx, e)
		return
	}
	t.inner.Record(ctx, e)
}
