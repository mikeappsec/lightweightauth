// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// refresh_tracker.go provides a JWKS refresh wrapper that instruments
// kid-miss-triggered refreshes with keyrotation metrics.
package jwt

import (
	"context"
	"sync"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
)

// JWKSRefreshTracker tracks JWKS refresh events and kid-miss-triggered
// force refreshes. It wraps around jwx's cache by being called from
// the jwt identifier whenever a kid miss occurs.
type JWKSRefreshTracker struct {
	mu          sync.Mutex
	lastRefresh time.Time
	minInterval time.Duration
	moduleName  string
}

// NewJWKSRefreshTracker creates a tracker for the given module name.
// minInterval prevents refresh storms (default 5s).
func NewJWKSRefreshTracker(moduleName string, minInterval time.Duration) *JWKSRefreshTracker {
	if minInterval <= 0 {
		minInterval = 5 * time.Second
	}
	return &JWKSRefreshTracker{
		moduleName:  moduleName,
		minInterval: minInterval,
	}
}

// ShouldRefresh returns true if enough time has elapsed since the last
// refresh to allow a kid-miss-triggered force refresh. If true, records
// the refresh metric.
func (t *JWKSRefreshTracker) ShouldRefresh(_ context.Context) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if now.Sub(t.lastRefresh) < t.minInterval {
		return false
	}
	t.lastRefresh = now
	keyrotation.Metrics.RefreshTotal.WithLabelValues(t.moduleName, "kid_miss_trigger").Inc()
	return true
}

// RecordRefreshSuccess records a successful JWKS refresh.
func (t *JWKSRefreshTracker) RecordRefreshSuccess() {
	keyrotation.Metrics.RefreshTotal.WithLabelValues(t.moduleName, "success").Inc()
}

// RecordRefreshError records a failed JWKS refresh.
func (t *JWKSRefreshTracker) RecordRefreshError() {
	keyrotation.Metrics.RefreshTotal.WithLabelValues(t.moduleName, "error").Inc()
}
