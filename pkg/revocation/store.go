// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package revocation provides a shared credential revocation store
// used by the LightweightAuth pipeline to reject previously-valid
// credentials that have been explicitly revoked by an operator.
//
// The store is keyed by opaque strings derived by each identifier
// module (via the [module.RevocationChecker] interface). The store
// itself knows nothing about credential formats — it is a simple
// "does key exist?" with TTL.
//
// Two backends are provided:
//   - "memory" — in-process map with TTL (single-replica / dev)
//   - "valkey" — shared Valkey backend (multi-replica production)
//
// An optional negative cache wraps either backend to avoid network
// round-trips for the common (not-revoked) case.
package revocation

import (
	"context"
	"time"
)

// Entry represents a single revocation record.
type Entry struct {
	// Key is the revocation key (e.g. "jti:abc-123", "sub:acme:user@x.com").
	Key string

	// Reason is an optional human-readable reason for the revocation.
	Reason string

	// TTL is how long this revocation entry lives. After TTL, the entry
	// expires — by then the credential itself should have expired.
	// Zero means use the store's default TTL.
	TTL time.Duration

	// RevokedAt is when the revocation was recorded.
	RevokedAt time.Time
}

// Store is the core abstraction for revocation state.
type Store interface {
	// Add records a revocation. The entry expires after its TTL.
	Add(ctx context.Context, entry Entry) error

	// Exists checks whether a key is currently revoked. Implementations
	// must be safe for concurrent use from the pipeline hot path.
	Exists(ctx context.Context, key string) (bool, error)

	// Remove explicitly deletes a revocation entry (un-revoke).
	Remove(ctx context.Context, key string) error

	// List returns active revocation entries matching the given prefix,
	// with pagination. Limit caps the number of results (0 = default 100).
	// Cursor is an opaque string for pagination ("" = start). Returns
	// entries and the next cursor ("" = no more pages).
	List(ctx context.Context, prefix string, limit int, cursor string) ([]Entry, string, error)

	// Close releases resources held by the store.
	Close() error
}

// DefaultListLimit is the maximum entries returned by a single List call.
const DefaultListLimit = 100
