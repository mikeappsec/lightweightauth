// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// defaultRecentCapacity bounds the in-memory recent-events ring so a
// bursty instance cannot exhaust admin-process memory. 1024 events
// covers ~5–10 min of triage context at moderate QPS and matches the
// documented default for /v1/admin/audit/recent (DESIGN.md D4).
const defaultRecentCapacity = 1024

// RecentRing is a bounded in-memory ring that retains the most recent
// audit events for the /v1/admin/audit/recent endpoint. Each event is
// shallow-copied before storage and the Subject field is HMAC-hashed so
// the buffer never retains raw PII in process memory — matching the
// "metadata only" exposure contract for the admin alerting/triage UI.
//
// The ring is safe for concurrent use. When the buffer is full the
// oldest entry is overwritten.
type RecentRing struct {
	capacity int
	mu       sync.Mutex
	entries  []Event // ring storage; len == capacity once full
	head     int     // index of the next write
	full     bool
	hmacKey  []byte // per-process seed for subject hashing
}

// NewRecentRing constructs a RecentRing with the given capacity.
// capacity <= 0 falls back to defaultRecentCapacity. The HMAC key is a
// single per-ring random salt; loss of the key on process restart
// resets the hash space (the ring is in-memory only anyway).
func NewRecentRing(capacity int) *RecentRing {
	if capacity <= 0 {
		capacity = defaultRecentCapacity
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Deterministic fallback so a failed crypto RNG still produces
		// a stable per-ring HMAC key rather than crashing.
		sum := sha256.Sum256([]byte("lwauth-recent-ring-fallback"))
		key = sum[:]
	}
	return &RecentRing{
		capacity: capacity,
		entries:  make([]Event, 0, capacity),
		hmacKey:  key,
	}
}

// Sink returns a Sink view over this ring. Calling Record on the
// returned Sink is equivalent to calling RecentRing.Record directly —
// the wrapper exists so the ring can be composed with audit.NewMultiSink
// alongside other configured sinks.
func (r *RecentRing) Sink() Sink { return SinkFunc(r.Record) }

// Record stores a redacted copy of the event. Implements Sink. Safe to
// call with a nil receiver or nil event. The Subject field is replaced
// with an HMAC-SHA-256 hex digest keyed by the ring's per-process
// salt; all other fields are passed through unchanged.
func (r *RecentRing) Record(_ context.Context, e *Event) {
	if r == nil || e == nil {
		return
	}
	snapshot := *e
	if snapshot.Subject != "" {
		snapshot.Subject = r.hashSubject(snapshot.Subject)
	}
	r.push(snapshot)
}

// push appends an event, overwriting the oldest entry when full.
func (r *RecentRing) push(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		r.entries = append(r.entries, e)
		if len(r.entries) == r.capacity {
			r.full = true
		}
		return
	}
	r.entries[r.head] = e
	r.head = (r.head + 1) % r.capacity
}

// RecentFilter is a predicate applied to ring snapshots. Events whose
// predicate returns false are skipped.
type RecentFilter func(Event) bool

// FilterByTenant keeps events whose Tenant matches.
func FilterByTenant(tenant string) RecentFilter {
	return func(e Event) bool { return e.Tenant == tenant }
}

// FilterByVerdict keeps events with a specific Decision (allow/deny/error).
func FilterByVerdict(verdict string) RecentFilter {
	return func(e Event) bool { return e.Decision == verdict }
}

// FilterByAuthorizer keeps events emitted by the given top-level
// authorizer name.
func FilterByAuthorizer(name string) RecentFilter {
	return func(e Event) bool { return e.Authorizer == name }
}

// FilterBySubjectHash keeps events whose Subject has already been hashed
// by RecentRing.Record and matches the provided hash. This is the only
// safe way to search by subject from the admin API since the stored
// events never include raw subject strings.
func FilterBySubjectHash(hash string) RecentFilter {
	return func(e Event) bool { return e.Subject == hash }
}

// Snapshot returns a copy of the most recent events ordered oldest
// first, after applying optional filters. limit <= 0 returns every
// matching event (capped by capacity).
func (r *RecentRing) Snapshot(limit int, filters ...RecentFilter) []Event {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	var ordered []Event
	if !r.full {
		ordered = make([]Event, len(r.entries))
		copy(ordered, r.entries)
	} else {
		ordered = make([]Event, 0, len(r.entries))
		n := len(r.entries)
		for i := 0; i < n; i++ {
			idx := (r.head + i) % n
			ordered = append(ordered, r.entries[idx])
		}
	}
	r.mu.Unlock()
	return applyFilters(ordered, limit, filters)
}

func applyFilters(events []Event, limit int, filters []RecentFilter) []Event {
	if len(filters) == 0 && (limit <= 0 || limit >= len(events)) {
		return events
	}
	out := make([]Event, 0, len(events))
	for _, e := range events {
		keep := true
		for _, f := range filters {
			if !f(e) {
				keep = false
				break
			}
		}
		if !keep {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func (r *RecentRing) hashSubject(s string) string {
	mac := hmac.New(sha256.New, r.hmacKey)
	mac.Write([]byte(s))
	return hex.EncodeToString(mac.Sum(nil))
}

// --- process-wide default -----------------------------------------------

var (
	recentMu sync.Mutex
	recent   *RecentRing
)

// DefaultRecentRing returns the process-wide recent-events ring, lazily
// initialised with defaultRecentCapacity. The engine's report() function
// and admin mutation handlers feed this ring; the /v1/admin/audit/recent
// and /v1/admin/audit endpoints read from it. Replaces the previous
// default conservatively: callers that previously replaced
// audit.Default() (operators bringing their own sink, tests isolating
// audit output) are unaffected — the ring is a side-band sink, not
// part of the audit.Default() sink chain.
func DefaultRecentRing() *RecentRing {
	recentMu.Lock()
	defer recentMu.Unlock()
	if recent == nil {
		recent = NewRecentRing(defaultRecentCapacity)
	}
	return recent
}

// ResetDefaultRecentRing resets the process-wide recent ring. Intended
// for tests that want a clean ring between subtests; production code
// should not call this.
func ResetDefaultRecentRing() {
	recentMu.Lock()
	recent = nil
	recentMu.Unlock()
}