// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package alerting implements a pull-based alerting engine that runs
// inside the control plane and lets operators answer the initial-triage
// question "why are requests not responding" without leaving the
// LightweightAuth console.
//
// Scope (locked plan): alerts cover only the policy engine's health
// (identifier/authorizer errors, latency, degraded cache, shadow /
// canary disagreements) and the requests passed to it (deny spikes,
// rate-limit denials, revocation storms). Sibling-repo signals (IdP
// login failures, eBPF node denies, infra cost/quota alerts) and deep
// investigation tooling are out of scope for this item.
//
// The engine is stateless from a durability standpoint: rule
// persistence comes from a Kubernetes ConfigMap, open-alerts and
// fired-history live in process memory (bounded ring ≤1000 OR 24h,
// whichever first). Production durability is the operator's
// responsibility via the existing audit.Sink fan-out chain — fired
// alerts are emitted to audit.Default() so they land in Loki/Kafka
// alongside decision events.
package alerting

import (
	"errors"
	"time"
)

// Severity tiers. The order matters — the dashboard banner surfaces
// only the highest-severity open alert.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// AlertState is the lifecycle phase of an Alert.
type AlertState string

const (
	AlertStateOpen         AlertState = "open"
	AlertStateAcknowledged AlertState = "acknowledged" // snoozed
	AlertStateResolved     AlertState = "resolved"
)

// Source indicates which query backend a rule evaluates against.
type Source string

const (
	SourcePrometheus Source = "prometheus"
	SourceLoki       Source = "loki"
)

// Comparator expresses the relation the rule's measured value must
// satisfy against the threshold for an alert to fire.
type Comparator string

const (
	ComparatorGreaterThan        Comparator = ">"
	ComparatorLessThan           Comparator = "<"
	ComparatorGreaterThanEqual  Comparator = ">="
	ComparatorLessThanEqual     Comparator = "<="
)

// ErrDegraded is returned by query clients that have not been
// configured (the backend URL env var is empty). The engine uses this
// to mark the affected rules as degraded-no-ops rather than treating
// the unavailability as a breach or as an internal error.
var ErrDegraded = errors.New("alerting: query backend not configured")

// ErrSinkDegraded is returned by sinks that are unreachable without
// aborting the evaluation loop. The engine logs the sink error and
// continues with the other sinks so a dead webhook does not block
// alerting.
var ErrSinkDegraded = errors.New("alerting: sink delivery failed")

// Rule is a declarative alert rule. The engine evaluates each enabled
// rule once per tick. Operators edit rules via the lwauth-alerting-rules
// ConfigMap; the built-in catalog returned by DefaultRuleCatalog() is
// the editable baseline — same Name is the merge key.
type Rule struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Severity    Severity      `json:"severity"`
	Source      Source        `json:"source"`
	Query       string        `json:"query"`     // PromQL or LogQL
	Comparator  Comparator    `json:"comparator"`
	Threshold   float64       `json:"threshold"`
	For         time.Duration `json:"for"`      // min sustained before firing
	Window      time.Duration `json:"window"`   // [window] for rate() / count_over_time()
	ScopeLabels []string      `json:"scope_labels,omitempty"`
	Enabled     bool          `json:"enabled"`
	// IsDefault marks rules shipped by DefaultRuleCatalog(). When an
	// operator deletes via the rules API, the override entry is set
	// Enabled:false — defaults cannot be removed, only masked.
	IsDefault bool `json:"is_default,omitempty"`
}

// Breached reports whether value crosses threshold using the rule's
// comparator. Returns the value side-by-side with the boolean so the
// metric snapshot in the resulting alert carries the measured value.
func (r Rule) Breached(value float64) bool {
	switch r.Comparator {
	case ComparatorGreaterThan:
		return value > r.Threshold
	case ComparatorLessThan:
		return value < r.Threshold
	case ComparatorGreaterThanEqual:
		return value >= r.Threshold
	case ComparatorLessThanEqual:
		return value <= r.Threshold
	}
	return false
}

// Scope is the per-breach label set that identifies the source of a
// violation: cluster / instance / tenant / identifier / authorizer /
// policy_version. The keys are the rule's ScopeLabels; values are
// drawn from the query result vector labels.
type Scope map[string]string

// Alert is a fired or resolved alert as the engine emits it via sinks
// and as the REST API returns it. The JSON tags are the canonical
// on-wire shape used by the UI.
type Alert struct {
	ID         string         `json:"id"`
	Rule       string         `json:"rule"`
	Severity   Severity       `json:"severity"`
	State      AlertState     `json:"state"`
	FiredAt    time.Time      `json:"fired_at"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
	AckedAt    *time.Time     `json:"acked_at,omitempty"`
	AckedBy    string         `json:"acked_by,omitempty"`
	AckNote    string         `json:"ack_note,omitempty"`
	SnoozeUntil *time.Time    `json:"snooze_until,omitempty"`
	Scope      Scope          `json:"scope"`
	Metric     *MetricValue   `json:"metric,omitempty"`
	Reason     *ReasonPayload `json:"reason,omitempty"`
}

// MetricValue is a snapshot of the measured metric at fire time so
// the UI can show the breach magnitude versus the rule's threshold.
type MetricValue struct {
	Value     float64       `json:"value"`
	Threshold float64       `json:"threshold"`
	Window    time.Duration `json:"window"`
	Comparator Comparator   `json:"comparator"`
}

// ReasonPayload is what the engine attaches to a firing alert so the
// triage UI can answer "why are requests not responding" at a glance.
//
// Metadata-only exposure: subject_hash is HMAC-SHA-256 hex (the data
// plane's RecentRing already hashed the Subject before shipping).
// Raw tokens, claims, headers, and password material are never
// included. recent_failures is capped at 5 rows.
type ReasonPayload struct {
	Headline        string              `json:"headline"`
	TopContributors []ReasonContributor `json:"top_contributors,omitempty"`
	RecentFailures  []ReasonFailure     `json:"recent_failures,omitempty"`
	Correlated      []ReasonCorrelated  `json:"correlated,omitempty"`
}

// ReasonContributor aggregates by a single dimension (identifier,
// authorizer, host, policy_version, tenant, subject_hash, path,
// reason). The Share field is a 0..1 relative fraction.
type ReasonContributor struct {
	Dimension string  `json:"dimension"`
	Value     string  `json:"value"`
	Share     float64 `json:"share,omitempty"`
}

// ReasonFailure is a single recent-decision row previewed in the
// reason panel — never raw PII. SubjectHash already HMAC-hashed by
// the data-plane RecentRing.
type ReasonFailure struct {
	Timestamp   time.Time `json:"timestamp"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	SubjectHash string    `json:"subject_hash,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Tenant      string    `json:"tenant,omitempty"`
}

// ReasonCorrelated references a sibling alert that fired within the
// same scope, hinting at causal links during initial triage.
type ReasonCorrelated struct {
	Rule  string `json:"rule"`
	Value string `json:"value,omitempty"`
	Note  string `json:"note,omitempty"`
}

// AlertEvent is the envelope the WebSocket subscriber pool pushes to
// connected clients. State transitions are emitted as AlertEvent
// records so the UI can render open/ack/resolve in real time.
type AlertEvent struct {
	Type      string    `json:"type"`              // "open" | "acked" | "resolved"
	Alert     Alert     `json:"alert"`
	Timestamp time.Time `json:"timestamp"`
}

// Event types broadcast over the WS pool.
const (
	EventOpen     = "open"
	EventAcked    = "acked"
	EventResolved = "resolved"
)