// Package audit emits one JSON record per terminal authorization
// decision (DESIGN.md M9). Sinks consume Events; the default Sink is a
// thin slog wrapper writing JSON lines to a *slog.Logger of the
// operator's choosing.
//
// The audit log is the durable, queryable trace of "who tried to do
// what, was it allowed, and why". Pair with metrics for aggregates and
// tracing for individual-request hops.
package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Event is one terminal pipeline decision. Field names mirror what
// operators expect to see in a SIEM. Use the json tags as the canonical
// shape.
type Event struct {
	// Timestamp of the decision, RFC 3339Nano.
	Timestamp time.Time `json:"ts"`

	// Tenant carries Request.TenantID (may be empty).
	Tenant string `json:"tenant,omitempty"`

	// Subject is Identity.Subject, "" if no identity was produced.
	Subject string `json:"subject,omitempty"`

	// IdentitySource is the name of the identifier that matched.
	IdentitySource string `json:"identity_source,omitempty"`

	// Authorizer is the name of the top-level authorizer that produced
	// the decision (or "" if the request denied before authorize).
	Authorizer string `json:"authorizer,omitempty"`

	// Decision is "allow" / "deny" / "error".
	Decision string `json:"decision"`

	// DenyReason is set when Decision != "allow".
	DenyReason string `json:"deny_reason,omitempty"`

	// HTTPStatus is the status the server adapter will return.
	HTTPStatus int `json:"http_status,omitempty"`

	// Method / Host / Path are echoed from the request for log
	// correlation. Headers are deliberately not included — operators
	// who need that should enable trace context propagation instead.
	Method string `json:"method,omitempty"`
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`

	// LatencyMs is the end-to-end pipeline latency in milliseconds.
	LatencyMs float64 `json:"latency_ms"`

	// CacheHit is true if the decision came from the decision cache.
	CacheHit bool `json:"cache_hit,omitempty"`

	// TraceID is the W3C trace ID in hex (or "" if no active span).
	TraceID string `json:"trace_id,omitempty"`

	// PolicyVersion is the operator-assigned spec.version tag (D2).
	// Empty when not set. Used for filtering audit logs by policy
	// revision during shadow/canary rollouts.
	PolicyVersion string `json:"policy_version,omitempty"`

	// ShadowDisagreement is true when the event represents a shadow-mode
	// disagreement: the policy would deny but production allows (D2).
	ShadowDisagreement bool `json:"shadow_disagreement,omitempty"`
}

// Sink consumes audit events. Implementations MUST be safe for
// concurrent use and SHOULD NOT block: emit asynchronously or drop on
// pressure rather than slowing the request path.
type Sink interface {
	Record(ctx context.Context, e *Event)
}

// SinkFunc adapts a function value to Sink.
type SinkFunc func(context.Context, *Event)

// Record implements Sink.
func (f SinkFunc) Record(ctx context.Context, e *Event) { f(ctx, e) }

// discardSink is the type of Discard. We use a named struct (rather
// than a SinkFunc) so two `Sink` interface values that both hold
// Discard compare equal at runtime — function values are
// uncomparable and would panic on `==`. Callers that want to know
// whether the process-default has been overridden therefore can
// safely write `audit.Default() == audit.Discard`.
type discardSink struct{}

// Record implements Sink and drops every event.
func (discardSink) Record(context.Context, *Event) {}

// Discard is a Sink that drops every event. It is a comparable
// singleton — see discardSink for why.
var Discard Sink = discardSink{}

// NewSlogSink returns a Sink that logs each event as a single
// structured slog record at INFO level under the message "audit". The
// logger's handler determines on-disk format (JSON in production).
func NewSlogSink(log *slog.Logger) Sink {
	if log == nil {
		log = slog.Default()
	}
	return SinkFunc(func(ctx context.Context, e *Event) {
		log.LogAttrs(ctx, slog.LevelInfo, "audit",
			slog.Time("ts", e.Timestamp),
			slog.String("tenant", e.Tenant),
			slog.String("subject", e.Subject),
			slog.String("identity_source", e.IdentitySource),
			slog.String("authorizer", e.Authorizer),
			slog.String("decision", e.Decision),
			slog.String("deny_reason", e.DenyReason),
			slog.Int("http_status", e.HTTPStatus),
			slog.String("method", e.Method),
			slog.String("host", e.Host),
			slog.String("path", e.Path),
			slog.Float64("latency_ms", e.LatencyMs),
			slog.Bool("cache_hit", e.CacheHit),
			slog.String("trace_id", e.TraceID),
		)
	})
}

// --- process-wide default --------------------------------------------------

var (
	defaultMu sync.RWMutex
	def       Sink = Discard
)

// Default returns the process-wide audit Sink. Defaults to Discard so
// nothing is emitted until an operator opts in via SetDefault.
func Default() Sink {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return def
}

// SetDefault installs s as the process-wide Sink. Pass nil to revert to
// Discard.
func SetDefault(s Sink) {
	defaultMu.Lock()
	if s == nil {
		s = Discard
	}
	def = s
	defaultMu.Unlock()
}
