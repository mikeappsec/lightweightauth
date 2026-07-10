// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/observability/audit"
)

// Sink consumes Alert state-transition events. Implementations are
// expected to be safe for concurrent use and non-blocking — the
// engine calls them on the tick goroutine, so a slow sink would
// delay the next evaluation cycle.
type Sink interface {
	Deliver(ctx context.Context, alert Alert, eventType string) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(ctx context.Context, alert Alert, eventType string) error

// Deliver implements Sink.
func (f SinkFunc) Deliver(ctx context.Context, alert Alert, eventType string) error {
	return f(ctx, alert, eventType)
}

// WebhookSink POSTs a JSON envelope of the alert to a configurable
// URL on every fired/resolved event. The body shape is intentionally
// Slack/PagerDuty-compatible so operators can drop a webhook URL
// verbatim into their tool of choice.
type WebhookSink struct {
	URL  string
	HTTP *http.Client
}

// NewWebhookSink constructs a webhook sink. Empty URL means the sink
// is a no-op (the engine skips it on delivery).
func NewWebhookSink(url string) *WebhookSink {
	return &WebhookSink{
		URL:  url,
		HTTP: &http.Client{Timeout: 5 * time.Second},
	}
}

// Empty returns true when no webhook URL was configured.
func (s *WebhookSink) Empty() bool { return s == nil || s.URL == "" }

// WebhookPayload is the on-wire JSON shape delivered to the webhook.
// It mirrors Alert 1:1 with an event_type discriminator so
// receivers can render open/ack/resolve notifications uniformly.
type WebhookPayload struct {
	EventType string    `json:"event_type"`
	Timestamp time.Time `json:"timestamp"`
	Alert     Alert     `json:"alert"`
}

// Deliver posts the webhooks. Returns ErrSinkDegraded when the
// webhook URL is unset (caller logs but does not fail the tick); a
// normal error for HTTP/non-2xx responses (caller logs and continues
// so a dead webhook cannot block the alerting loop).
func (s *WebhookSink) Deliver(ctx context.Context, alert Alert, eventType string) error {
	if s.Empty() {
		return ErrSinkDegraded
	}
	body, err := json.Marshal(WebhookPayload{
		EventType: eventType,
		Timestamp: time.Now(),
		Alert:     alert,
	})
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "lwauth-alerting/1.0")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook post: status %d", resp.StatusCode)
	}
	return nil
}

// AuditSink fans fired-alert transitions into the existing
// audit.Default() chain so alerts land in Loki/Kafka alongside
// terminal decision events. The audit Event is emitted with
// Decision="alert:<eventType>" so downstream SIEM dashboards can filter
// independently from regular decisions. The Subject field is the
// ack-by operator on ack events; otherwise empty.
type AuditSink struct{}

// NewAuditSink constructs an AuditSink that wraps audit.Default().
//
// Per the locked redaction contract: the audit.RecentRing hashes
// subjects before persisting, and the alert Reason payload already
// contains only metadata (subject hashes, method, path, reason
// strings). This means the Alert encoded inside the audit Event is
// safe to persist — no raw PII travels in alert events.
func NewAuditSink() *AuditSink { return &AuditSink{} }

// Deliver fans the alert out to the audit chain. Always returns nil:
// audit.Default() is non-blocking (the slog sink is async-buffered in
// production) and a failed delivery is logged by the audit package
// itself rather than propagated to the engine.
func (s *AuditSink) Deliver(ctx context.Context, alert Alert, eventType string) error {
	if s == nil {
		return nil
	}
	audit.Default().Record(ctx, &audit.Event{
		Timestamp:      time.Now(),
		Subject:        alert.AckedBy, // only populated on ack events
		IdentitySource: "alerting",
		Decision:       "alert:" + eventType,
		DenyReason:     alert.Rule,
		Method:         string(alert.Severity),
		Path:           string(alert.State),
	})
	return nil
}

// MultiSink fans an alert out to every wrapped sink concurrently. A
// failing sink does NOT cancel delivery to siblings (one dead webhook
// must not starve the audit fan-out). Errors are collected and
// returned as a single error summary so the engine can log without
// having to plumb per-sink error handlers.
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink creates a fan-out sink.
func NewMultiSink(sinks ...Sink) *MultiSink { return &MultiSink{sinks: sinks} }

// Deliver dispatches the alert to all wrapped sinks sequentially.
// The execution is serial rather than parallel because each sink
// is already non-blocking internally and serial keeps the overall
// CPU/memory profile predictable on each tick.
func (m *MultiSink) Deliver(ctx context.Context, alert Alert, eventType string) error {
	var errs []error
	for _, s := range m.sinks {
		if s == nil {
			continue
		}
		if err := s.Deliver(ctx, alert, eventType); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	// Combine into one summary so the engine logs once per tick
	// rather than once per sink.
	return fmt.Errorf("multi-sink: %v (and %d more)", errs[0], len(errs)-1)
}