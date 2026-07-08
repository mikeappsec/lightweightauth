// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// DefaultTickInterval is the locked evaluation cadence (15s). Every
// tick the engine evaluates the rule catalog against the configured
// Prom/Loki backends, transitions alert states, and fans
// state-change events to sinks + WS subscribers.
const DefaultTickInterval = 15 * time.Second

// DefaultAckCooldown is the locked operator-ack snooze duration
// (30 min). When an operator acknowledges an alert, the alert stays
// "acknowledged" in the UI and repeat notifications are suppressed
// for this window. After cooldown, if the rule is still firing, the
// alert auto-reopens.
const DefaultAckCooldown = 30 * time.Minute

// HistoryRetention bounds the fired-alert history ring per the lock
// decision (≤1000 events OR 24h, whichever first).
const (
	historyMaxEvents = 1000
	historyMaxAge    = 24 * time.Hour
)

// pendingEval is the book-keeping row used during one tick: for each
// (rule, scope) that currently breaches we keep the first time we saw
// the breach so the rule's `for` period is honoured before the alert
// actually opens. Pending rows are swept on every tick.
type pendingEval struct {
	rule      Rule
	scope     Scope
	value     float64
	since     time.Time
	transient bool // inherited from cache_stale_served-style rules
}

// Engine is the pull-based alerting state machine. One Engine per
// control-plane process owns:
//   - the active rule set (defaults merged with ConfigMap overrides)
//   - the open-alerts registry keyed by stable ID = sha256(rule+scope)
//   - the per-tick pending-states map (the `for` evaluation scratchpad)
//   - the bounded fired-history ring (≤1000 events OR 24h)
//   - the WS subscriber pool and the inbound transitions queue
//
// Run() blocks until ctx is cancelled, ticking at TickInterval.
type Engine struct {
	Cluster string // control-plane's own cluster name (synthetic scope key)

	Prom *PromClient
	Loki *LokiClient
	Sink Sink

	TickInterval time.Duration
	AckCooldown  time.Duration

	mu      sync.RWMutex
	rules   []Rule
	opens   map[string]*Alert   // ID -> open or acked alert
	pending map[string]time.Time // ID -> first-breached-at
	history []Alert              // ring capped at historyMaxEvents OR historyMaxAge, oldest first

	subsMu sync.RWMutex
	subs   map[*alertSub]bool
}

type alertSub struct {
	ch     chan AlertEvent
	filter AlertFilter
}

// AlertFilter is the WS subscriber filter mirroring DecisionFilter's
// shape for clients that wish to scope the live stream.
type AlertFilter struct {
	Severity string `json:"severity,omitempty"`
	State    string `json:"state,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// NewEngine constructs a ready-to-Run engine with the supplied
// defaults-overrides rule set. The rule slice typically comes from
// MergeRules(DefaultRuleCatalog(), loader.Overrides); passing nil
// defaults to the built-in catalog.
func NewEngine(cluster string, prom *PromClient, loki *LokiClient, sink Sink, rules []Rule) *Engine {
	if rules == nil {
		rules = DefaultRuleCatalog()
	}
	if sink == nil {
		sink = NewMultiSink()
	}
	return &Engine{
		Cluster:      cluster,
		Prom:         prom,
		Loki:         loki,
		Sink:         sink,
		TickInterval: DefaultTickInterval,
		AckCooldown:  DefaultAckCooldown,
		rules:        rules,
		opens:        make(map[string]*Alert),
		pending:      make(map[string]time.Time),
		subs:         make(map[*alertSub]bool),
	}
}

// SetRules replaces the active rule set atomically. Safe to call
// from any goroutine — used by the ConfigMap loader to live-apply
// operator edits without restarting the engine loop.
func (e *Engine) SetRules(rules []Rule) {
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

// Rules returns a stable snapshot of the active rules (sorted by
// name) for the GET /v1/controlplane/alerts/rules endpoint.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ListAlerts returns the open/acked alerts plus historical (already
// resolved) alerts filtered by scope. state="" returns all states.
func (e *Engine) ListAlerts(state string, filter AlertFilter) []Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Alert, 0, len(e.opens))
	for _, a := range e.opens {
		if state != "" && string(a.State) != state {
			continue
		}
		if !matchAlertFilter(*a, filter) {
			continue
		}
		out = append(out, *a)
	}
	// Include resolved history too — operators reviewing the panel
	// want to see the recent context across state transitions in the
	// same query.
	for i := range e.history {
		a := e.history[i]
		if state != "" && string(a.State) != state {
			continue
		}
		if !matchAlertFilter(a, filter) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// Ack snoozes notifications on the alert with the given ID for the
// AckCooldown window. Returns ErrAlertNotFound when no open alert
// has the supplied ID, and ErrAlertAlreadyAcked when an ack exists
// and the same operator attempts to ack again.
func (e *Engine) Ack(id, operator, note string) error {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	a, ok := e.opens[id]
	if !ok {
		return ErrAlertNotFound
	}
	if a.State == AlertStateAcknowledged && a.AckedBy == operator {
		return ErrAlertAlreadyAcked
	}
	a.State = AlertStateAcknowledged
	a.AckedBy = operator
	a.AckNote = note
	sn := now.Add(e.AckCooldown)
	a.AckedAt = &now
	a.SnoozeUntil = &sn
	e.broadcastLocked(*a, EventAcked, now)
	return nil
}

// IsDegraded returns true when one or more rule sources have no
// configured backend — the UI surfaces this so operators know some
// rules may be no-opping and which backends to wire up.
func (e *Engine) IsDegraded() (prom, loki bool) {
	return e.Prom.Empty(), e.Loki.Empty()
}

// Run is the periodic evaluation loop. Ticks every TickInterval,
// evaluating every enabled rule against its configured backend and
// transitioning alert state. Blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	logger := slog.Default().With("service", "alerting-engine", "cluster", e.Cluster)
	logger.Info("starting alerting engine", "interval", e.TickInterval, "rules", len(e.rules))
	ticker := time.NewTicker(e.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.tick(ctx); err != nil {
				logger.Warn("alerting tick error", "err", err)
			}
		}
	}
}

// tick evaluates one round of the rule catalog and transitions alert
// states. Public errors are logged but never abort the loop.
func (e *Engine) tick(ctx context.Context) error {
	now := time.Now()
	e.mu.Lock()
	rulesSnapshot := make([]Rule, len(e.rules))
	copy(rulesSnapshot, e.rules)
	e.mu.Unlock()

	// Track which alert IDs we still observe breaching this tick —
	// anything missing from this set will auto-resolve at the end.
	observed := make(map[string]bool)

	var tickErrs []string

	for _, r := range rulesSnapshot {
		if !r.Enabled {
			continue
		}
		breaches, err := e.evaluateRule(ctx, r)
		if err != nil {
			// Per-backend degradation suppresses silently; other
			// errors are surfaced as one consolidated tick error so
			// the engine log stays readable.
			if err != ErrDegraded {
				tickErrs = append(tickErrs, fmt.Sprintf("%s: %v", r.Name, err))
			}
			continue
		}
		for _, b := range breaches {
			id := b.ID
			observed[id] = true
			e.handleBreach(now, r, b)
		}
	}

	// Resolve alerts whose scope no longer breaches — they fell out
	// of the observed set this tick.
	e.resolveUnobserved(now, observed)

	// Sweep expired acknowledgements: an alert past its snooze window
	// that is still breaching reopens (state transitions back to Open).
	e.sweepExpiredAcks(now, observed)

	// Trim fired history ring by both the cap and the age window.
	e.trimHistory(now)

	if len(tickErrs) > 0 {
		return fmt.Errorf("tick errors: %v", tickErrs)
	}
	return nil
}

// evalBreach is one (rule, scope) row successfully evaluated to a
// breaching float beyond the rule threshold.
type evalBreach struct {
	ID    string
	Scope Scope
	Value float64
}

// evaluateRule issues the rule's query to its backend and returns the
// breaching rows (rows where the measured value crossed the rule's
// comparator + threshold). Non-breaching rows return nil. The caller
// uses observed.setFocus so the engine can later resolve alerts that
// fall out of the breach set.
func (e *Engine) evaluateRule(ctx context.Context, r Rule) ([]evalBreach, error) {
	switch r.Source {
	case SourcePrometheus:
		if e.Prom.Empty() {
			return nil, ErrDegraded
		}
		rows, err := e.Prom.Query(ctx, r.Query)
		if err != nil {
			return nil, err
		}
		var out []evalBreach
		for _, row := range rows {
			v, err := row.Float()
			if err != nil {
				continue
			}
			if !r.Breached(v) {
				continue
			}
			scope := row.ExtractScope(r.ScopeLabels, e.Cluster)
			out = append(out, evalBreach{
				ID:    alertID(r.Name, scope),
				Scope: scope,
				Value: v,
			})
		}
		return out, nil

	case SourceLoki:
		if e.Loki.Empty() {
			return nil, ErrDegraded
		}
		streams, err := e.Loki.QueryRange(ctx, r.Query, r.Window)
		if err != nil {
			return nil, err
		}
		var out []evalBreach
		for _, st := range streams {
			v, err := st.LatestValue()
			if err != nil {
				continue
			}
			if !r.Breached(v) {
				continue
			}
			scope := st.ExtractScope(r.ScopeLabels, e.Cluster)
			out = append(out, evalBreach{
				ID:    alertID(r.Name, scope),
				Scope: scope,
				Value: v,
			})
		}
		return out, nil

	default:
		return nil, fmt.Errorf("rule %q: unknown source %q", r.Name, r.Source)
	}
}

// handleBreach is the per-row transition path. It honours the rule's
// `for` duration by parking the first breach in the pending scratch
// map; on subsequent ticks if the breach persists past `for`, the
// alert is promoted to Open. A rule with For <= 0 opens on the first
// breach — the parked-scratch state is skipped entirely.
func (e *Engine) handleBreach(now time.Time, r Rule, b evalBreach) {
	e.mu.Lock()
	defer e.mu.Unlock()
	existing, isOpen := e.opens[b.ID]
	if isOpen {
		// Refresh the observed value on the existing alert so the
		// UI shows the most-recent measurement, even when acked. We
		// do NOT transition state here — resolved re-open goes via
		// sweepExpiredAcks; new opens go via the pending path.
		existing.Metric = &MetricValue{
			Value:      b.Value,
			Threshold:  r.Threshold,
			Window:     r.Window,
			Comparator: r.Comparator,
		}
		// Clear pending because we already opened — no need to keep
		// parked scratch.
		delete(e.pending, b.ID)
		return
	}
	// For <= 0 means "fire on the first breach" — skip parking.
	if r.For <= 0 {
		e.openAlertLocked(now, r, b)
		return
	}
	first, parked := e.pending[b.ID]
	if !parked {
		e.pending[b.ID] = now
		return
	}
	if now.Sub(first) >= r.For {
		e.openAlertLocked(now, r, b)
		delete(e.pending, b.ID)
	}
}

// openAlertLocked inserts a new Open alert for the supplied breach and
// broadcasts the transition. Caller MUST hold e.mu.
//
// History vs opens invariant: the opens map tracks the live Open/Ack
// state (one Alert per (rule+scope)). The history ring captures
// terminal (Resolved) events only — fires acknowledges go through the
// WS broadcast but not the history append, so ListAlerts returns each
// alert exactly once while it is active AND exactly once after it
// terminates.
func (e *Engine) openAlertLocked(now time.Time, r Rule, b evalBreach) {
	a := &Alert{
		ID:       b.ID,
		Rule:     r.Name,
		Severity: r.Severity,
		State:    AlertStateOpen,
		FiredAt:  now,
		Scope:    b.Scope,
		Metric: &MetricValue{
			Value:      b.Value,
			Threshold:  r.Threshold,
			Window:     r.Window,
			Comparator: r.Comparator,
		},
	}
	e.opens[b.ID] = a
	e.broadcastLocked(*a, EventOpen, now)
}

// resolveUnobserved marks alerts whose breaches fell out of this
// tick's observed set as Resolved. Snoozed alerts that are still
// resolution candidates (their rule stopped firing) also resolve; the
// rule's evaluator only resolves whatever is NOT in the observed set,
// which already excludes acked-but-still-firing alerts.
func (e *Engine) resolveUnobserved(now time.Time, observed map[string]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, a := range e.opens {
		if observed[id] {
			continue
		}
		ts := now
		a.State = AlertStateResolved
		a.ResolvedAt = &ts
		e.appendHistoryLocked(*a)
		delete(e.opens, id)
		e.broadcastLocked(*a, EventResolved, now)
	}
	// Sweep pending entries whose breaches fell out — they never
	// opened so no event fires, but cleanup keeps the scratchpad
	// bounded across bursts.
	for id := range e.pending {
		if !observed[id] {
			delete(e.pending, id)
		}
	}
}

// sweepExpiredAcks reopens alerts whose ack cooldown has expired AND
// whose underlying rule is still observed breaching this tick. This
// is the auto-reopen behaviour locked in the alert-triage plan.
func (e *Engine) sweepExpiredAcks(now time.Time, observed map[string]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, a := range e.opens {
		if a.State != AlertStateAcknowledged {
			continue
		}
		if a.SnoozeUntil == nil || now.Before(*a.SnoozeUntil) {
			continue
		}
		// Snooze expired. If the underlying rule still breaches this
		// tick, transition back to Open + re-broadcast so subscribers
		// get a real signal — a quiet ack followed by silent re-fire
		// would look like the alert magically came back without
		// operator action otherwise.
		if observed[id] {
			a.State = AlertStateOpen
			a.AckedBy = ""
			a.AckNote = ""
			a.SnoozeUntil = nil
			e.broadcastLocked(*a, EventOpen, now)
		}
	}
}

// appendHistoryLocked is the fired-history appender. Caller MUST hold
// e.mu (History ring is mutated under the open-alerts lock so the
// ListAlerts response stays consistent).
func (e *Engine) appendHistoryLocked(a Alert) {
	e.history = append(e.history, a)
	// Hard cap (≤1000 events).
	if len(e.history) > historyMaxEvents {
		// Drop oldest 20% so we trim in amortized-O(N) rather than
		// one element per tick — keeps the ring stable against
		// high-frequency rule flapping.
		drop := len(e.history) - historyMaxEvents
		if drop < len(e.history)/5 {
			drop = len(e.history) / 5
		}
		e.history = e.history[drop:]
	}
}

// trimHistory enforces both the cap (already handled in append) and
// the 24h age cutoff. Run once per tick so aging is fair without
// spurious evictions during a long burst.
func (e *Engine) trimHistory(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := now.Add(-historyMaxAge)
	first := -1
	for i, a := range e.history {
		if a.ResolvedAt != nil && a.ResolvedAt.After(cutoff) {
			first = i
			break
		}
		if a.ResolvedAt == nil {
			// Open/acked alerts shouldn't sit in history; defensive.
			first = i
			break
		}
	}
	if first <= 0 {
		return
	}
	// Drop everything older than cutoff.
	e.history = e.history[first:]
}

// alertID is the stable hash of a (rule, scope) pair used as the
// open-alerts registry key. The hash is deterministic so the same
// breach re-observed across ticks consistently addresses the same
// Alert — this is critical for ack semantics.
func alertID(rule string, scope Scope) string {
	// Stable key: sort scope keys so map iteration order doesn't
	// affect the hash. Hash collisions on the alert registry would
	// cause two unrelated alerts to share ID — only a real bug, so we
	// normalise.
	keys := make([]string, 0, len(scope))
	for k := range scope {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf := make([]byte, 0, len(rule)+1+len(keys)*48)
	buf = append(buf, rule...)
	buf = append(buf, '|')
	for _, k := range keys {
		buf = append(buf, k...)
		buf = append(buf, '=')
		buf = append(buf, scope[k]...)
		buf = append(buf, ';')
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:16])
}

// matchAlertFilter applies the WS subscriber filter to a candidate
// alert. Empty filter fields match anything.
func matchAlertFilter(a Alert, f AlertFilter) bool {
	if f.Severity != "" && string(a.Severity) != f.Severity {
		return false
	}
	if f.State != "" && string(a.State) != f.State {
		return false
	}
	if f.Rule != "" && a.Rule != f.Rule {
		return false
	}
	return true
}

// --- WS subscriber pool ------------------------------------------------------

// Subscribe registers a new WS subscriber with the given filter and
// returns a receive channel the caller drains in its own goroutine.
// Unsubscribe by closing the returned channel via the engine's
// Unsubscribe method (closing it directly would race the broadcast).
func (e *Engine) Subscribe(filter AlertFilter) <-chan AlertEvent {
	ch := make(chan AlertEvent, 16)
	sub := &alertSub{ch: ch, filter: filter}
	e.subsMu.Lock()
	e.subs[sub] = true
	e.subsMu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber by channel identity. Safe to call
// from the subscriber goroutine. The channel is closed so a blocked
// receiver unblocks cleanly.
func (e *Engine) Unsubscribe(ch <-chan AlertEvent) {
	e.subsMu.Lock()
	defer e.subsMu.Unlock()
	for sub := range e.subs {
		if sub.ch == ch {
			close(sub.ch)
			delete(e.subs, sub)
			return
		}
	}
}

// broadcastLocked fans a state transition to every subscriber whose
// filter matches. Caller MUST hold e.mu (we're under state mutation).
// The subscriber channel writes are non-blocking — slow subscribers
// drop rather than block the engine tick.
func (e *Engine) broadcastLocked(a Alert, eventType string, ts time.Time) {
	evt := AlertEvent{Type: eventType, Alert: a, Timestamp: ts}
	// Build subscriber list under subsMu but copy then release before
	// writing so we don't hold the subs lock across channel ops.
	e.subsMu.RLock()
	subs := make([]*alertSub, 0, len(e.subs))
	for s := range e.subs {
		if matchAlertFilter(a, s.filter) {
			subs = append(subs, s)
		}
	}
	e.subsMu.RUnlock()
	// Sink delivery happens after the WS broadcast so subscribers see
	// the event before Sinks' potentially blocking webhook POST.
	for _, s := range subs {
		select {
		case s.ch <- evt:
		default:
			// Subscriber buffer full: drop (operator-side bug, but
			// the engine continues).
		}
	}
	// Best-effort sink delivery — failures are logged by the engine
	// run loop (we deliberately don't await success; alerting remains
	// available even if the webhook is down).
	if e.Sink != nil {
		go func() {
			if err := e.Sink.Deliver(context.Background(), a, eventType); err != nil && err != ErrSinkDegraded {
				slog.Default().Warn("alerting sink delivery failed", "rule", a.Rule, "type", eventType, "err", err)
			}
		}()
	}
}

// ErrAlertNotFound and ErrAlertAlreadyAcked returned by Ack.
var (
	ErrAlertNotFound     = fmt.Errorf("alerting: alert not found")
	ErrAlertAlreadyAcked = fmt.Errorf("alerting: alert already acknowledged by this operator")
)