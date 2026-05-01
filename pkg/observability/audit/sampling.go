package audit

import "context"

// SamplingRule controls whether an event is emitted. Rules are evaluated
// in order; the first match wins.
type SamplingRule struct {
	// Match is a predicate over the event. Nil means "match all".
	Match func(*Event) bool
	// Action is "always" (emit), "drop" (discard), or "sample" (probabilistic).
	Action SamplingAction
	// Rate is the sampling rate when Action is SampleAction (0.0–1.0).
	Rate float64
}

// SamplingAction is the behaviour when a rule matches.
type SamplingAction string

const (
	// ActionAlways emits the event unconditionally.
	ActionAlways SamplingAction = "always"
	// ActionDrop silently discards the event.
	ActionDrop SamplingAction = "drop"
	// ActionSample emits the event with probability Rate.
	ActionSample SamplingAction = "sample"
)

// SamplingSink wraps an inner Sink with configurable sampling rules.
// Security-critical events (deny, error, shadow/canary disagreements)
// are ALWAYS emitted via hard-coded pre-rules that cannot be overridden
// User-defined rules run after pre-rules.
type SamplingSink struct {
	inner         Sink
	preRules      []SamplingRule // immutable, security-critical
	rules         []SamplingRule
	defaultAction SamplingAction
	defaultRate   float64
	rand          func() float64 // injectable for testing
}

// SamplingSinkOption configures a SamplingSink.
type SamplingSinkOption func(*SamplingSink)

// WithDefaultAction sets what happens when no rule matches (default: always).
func WithDefaultAction(a SamplingAction, rate float64) SamplingSinkOption {
	return func(s *SamplingSink) {
		s.defaultAction = a
		s.defaultRate = rate
	}
}

// WithRandFunc injects a random function for testing.
func WithRandFunc(f func() float64) SamplingSinkOption {
	return func(s *SamplingSink) { s.rand = f }
}

// NewSamplingSink creates a sampling filter in front of inner.
// Security-critical pre-rules (deny, error, shadow/canary disagreement)
// are always evaluated first and cannot be overridden by user rules.
func NewSamplingSink(inner Sink, rules []SamplingRule, opts ...SamplingSinkOption) *SamplingSink {
	s := &SamplingSink{
		inner: inner,
		preRules: []SamplingRule{
			AlwaysDeny(),
			AlwaysError(),
			AlwaysShadowDisagreement(),
			AlwaysCanaryDisagreement(),
		},
		rules:         rules,
		defaultAction: ActionAlways,
		rand:          defaultRand,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Record implements Sink with sampling logic.
// Pre-rules (security-critical) are evaluated first.
func (s *SamplingSink) Record(ctx context.Context, e *Event) {
	// Immutable pre-rules: always emit security-critical events.
	for _, r := range s.preRules {
		if r.Match == nil || r.Match(e) {
			s.inner.Record(ctx, e)
			return
		}
	}
	// User-defined rules.
	action, rate := s.defaultAction, s.defaultRate
	for _, r := range s.rules {
		if r.Match == nil || r.Match(e) {
			action, rate = r.Action, r.Rate
			break
		}
	}
	switch action {
	case ActionDrop:
		return
	case ActionSample:
		if s.rand() >= rate {
			return
		}
	case ActionAlways:
		// emit
	}
	s.inner.Record(ctx, e)
}

// --- default sampling rules ------------------------------------------------

// AlwaysDeny matches events with Decision == "deny".
func AlwaysDeny() SamplingRule {
	return SamplingRule{
		Match:  func(e *Event) bool { return e.Decision == "deny" },
		Action: ActionAlways,
	}
}

// AlwaysShadowDisagreement matches shadow disagreements.
func AlwaysShadowDisagreement() SamplingRule {
	return SamplingRule{
		Match:  func(e *Event) bool { return e.ShadowDisagreement },
		Action: ActionAlways,
	}
}

// AlwaysCanaryDisagreement matches canary disagreements.
func AlwaysCanaryDisagreement() SamplingRule {
	return SamplingRule{
		Match:  func(e *Event) bool { return e.CanaryAgreement != "" && e.CanaryAgreement != "match" },
		Action: ActionAlways,
	}
}

// AlwaysError matches error decisions.
func AlwaysError() SamplingRule {
	return SamplingRule{
		Match:  func(e *Event) bool { return e.Decision == "error" },
		Action: ActionAlways,
	}
}

func defaultRand() float64 {
	// Use the global math/rand/v2 source (concurrent-safe in Go 1.22+).
	return rand2Float64()
}
