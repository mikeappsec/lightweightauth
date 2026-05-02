// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"log/slog"
)

// MultiSink fans out every event to all wrapped sinks. If any sink
// panics the others still receive the event (best-effort delivery).
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink creates a sink that dispatches to all provided sinks.
func NewMultiSink(sinks ...Sink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

// Record implements Sink by calling Record on every wrapped sink.
func (m *MultiSink) Record(ctx context.Context, e *Event) {
	for _, s := range m.sinks {
		sink := s
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("audit: sink panicked", "sink", fmt.Sprintf("%T", sink), "panic", r)
				}
			}()
			sink.Record(ctx, e)
		}()
	}
}
