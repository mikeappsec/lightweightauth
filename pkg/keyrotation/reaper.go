// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package keyrotation

import (
	"context"
	"log/slog"
	"time"
)

// ReaperConfig configures the background key rotation reaper.
type ReaperConfig struct {
	// Interval is how often the reaper runs. Default: 60s.
	Interval time.Duration
	// Clock overrides the time source. Default: time.Now. Must match
	// the clock used by the KeySet for state transitions to be detected
	// correctly.
	Clock func() time.Time
	// OnPrune is called when keys are pruned with their KIDs.
	OnPrune func(pruned []string)
	// OnTransition is called when a key changes state.
	OnTransition func(kid string, from, to KeyState)
}

// Reaper is a background worker that periodically prunes retired keys
// from a KeySet and emits metrics when keys transition lifecycle state.
// It replaces the passive lazy-prune-on-Get/Put approach with proactive
// maintenance, ensuring retired keys don't accumulate and state
// transitions are observed promptly.
type Reaper[T any] struct {
	keyset *KeySet[T]
	cfg    ReaperConfig
	cancel context.CancelFunc
	done   chan struct{}
	clock  func() time.Time
	// snapshot of last-observed states for transition detection.
	lastState map[string]KeyState
}

// NewReaper starts a background reaper goroutine for the given KeySet.
// The reaper runs until ctx is cancelled or Stop is called.
func NewReaper[T any](ctx context.Context, ks *KeySet[T], cfg ReaperConfig) *Reaper[T] {
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}

	ctx, cancel := context.WithCancel(ctx)
	r := &Reaper[T]{
		keyset:    ks,
		cfg:       cfg,
		cancel:    cancel,
		done:      make(chan struct{}),
		clock:     clock,
		lastState: make(map[string]KeyState),
	}
	go r.loop(ctx)
	return r
}

// Stop halts the reaper and waits for the goroutine to exit.
func (r *Reaper[T]) Stop() {
	r.cancel()
	<-r.done
}

func (r *Reaper[T]) loop(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick()
		}
	}
}

func (r *Reaper[T]) tick() {
	// Detect state transitions before pruning.
	allMeta := r.keyset.All()
	now := r.clock()

	for _, meta := range allMeta {
		currentState := meta.State(now)
		if prev, known := r.lastState[meta.KID]; known && prev != currentState {
			if r.cfg.OnTransition != nil {
				r.cfg.OnTransition(meta.KID, prev, currentState)
			}
			slog.Info("key state transition",
				"kid", meta.KID,
				"from", string(prev),
				"to", string(currentState),
			)
		}
		r.lastState[meta.KID] = currentState
	}

	// Prune retired keys.
	pruned := r.keyset.Prune()
	if len(pruned) > 0 {
		// Clean up lastState tracking for pruned keys.
		for _, kid := range pruned {
			delete(r.lastState, kid)
		}
		if r.cfg.OnPrune != nil {
			r.cfg.OnPrune(pruned)
		}
		slog.Info("reaper pruned retired keys", "count", len(pruned), "kids", pruned)
	}
}
