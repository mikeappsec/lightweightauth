// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !spire

package spire

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// fetchSVIDFromWorkloadAPI is the stub implementation when the go-spiffe
// dependency is not included (build without -tags=spire).
// It returns an error indicating SPIRE support requires the spire build tag.
func fetchSVIDFromWorkloadAPI(_ context.Context, _ *Source) error {
	return errors.New("spire: SPIRE support not compiled in — rebuild with -tags=spire")
}

// watchSVIDUpdates is the stub implementation that does nothing.
func watchSVIDUpdates(ctx context.Context, _ *Source) {
	slog.Warn("spire: SVID watcher not available (build without -tags=spire)")
	// Block until context is cancelled to prevent goroutine exit.
	<-ctx.Done()
	_ = time.Now() // prevent unused import
}
