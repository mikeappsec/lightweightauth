package lwauthd

import (
	"context"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"
	"github.com/mikeappsec/lightweightauth/pkg/configstream"
)

// followerBackoff defines the reconnect backoff schedule for the
// configstream subscription loop.
var followerBackoff = []time.Duration{
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	5 * time.Second,
	10 * time.Second,
}

// startFollowerSubscription runs a persistent configstream.Stream loop
// that receives compiled AuthConfig snapshots from the leader and swaps
// them into the holder. Reconnects with exponential backoff on failure.
//
// This enables active/active HA: even when this pod is not the leader,
// it serves auth requests using the latest config pushed by the leader.
// The /readyz probe already gates traffic until holder.Load() != nil,
// so followers remain unready until the first snapshot arrives.
func startFollowerSubscription(ctx context.Context, log *slog.Logger, opts Options, holder *server.EngineHolder) {
	nodeID := opts.ConfigStreamNodeID
	if nodeID == "" {
		nodeID, _ = os.Hostname()
		if nodeID == "" {
			nodeID = "unknown"
		}
	}
	runFollowerLoop(ctx, log, opts.ConfigStreamAddr, nodeID, holder)
}

// StartFollowerForTest is the test-only entry point for the follower
// subscription loop. Exposed so package-level tests can exercise the
// reconnect behavior without the full HTTP/gRPC stack.
func StartFollowerForTest(ctx context.Context, addr, nodeID string, holder *server.EngineHolder) {
	log := slog.New(slog.NewTextHandler(stderrSink{}, nil))
	runFollowerLoop(ctx, log, addr, nodeID, holder)
}

func runFollowerLoop(ctx context.Context, log *slog.Logger, addr, nodeID string, holder *server.EngineHolder) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := runFollowerStream(ctx, log, addr, nodeID, holder)
		if ctx.Err() != nil {
			return // shutting down
		}

		// Backoff before reconnect.
		idx := attempt
		if idx >= len(followerBackoff) {
			idx = len(followerBackoff) - 1
		}
		delay := followerBackoff[idx]
		log.Warn("configstream subscription disconnected; reconnecting",
			"err", err, "attempt", attempt, "backoff", delay)
		attempt++

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// runFollowerStream opens a single configstream.Stream session. Returns
// when the stream ends or errors.
func runFollowerStream(ctx context.Context, log *slog.Logger, addr, nodeID string, holder *server.EngineHolder) error {
	// Use insecure by default; in production the gRPC listener should be
	// protected by mTLS at the transport level (configured separately).
	// TODO: support TLS credentials from Options when GRPCTLSClientCA is set.
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Info("configstream follower subscribing", "addr", addr, "nodeID", nodeID)

	return configstream.Stream(ctx, conn, nodeID, func(_ context.Context, version uint64, spec *config.AuthConfig) error {
		eng, compileErr := config.Compile(spec)
		if compileErr != nil {
			log.Error("follower: compile snapshot failed; keeping previous engine",
				"version", version, "err", compileErr)
			return nil // don't tear down the stream for a bad snapshot
		}
		holder.Swap(eng)
		log.Info("follower: engine swapped from configstream", "version", version)
		return nil
	})
}
