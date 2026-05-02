package lwauthd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"
	"github.com/mikeappsec/lightweightauth/pkg/configstream"
	"github.com/mikeappsec/lightweightauth/pkg/observability/metrics"
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

// maxSnapshotBytes caps the size of a received config snapshot.
// Protects followers from OOM on malicious/buggy large payloads.
const maxSnapshotBytes = 4 * 1024 * 1024 // 4 MiB

// startFollowerSubscription runs a persistent configstream.Stream loop
// that receives compiled AuthConfig snapshots from the leader and swaps
// them into the holder. Reconnects with exponential backoff + jitter.
//
// When leaderCh is non-nil, the subscription terminates once the channel
// is closed (indicating this pod won the leader election). This prevents
// the pod from self-connecting to its own ConfigStream service.
//
// This enables active/active HA: even when this pod is not the leader,
// it serves auth requests using the latest config pushed by the leader.
// The /readyz probe already gates traffic until holder.Load() != nil,
// so followers remain unready until the first snapshot arrives.
func startFollowerSubscription(ctx context.Context, log *slog.Logger, opts Options, holder *server.EngineHolder, leaderCh <-chan struct{}) {
	nodeID := opts.ConfigStreamNodeID
	if nodeID == "" {
		nodeID, _ = os.Hostname()
		if nodeID == "" {
			nodeID = "unknown"
		}
	}

	tlsCreds, err := buildFollowerTLSCreds(opts)
	if err != nil {
		log.Error("follower: TLS configuration failed; subscription disabled", "err", err)
		return
	}

	// If we have a leader election channel, wrap the context so the
	// follower loop terminates when this pod becomes leader.
	if leaderCh != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		go func() {
			select {
			case <-leaderCh:
				log.Info("follower: this pod became leader; stopping configstream subscription")
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	runFollowerLoop(ctx, log, opts.ConfigStreamAddr, nodeID, holder, tlsCreds)
}

// StartFollowerForTest is the test-only entry point for the follower
// subscription loop. Exposed so package-level tests can exercise the
// reconnect behavior without the full HTTP/gRPC stack.
func StartFollowerForTest(ctx context.Context, addr, nodeID string, holder *server.EngineHolder) {
	log := slog.New(slog.NewTextHandler(stderrSink{}, nil))
	runFollowerLoop(ctx, log, addr, nodeID, holder, nil)
}

func runFollowerLoop(ctx context.Context, log *slog.Logger, addr, nodeID string, holder *server.EngineHolder, tlsCreds credentials.TransportCredentials) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := runFollowerStream(ctx, log, addr, nodeID, holder, tlsCreds)
		if ctx.Err() != nil {
			return // shutting down
		}

		// Backoff with jitter before reconnect.
		idx := attempt
		if idx >= len(followerBackoff) {
			idx = len(followerBackoff) - 1
		}
		delay := followerBackoff[idx]
		// Add up to 50% jitter to prevent thundering herd.
		jitter := time.Duration(rand.Int63n(int64(delay / 2)))
		delay += jitter

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
func runFollowerStream(ctx context.Context, log *slog.Logger, addr, nodeID string, holder *server.EngineHolder, tlsCreds credentials.TransportCredentials) error {
	var dialOpt grpc.DialOption
	if tlsCreds != nil {
		dialOpt = grpc.WithTransportCredentials(tlsCreds)
	} else {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(addr,
		dialOpt,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxSnapshotBytes)),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Info("configstream follower subscribing", "addr", addr, "nodeID", nodeID, "tls", tlsCreds != nil)

	var lastVersion uint64
	return configstream.Stream(ctx, conn, nodeID, func(_ context.Context, version uint64, spec *config.AuthConfig) error {
		// Version monotonicity check — reject replayed older snapshots.
		if version <= lastVersion && lastVersion > 0 {
			log.Warn("follower: rejected non-monotonic snapshot version",
				"received", version, "last", lastVersion)
			return nil
		}
		lastVersion = version

		eng, compileErr := config.Compile(spec)
		if compileErr != nil {
			log.Error("follower: compile snapshot failed; keeping previous engine",
				"version", version, "err", compileErr)
			metrics.RecordCacheDistSF("follower_compile_error")
			return nil // don't tear down the stream for a bad snapshot
		}
		holder.Swap(eng)
		log.Info("follower: engine swapped from configstream", "version", version)
		return nil
	})
}

// buildFollowerTLSCreds constructs gRPC transport credentials for the
// follower subscription. When gRPC TLS is configured (server cert +
// client CA), the follower uses mTLS. Otherwise returns nil (insecure).
func buildFollowerTLSCreds(opts Options) (credentials.TransportCredentials, error) {
	if opts.GRPCTLSCertFile == "" || opts.GRPCTLSKeyFile == "" {
		// No TLS configured — allow insecure for dev/test.
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(opts.GRPCTLSCertFile, opts.GRPCTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("follower tls: load keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if opts.GRPCTLSClientCAFile != "" {
		pem, err := os.ReadFile(opts.GRPCTLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("follower tls: read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("follower tls: no PEM certs in %s", opts.GRPCTLSClientCAFile)
		}
		tlsCfg.RootCAs = pool
	}

	return credentials.NewTLS(tlsCfg), nil
}
