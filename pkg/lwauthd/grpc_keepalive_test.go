package lwauthd

import (
	"testing"
	"time"

	"google.golang.org/grpc"
)

// TestBuildGRPCServerOptions_F14_KeepaliveAndStreamsWired asserts the
// gRPC server is built with keepalive enforcement, connection-age /
// idle limits, and a MaxConcurrentStreams ceiling so a malicious
// client can't park thousands of idle TCP/HTTP-2 connections to
// exhaust file descriptors and goroutines (each accepted gRPC
// connection spawns a server reader goroutine via
// transport.http2Server).
//
// We can't introspect the constructed *grpc.Server (the stdlib type
// hides its serverOptions), so the assertion is:
//   - buildGRPCServerOptions returns the expected option count given
//     the configured knobs;
//   - feeding the slice into grpc.NewServer does not panic (panic on
//     conflicting options would be the canary for a wiring bug).
//
// The behavioural surface (idle tear-down, GOAWAY at age) is owned by
// the gRPC library; we only verify that lwauthd hands it the right
// dials.
func TestBuildGRPCServerOptions_F14_KeepaliveAndStreamsWired(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts Options
		// Expected slice length:
		//   1 (MaxRecvMsgSize) + 1 (KeepaliveEnforcementPolicy)
		// + 1 (KeepaliveParams) + 1 (MaxConcurrentStreams) = 4
		// when no TLS is configured.
		wantLen int
	}{
		{
			name:    "defaults",
			opts:    Options{},
			wantLen: 4,
		},
		{
			name: "explicit knobs",
			opts: Options{
				GRPCKeepaliveMinTime:      45 * time.Second,
				GRPCKeepaliveTime:         2 * time.Minute,
				GRPCKeepaliveTimeout:      30 * time.Second,
				GRPCMaxConnectionIdle:     10 * time.Minute,
				GRPCMaxConnectionAge:      45 * time.Minute,
				GRPCMaxConnectionAgeGrace: 1 * time.Minute,
				GRPCMaxConcurrentStreams:  2048,
			},
			wantLen: 4,
		},
		{
			name:    "body cap disabled (-1) drops MaxRecvMsgSize",
			opts:    Options{MaxRequestBytes: -1},
			wantLen: 3, // no MaxRecvMsgSize, but keepalive triplet still present
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildGRPCServerOptions(tc.opts)
			if err != nil {
				t.Fatalf("buildGRPCServerOptions: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Errorf("len(opts) = %d, want %d", len(got), tc.wantLen)
			}
			// Must not panic when handed to grpc.NewServer.
			s := grpc.NewServer(got...)
			s.Stop()
		})
	}
}
