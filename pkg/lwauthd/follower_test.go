// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package lwauthd_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"
	"github.com/mikeappsec/lightweightauth/pkg/configstream"
	"github.com/mikeappsec/lightweightauth/pkg/lwauthd"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

const followerTestConfig = `
identifierMode: firstMatch
identifiers:
  - name: dev-apikey
    type: apikey
    config:
      headerName: X-Api-Key
      static:
        k1: { subject: alice, roles: [admin] }
authorizers:
  - name: rbac
    type: rbac
    config:
      rolesFrom: claim:roles
      allow: [admin]
`

func TestFollowerSubscription_ReceivesConfig(t *testing.T) {
	t.Parallel()

	// Set up a configstream server (simulating a leader).
	broker := configstream.NewBroker()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	configstream.NewServer(broker, func(ctx context.Context) error { return nil }).Register(gs)
	go gs.Serve(lis)
	defer gs.Stop()

	addr := lis.Addr().String()

	// Create a holder with no engine (simulates a cold follower).
	holder := server.NewEngineHolder(nil)
	if holder.Load() != nil {
		t.Fatal("expected nil engine at start")
	}

	// Start follower subscription via configstream.Stream directly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return
		}
		defer conn.Close()
		_ = configstream.Stream(ctx, conn, "test-follower", func(_ context.Context, version uint64, spec *config.AuthConfig) error {
			eng, err := config.Compile(spec)
			if err != nil {
				return nil
			}
			holder.Swap(eng)
			return nil
		})
	}()

	// Give the subscriber time to connect.
	time.Sleep(100 * time.Millisecond)

	// Publish a config snapshot (simulates leader reconcile).
	var spec config.AuthConfig
	if err := loadAuthConfigFromString(followerTestConfig, &spec); err != nil {
		t.Fatal(err)
	}
	broker.Publish(&spec)

	// Wait for the follower to receive and swap.
	deadline := time.After(3 * time.Second)
	for {
		if holder.Load() != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("follower did not receive config within 3s")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Verify the engine is functional.
	eng := holder.Load()
	if eng == nil {
		t.Fatal("engine should be non-nil after follower swap")
	}
}

func TestFollowerSubscription_ReconnectsOnDisconnect(t *testing.T) {
	t.Parallel()

	broker := configstream.NewBroker()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	configstream.NewServer(broker, func(ctx context.Context) error { return nil }).Register(gs)
	go gs.Serve(lis)

	addr := lis.Addr().String()
	holder := server.NewEngineHolder(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the follower with the full retry loop.
	go lwauthd.StartFollowerForTest(ctx, addr, "test-node", holder)

	// Give time to connect.
	time.Sleep(100 * time.Millisecond)

	// Publish first config.
	var spec config.AuthConfig
	if err := loadAuthConfigFromString(followerTestConfig, &spec); err != nil {
		t.Fatal(err)
	}
	broker.Publish(&spec)

	// Wait for engine swap.
	deadline := time.After(3 * time.Second)
	for holder.Load() == nil {
		select {
		case <-deadline:
			t.Fatal("follower did not receive config")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Stop the server to simulate leader crash.
	gs.Stop()
	lis.Close()

	// Restart on the same address.
	lis2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip("could not rebind same address")
	}
	gs2 := grpc.NewServer()
	broker2 := configstream.NewBroker()
	configstream.NewServer(broker2, func(ctx context.Context) error { return nil }).Register(gs2)
	go gs2.Serve(lis2)
	defer gs2.Stop()

	// Swap in a new engine via the new broker to verify reconnect worked.
	holder.Swap(nil) // clear engine to detect the new snapshot
	time.Sleep(2 * time.Second) // allow reconnect backoff

	broker2.Publish(&spec)
	deadline = time.After(5 * time.Second)
	for holder.Load() == nil {
		select {
		case <-deadline:
			t.Fatal("follower did not reconnect and receive config after leader restart")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func loadAuthConfigFromString(s string, ac *config.AuthConfig) error {
	return yaml.Unmarshal([]byte(s), ac)
}
