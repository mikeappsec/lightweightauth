package configstream

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

// allowAll is the test-only Authorizer that admits every stream. The
// production constructor refuses a nil Authorizer; tests pass this to
// exercise the snapshot path without a real auth layer.
var allowAll Authorizer = func(_ context.Context) error { return nil }

func startBufServer(t *testing.T, b *Broker) (*grpc.ClientConn, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	NewServer(b, allowAll).Register(gs)
	go func() {
		_ = gs.Serve(lis)
	}()
	cc, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return cc, func() {
		cc.Close()
		gs.GracefulStop()
	}
}

func TestServer_StreamsLatestThenUpdates(t *testing.T) {
	b := NewBroker()
	b.Publish(&config.AuthConfig{TenantID: "v1"})

	cc, cleanup := startBufServer(t, b)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := make(chan struct {
		v   uint64
		ten string
	}, 8)
	streamErr := make(chan error, 1)
	go func() {
		streamErr <- Stream(ctx, cc, "node-A", func(_ context.Context, v uint64, spec *config.AuthConfig) error {
			got <- struct {
				v   uint64
				ten string
			}{v, spec.TenantID}
			return nil
		})
	}()

	first := <-got
	if first.v != 1 || first.ten != "v1" {
		t.Fatalf("first = %+v", first)
	}

	b.Publish(&config.AuthConfig{TenantID: "v2"})
	second := <-got
	if second.v != 2 || second.ten != "v2" {
		t.Fatalf("second = %+v", second)
	}

	cancel()
	select {
	case <-streamErr:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not exit after cancel")
	}
}

func TestServer_MultipleClients(t *testing.T) {
	b := NewBroker()
	cc, cleanup := startBufServer(t, b)
	defer cleanup()

	const N = 4
	var observed atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < N; i++ {
		go func() {
			_ = Stream(ctx, cc, "node", func(_ context.Context, _ uint64, spec *config.AuthConfig) error {
				if spec.TenantID == "broadcast" {
					observed.Add(1)
				}
				return nil
			})
		}()
	}
	time.Sleep(100 * time.Millisecond) // let streams open
	b.Publish(&config.AuthConfig{TenantID: "broadcast"})

	deadline := time.After(2 * time.Second)
	for observed.Load() < N {
		select {
		case <-deadline:
			t.Fatalf("only %d/%d clients observed", observed.Load(), N)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
