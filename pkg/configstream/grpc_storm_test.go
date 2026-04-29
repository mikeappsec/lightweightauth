package configstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

// gRPC keeps a small handful of long-lived helpers per (server
// transport, client conn). They unwind on GracefulStop / conn.Close,
// but the unwind is asynchronous, so allow-list the well-known frames.
// Our Broker pump goroutines (broker.go) are NOT in this list, so a
// real pump leak still fails the test.
//
// TEST-RACE-1: the original list covered only server-side helpers,
// which let the client-side counterparts (http2Client.{reader,keepalive},
// addrConn.resetTransport, the resolver/balancer callback serializers)
// race the goleak check under -race ./... when many goroutines compete
// for the scheduler. The mirrored client-side entries below close that
// gap; everything here is a known-bounded gRPC internal that exits on
// cc.Close() / GracefulStop(), not a Broker subscription pump.
var grpcGoleakIgnores = []goleak.Option{
	// Server side.
	goleak.IgnoreAnyFunction("google.golang.org/grpc.(*Server).handleStream"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc.(*Server).serveStreams"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc.(*Server).handleRawConn.func1"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc/internal/transport.(*http2Server).keepalive"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc/internal/transport.(*http2Server).HandleStreams"),
	// Client side (mirror of the server entries).
	goleak.IgnoreAnyFunction("google.golang.org/grpc.(*ccBalancerWrapper).watcher"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc.(*addrConn).resetTransport"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc.(*ClientConn).updateResolverState"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc/internal/transport.(*http2Client).reader"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc/internal/transport.(*http2Client).keepalive"),
	// Shared (transport-direction agnostic).
	goleak.IgnoreAnyFunction("google.golang.org/grpc/internal/transport.(*controlBuffer).get"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc/internal/transport.(*loopyWriter).run"),
	goleak.IgnoreAnyFunction("google.golang.org/grpc/internal/grpcsync.(*CallbackSerializer).run"),
}

// verifyNoBrokerLeaks is goleak.VerifyNone with a small settle window
// so post-handler-return gRPC helpers can finish unwinding. The window
// is intentionally short — a real Broker subscription pump leak does
// NOT exit on its own, so it will still trip the check after the
// settle. Any real leak is therefore caught; only the cosmetic
// "GracefulStop returned before the http2 transport's last goroutine
// scheduled out" race is masked.
func verifyNoBrokerLeaks(t *testing.T) {
	t.Helper()
	// 50ms is well over the worst observed unwind on CI under -race.
	time.Sleep(50 * time.Millisecond)
	goleak.VerifyNone(t, grpcGoleakIgnores...)
}

// TestGRPC_MultiClientReconnectStorm is the M12 multi-client xDS-push
// integration: one Broker behind a gRPC server with N concurrent
// Stream() clients, churn reconnections under a steady publish stream,
// assert every long-lived stream converges to the final published
// version and per-stream sequences never go backwards.
//
// Mode of failure caught:
//   - broker drops snapshots when subscribers join/leave concurrently
//     with publishes (latest-wins);
//   - per-stream version sequence ever goes backwards;
//   - server handler tears a client down on benign sub-channel events;
//   - broker subscription pump leaks across short-lived subscribers.
func TestGRPC_MultiClientReconnectStorm(t *testing.T) {
	const (
		clients         = 16
		reconnectsEach  = 3
		totalPublishes  = 100
		publishInterval = 2 * time.Millisecond
	)

	b := NewBroker()

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	NewServer(b, allowAll).Register(gs)
	go func() { _ = gs.Serve(lis) }()
	// Cleanups run LIFO: goleak last, after GracefulStop has finished
	// unwinding the server transport goroutines.
	t.Cleanup(func() { verifyNoBrokerLeaks(t) })
	t.Cleanup(func() { gs.GracefulStop() })

	dialer := func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }

	pubCtx, pubCancel := context.WithCancel(context.Background())
	publisherDone := make(chan struct{})
	var lastPublished atomic.Uint64
	// Prime so the first Subscribe gets a "current" snapshot.
	b.Publish(&config.AuthConfig{TenantID: "v1"})
	lastPublished.Store(1)
	go func() {
		defer close(publisherDone)
		tk := time.NewTicker(publishInterval)
		defer tk.Stop()
		for k := 2; k <= totalPublishes+1; k++ {
			select {
			case <-pubCtx.Done():
				return
			case <-tk.C:
			}
			b.Publish(&config.AuthConfig{TenantID: fmt.Sprintf("v%d", k)})
			lastPublished.Store(uint64(k))
		}
	}()
	t.Cleanup(pubCancel)

	// One shared client conn — gRPC multiplexes N streams over one
	// HTTP/2 connection, exercising the per-stream subscription path
	// without conflating reconnect with dial cost.
	cc, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	runOneStream := func(parent context.Context, id int, observeAtLeast int) error {
		var count atomic.Int32
		streamCtx, streamCancel := context.WithCancel(parent)
		defer streamCancel()

		errCh := make(chan error, 1)
		go func() {
			seen := uint64(0)
			errCh <- Stream(streamCtx, cc, fmt.Sprintf("node-%d", id),
				func(_ context.Context, v uint64, _ *config.AuthConfig) error {
					if v < seen {
						return fmt.Errorf("client %d: version backwards %d -> %d", id, seen, v)
					}
					seen = v
					count.Add(1)
					return nil
				})
		}()

		deadline := time.After(5 * time.Second)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for count.Load() < int32(observeAtLeast) {
			select {
			case err := <-errCh:
				return fmt.Errorf("stream exited early after %d msgs: %w", count.Load(), err)
			case <-deadline:
				return fmt.Errorf("only observed %d/%d before deadline", count.Load(), observeAtLeast)
			case <-ticker.C:
			}
		}
		streamCancel()
		<-errCh
		return nil
	}

	finalHighest := make([]atomic.Uint64, clients)
	streamErrs := make([]error, clients)
	var wg sync.WaitGroup

	clientCtx, clientCancel := context.WithCancel(context.Background())
	t.Cleanup(clientCancel)

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for r := 0; r < reconnectsEach; r++ {
				if err := runOneStream(clientCtx, id, 2); err != nil {
					streamErrs[id] = err
					return
				}
			}

			streamCtx, streamCancel := context.WithCancel(clientCtx)
			defer streamCancel()

			var finalSeen atomic.Uint64
			done := make(chan error, 1)
			go func() {
				seen := uint64(0)
				done <- Stream(streamCtx, cc, fmt.Sprintf("node-%d-final", id),
					func(_ context.Context, v uint64, _ *config.AuthConfig) error {
						if v < seen {
							return fmt.Errorf("client %d final: backwards %d -> %d", id, seen, v)
						}
						seen = v
						finalSeen.Store(v)
						return nil
					})
			}()

			<-publisherDone
			final := lastPublished.Load()
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) && finalSeen.Load() < final {
				time.Sleep(5 * time.Millisecond)
			}
			finalHighest[id].Store(finalSeen.Load())
			streamCancel()
			<-done
		}(i)
	}

	wg.Wait()

	final := lastPublished.Load()
	if final == 0 {
		t.Fatal("publisher never ran")
	}
	for i := 0; i < clients; i++ {
		if streamErrs[i] != nil {
			t.Errorf("client %d: %v", i, streamErrs[i])
			continue
		}
		if got := finalHighest[i].Load(); got < final {
			t.Errorf("client %d: highest=%d, expected >= final=%d (latest-wins broken)",
				i, got, final)
		}
	}
}

// TestGRPC_ServerCancelClosesAllClients: GracefulStop on the server
// tears every Stream() RPC down promptly with a non-nil transport
// error and no broker subscription pump leaks.
func TestGRPC_ServerCancelClosesAllClients(t *testing.T) {
	const clients = 6

	b := NewBroker()
	b.Publish(&config.AuthConfig{TenantID: "initial"})

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	NewServer(b, allowAll).Register(gs)
	go func() { _ = gs.Serve(lis) }()

	t.Cleanup(func() { verifyNoBrokerLeaks(t) })

	dialer := func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }
	cc, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	primed := make(chan struct{}, clients)
	exited := make(chan error, clients)

	clientCtx, clientCancel := context.WithCancel(context.Background())
	t.Cleanup(clientCancel)

	for i := 0; i < clients; i++ {
		go func(id int) {
			gotFirst := false
			err := Stream(clientCtx, cc, fmt.Sprintf("node-%d", id),
				func(_ context.Context, _ uint64, _ *config.AuthConfig) error {
					if !gotFirst {
						gotFirst = true
						primed <- struct{}{}
					}
					return nil
				})
			exited <- err
		}(i)
	}

	for i := 0; i < clients; i++ {
		select {
		case <-primed:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d/%d clients primed", i, clients)
		}
	}

	// Stop() (not GracefulStop) — we are explicitly testing that the
	// server tears active in-flight RPCs down, which is exactly what
	// GracefulStop refuses to do.
	gs.Stop()

	for i := 0; i < clients; i++ {
		select {
		case err := <-exited:
			if err == nil {
				t.Errorf("client %d exited with nil error after server stop", i)
			} else if errors.Is(err, context.Canceled) {
				t.Errorf("client %d exited with context.Canceled (expected transport error): %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d/%d clients exited", i, clients)
		}
	}
}
