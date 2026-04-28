package configstream

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
)

// Server adapts a *Broker to the ConfigDiscovery gRPC service. Each
// inbound StreamAuthConfig RPC subscribes once and forwards every
// snapshot until the client disconnects or the broker is dropped.
type Server struct {
	authv1.UnimplementedConfigDiscoveryServer
	broker *Broker
}

// NewServer wraps b. The returned value is registered with a
// grpc.Server via Register.
func NewServer(b *Broker) *Server {
	return &Server{broker: b}
}

// Register attaches s to gs under the standard
// lightweightauth.v1.ConfigDiscovery service name.
func (s *Server) Register(gs grpc.ServiceRegistrar) {
	authv1.RegisterConfigDiscoveryServer(gs, s)
}

// StreamAuthConfig serves one client. It subscribes to the broker
// (which primes the channel with the latest snapshot, if any) and
// forwards each value as a JSON-encoded AuthConfigSnapshot until the
// client cancels.
func (s *Server) StreamAuthConfig(_ *authv1.StreamAuthConfigRequest, stream grpc.ServerStreamingServer[authv1.AuthConfigSnapshot]) error {
	ctx := stream.Context()
	sub := s.broker.Subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case snap, ok := <-sub:
			if !ok {
				return nil
			}
			body, err := json.Marshal(snap.Spec)
			if err != nil {
				return fmt.Errorf("marshal spec: %w", err)
			}
			if err := stream.Send(&authv1.AuthConfigSnapshot{
				Version:  snap.Version,
				SpecJson: body,
			}); err != nil {
				return err
			}
		}
	}
}

// ClientHandler is the callback Stream invokes once per received
// snapshot. Returning an error tears the stream down so the caller's
// reconnect loop kicks in.
type ClientHandler func(ctx context.Context, version uint64, spec *config.AuthConfig) error

// Stream opens a StreamAuthConfig RPC against cc and feeds every
// received snapshot to handle. It blocks until ctx is canceled or the
// server / handler returns an error. A trivial caller is:
//
//	go configstream.Stream(ctx, conn, "lwauth-pod-7", func(_ context.Context, _ uint64, spec *config.AuthConfig) error {
//	    eng, err := config.Compile(spec)
//	    if err != nil { return err }
//	    holder.Swap(eng)
//	    return nil
//	})
//
// Reconnect logic (back-off, jitter) is the caller's responsibility;
// Stream is one-shot so it composes cleanly with golang.org/x/sync
// Group or any retry library.
func Stream(ctx context.Context, cc grpc.ClientConnInterface, nodeID string, handle ClientHandler) error {
	client := authv1.NewConfigDiscoveryClient(cc)
	stream, err := client.StreamAuthConfig(ctx, &authv1.StreamAuthConfigRequest{NodeId: nodeID})
	if err != nil {
		return fmt.Errorf("open StreamAuthConfig: %w", err)
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		var spec config.AuthConfig
		if err := json.Unmarshal(msg.GetSpecJson(), &spec); err != nil {
			return fmt.Errorf("decode spec v%d: %w", msg.GetVersion(), err)
		}
		if err := handle(ctx, msg.GetVersion(), &spec); err != nil {
			return fmt.Errorf("handle v%d: %w", msg.GetVersion(), err)
		}
	}
}
