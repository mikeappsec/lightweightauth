// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package configstream

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
)

// Authorizer gates each inbound StreamAuthConfig RPC. It runs once at
// stream open with the gRPC stream context, which carries peer TLS state
// and per-call metadata. Returning a non-nil error tears the stream down
// before any snapshot is sent. Returning nil admits the stream.
//
// The fail-closed contract is intentional: AuthConfigSnapshot bytes ARE
// trust material (they shape every downstream authorize decision in every
// pod that consumes them), so an embedder who registers ConfigDiscovery
// MUST tell the server how to authenticate the caller. There is no
// "anonymous" mode.
type Authorizer func(ctx context.Context) error

// Server adapts a *Broker to the ConfigDiscovery gRPC service. Each
// inbound StreamAuthConfig RPC is gated by an Authorizer, then subscribes
// once and forwards every snapshot until the client disconnects or the
// broker is dropped.
type Server struct {
	authv1.UnimplementedConfigDiscoveryServer
	broker *Broker
	auth   Authorizer
}

// NewServer wraps b and gates every StreamAuthConfig call through auth.
// auth MUST be non-nil — passing nil panics rather than silently exposing
// the snapshot stream. Embedders who genuinely want an open endpoint
// should pass an explicit allow-everything Authorizer so the choice is
// visible in their own code review.
func NewServer(b *Broker, auth Authorizer) *Server {
	if auth == nil {
		panic("configstream.NewServer: Authorizer is required; pass an explicit allow function if you really want an open endpoint")
	}
	return &Server{broker: b, auth: auth}
}

// Register attaches s to gs under the standard
// lightweightauth.v1.ConfigDiscovery service name.
func (s *Server) Register(gs grpc.ServiceRegistrar) {
	authv1.RegisterConfigDiscoveryServer(gs, s)
}

// maxSnapshotBytes is the maximum serialized size of a single config
// snapshot that the server will send. Prevents OOM-bombing followers
// with pathologically large configs.
const maxSnapshotBytes = 4 * 1024 * 1024 // 4 MiB

// StreamAuthConfig serves one client. It runs the configured Authorizer
// against the stream context first, then subscribes to the broker (which
// primes the channel with the latest snapshot, if any) and forwards each
// value as a JSON-encoded AuthConfigSnapshot until the client cancels.
func (s *Server) StreamAuthConfig(_ *authv1.StreamAuthConfigRequest, stream grpc.ServerStreamingServer[authv1.AuthConfigSnapshot]) error {
	ctx := stream.Context()
	if err := s.auth(ctx); err != nil {
		// Preserve any gRPC status the Authorizer returned; otherwise
		// surface as Unauthenticated so callers see a stable code.
		if _, ok := status.FromError(err); ok {
			return err
		}
		return status.Errorf(codes.Unauthenticated, "configstream: %v", err)
	}
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
			if len(body) > maxSnapshotBytes {
				return status.Errorf(codes.ResourceExhausted,
					"snapshot v%d exceeds max size (%d > %d bytes)",
					snap.Version, len(body), maxSnapshotBytes)
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
