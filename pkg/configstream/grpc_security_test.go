package configstream

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
)

// TestNewServer_PanicsWithoutAuthorizer is the fail-closed fence on
// ConfigDiscovery construction. AuthConfigSnapshot bytes are trust
// material for every consumer pod; the constructor refuses to build a
// server without an explicit Authorizer rather than ship a default-open
// endpoint.
func TestNewServer_PanicsWithoutAuthorizer(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewServer(b, nil) must panic")
		}
	}()
	b := NewBroker()
	_ = NewServer(b, nil)
}

// TestServer_AuthorizerGatesStream confirms a non-nil Authorizer error
// short-circuits the stream before any snapshot is sent, and that a
// non-status error is normalised to codes.Unauthenticated.
func TestServer_AuthorizerGatesStream(t *testing.T) {
	t.Parallel()

	b := NewBroker()
	// Prime a snapshot so we can prove the stream never delivered it.
	b.Publish(&config.AuthConfig{TenantID: "t1"})

	denied := errors.New("token missing")
	srv := NewServer(b, func(_ context.Context) error { return denied })

	gs := grpc.NewServer()
	srv.Register(gs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go gs.Serve(lis)
	defer gs.Stop()

	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := authv1.NewConfigDiscoveryClient(cc).StreamAuthConfig(ctx, &authv1.StreamAuthConfigRequest{})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	_, err = stream.Recv()
	if err == nil {
		t.Fatal("recv must fail when authorizer denies; got snapshot")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %s, want Unauthenticated", st.Code())
	}
	if !strings.Contains(st.Message(), "token missing") {
		t.Errorf("message should surface authorizer error: %q", st.Message())
	}
}

// TestServer_AuthorizerStatusErrorPreserved confirms a status.Error from
// the Authorizer is propagated verbatim (code + message), letting
// embedders pick the most precise code (e.g. PermissionDenied vs
// Unauthenticated).
func TestServer_AuthorizerStatusErrorPreserved(t *testing.T) {
	t.Parallel()

	b := NewBroker()
	b.Publish(&config.AuthConfig{TenantID: "t1"})

	want := status.Error(codes.PermissionDenied, "tenant not allowed")
	srv := NewServer(b, func(_ context.Context) error { return want })

	gs := grpc.NewServer()
	srv.Register(gs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go gs.Serve(lis)
	defer gs.Stop()

	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := authv1.NewConfigDiscoveryClient(cc).StreamAuthConfig(ctx, &authv1.StreamAuthConfigRequest{})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	_, err = stream.Recv()
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("code = %s, want PermissionDenied", st.Code())
	}
	if st.Message() != "tenant not allowed" {
		t.Errorf("message = %q, want %q", st.Message(), "tenant not allowed")
	}
}
