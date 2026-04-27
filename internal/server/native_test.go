package server_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// bootNative reuses the same AuthConfig as bootGRPC (apikey + RBAC) but
// exposes it over the native lightweightauth.v1.Auth service. Tests
// asserting Door A == Door B parity rely on the configs being identical
// — see [conformance_test.go].
func bootNative(t *testing.T) authv1.AuthClient {
	t.Helper()
	ac := nativeTestConfig()
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	holder := server.NewEngineHolder(eng)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	authv1.RegisterAuthServer(gs, server.NewNativeAuthServer(holder))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(context.Background())
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return authv1.NewAuthClient(conn)
}

// nativeTestConfig is the shared AuthConfig fixture for native + parity
// tests. apikey identifier + rbac authorizer keeps the surface focused
// on the transport adapters; M5/M6 modules exercise their own logic.
func nativeTestConfig() *config.AuthConfig {
	return &config.AuthConfig{
		Identifier: config.IdentifierFirstMatch,
		Identifiers: []config.ModuleSpec{{
			Name: "dev-apikey",
			Type: "apikey",
			Config: map[string]any{
				"headerName": "X-Api-Key",
				"static": map[string]any{
					"dev-admin-key":  map[string]any{"subject": "alice", "roles": []any{"admin"}},
					"dev-viewer-key": map[string]any{"subject": "carol", "roles": []any{"viewer"}},
				},
			},
		}},
		Authorizers: []config.ModuleSpec{{
			Name: "rbac",
			Type: "rbac",
			Config: map[string]any{
				"rolesFrom": "claim:roles",
				"allow":     []any{"admin", "editor"},
			},
		}},
	}
}

func authReq(headerKey, headerVal string) *authv1.AuthorizeRequest {
	return &authv1.AuthorizeRequest{
		Method:   "GET",
		Resource: "/things",
		Headers:  map[string]string{headerKey: headerVal},
	}
}

func TestNativeAuthorize_AllowsAdmin(t *testing.T) {
	t.Parallel()
	cli := bootNative(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := cli.Authorize(ctx, authReq("x-api-key", "dev-admin-key"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !resp.Allow {
		t.Fatalf("expected allow, got deny: %s", resp.DenyReason)
	}
	if resp.Identity == nil || resp.Identity.Subject != "alice" {
		t.Errorf("identity not surfaced: %+v", resp.Identity)
	}
	if resp.Identity != nil && resp.Identity.Source != "dev-apikey" {
		t.Errorf("identity.source = %q, want dev-apikey", resp.Identity.Source)
	}
}

func TestNativeAuthorize_DeniesViewer(t *testing.T) {
	t.Parallel()
	cli := bootNative(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := cli.Authorize(ctx, authReq("x-api-key", "dev-viewer-key"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.Allow {
		t.Fatalf("expected deny for viewer")
	}
	if resp.HttpStatus != 403 {
		t.Errorf("http_status = %d, want 403", resp.HttpStatus)
	}
	if resp.DenyReason == "" {
		t.Errorf("deny_reason should not be empty")
	}
}

func TestNativeAuthorize_RejectsMissingCredential(t *testing.T) {
	t.Parallel()
	cli := bootNative(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := cli.Authorize(ctx, &authv1.AuthorizeRequest{Method: "GET", Resource: "/things"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if resp.Allow {
		t.Fatalf("expected deny for missing credential")
	}
	if resp.HttpStatus != 401 && resp.HttpStatus != 403 {
		t.Errorf("http_status = %d, want 401 or 403", resp.HttpStatus)
	}
}

// AuthorizeStream feeds three messages and expects three matching
// responses. The deny in the middle MUST NOT close the stream — the
// caller decides when to disconnect (DESIGN.md §1, Door B note on
// long-lived sessions).
func TestNativeAuthorize_StreamMixedDecisions(t *testing.T) {
	t.Parallel()
	cli := bootNative(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := cli.AuthorizeStream(ctx)
	if err != nil {
		t.Fatalf("AuthorizeStream: %v", err)
	}

	msgs := []struct {
		key  string
		want bool
	}{
		{"dev-admin-key", true},
		{"dev-viewer-key", false},
		{"dev-admin-key", true},
	}

	for i, m := range msgs {
		if err := stream.Send(authReq("x-api-key", m.key)); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv[%d]: %v", i, err)
		}
		if resp.Allow != m.want {
			t.Errorf("msg %d: allow=%v want=%v reason=%q", i, resp.Allow, m.want, resp.DenyReason)
		}
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if _, err := stream.Recv(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("trailing Recv: %v", err)
	}
}
