// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// bootGRPC compiles a minimal apikey+rbac AuthConfig and exposes it over a
// bufconn gRPC server registered as an Envoy ext_authz Authorization
// service.
func bootGRPC(t *testing.T) authv3.AuthorizationClient {
	t.Helper()
	ac := &config.AuthConfig{
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
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	holder := server.NewEngineHolder(eng)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, server.NewExtAuthzServer(holder))
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
	return authv3.NewAuthorizationClient(conn)
}

// checkReq builds an Envoy CheckRequest carrying the given header.
func checkReq(headerKey, headerVal string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Path:    "/things",
					Host:    "api.test",
					Headers: map[string]string{headerKey: headerVal},
				},
			},
		},
	}
}

func TestExtAuthz_AllowsAdmin(t *testing.T) {
	t.Parallel()
	cli := bootGRPC(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := cli.Check(ctx, checkReq("x-api-key", "dev-admin-key"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got, want := codes.Code(resp.Status.Code), codes.OK; got != want {
		t.Fatalf("status code = %v, want %v (msg=%q)", got, want, resp.Status.Message)
	}
	if _, ok := resp.HttpResponse.(*authv3.CheckResponse_OkResponse); !ok {
		t.Errorf("HttpResponse type = %T, want OkResponse", resp.HttpResponse)
	}
}

func TestExtAuthz_DeniesViewer(t *testing.T) {
	t.Parallel()
	cli := bootGRPC(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := cli.Check(ctx, checkReq("x-api-key", "dev-viewer-key"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got, want := codes.Code(resp.Status.Code), codes.PermissionDenied; got != want {
		t.Fatalf("status code = %v, want %v (msg=%q)", got, want, resp.Status.Message)
	}
	dr, ok := resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatalf("HttpResponse type = %T, want DeniedResponse", resp.HttpResponse)
	}
	if dr.DeniedResponse.Status.Code != 403 {
		t.Errorf("denied http status = %v, want 403", dr.DeniedResponse.Status.Code)
	}
}

func TestExtAuthz_RejectsMissingCredential(t *testing.T) {
	t.Parallel()
	cli := bootGRPC(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No x-api-key header at all.
	resp, err := cli.Check(ctx, &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Method: "GET", Path: "/things"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := codes.Code(resp.Status.Code); got != codes.Unauthenticated && got != codes.PermissionDenied {
		t.Fatalf("status code = %v, want Unauthenticated or PermissionDenied", got)
	}
	if _, ok := resp.HttpResponse.(*authv3.CheckResponse_DeniedResponse); !ok {
		t.Errorf("HttpResponse type = %T, want DeniedResponse", resp.HttpResponse)
	}
}

// silence unused — keeps corev3 import resilient if helper grows.
var _ = corev3.HeaderValue{}
