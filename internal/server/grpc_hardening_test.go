// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// TestGRPC_BodyCapEnforced is the F11 regression guard. The HTTP
// handler caps /v1/authorize bodies at 1 MiB; both gRPC doors must
// honour the same cap so a caller can't bypass the HTTP limit by
// switching transports.
//
// We boot one engine on a bufconn server with a tiny cap (256 B) and
// submit a body slightly larger than the cap to each door, asserting
// the cap fires; we also assert a body just under the cap is NOT
// rejected by the cap (the engine's own verdict is allowed).
func TestGRPC_BodyCapEnforced(t *testing.T) {
	t.Parallel()
	eng, err := config.Compile(nativeTestConfig())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	holder := server.NewEngineHolder(eng)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	const limit = 256
	authv3.RegisterAuthorizationServer(gs, &server.ExtAuthzServer{Engines: holder, MaxRequestBytes: limit})
	authv1.RegisterAuthServer(gs, &server.NativeAuthServer{Engines: holder, MaxRequestBytes: limit})
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

	envoyCli := authv3.NewAuthorizationClient(conn)
	nativeCli := authv1.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bigBody := strings.Repeat("A", limit+128)

	// Door A (ext_authz). Oversize body returns a CheckResponse
	// whose gRPC status code is ResourceExhausted (Envoy will map
	// our DeniedResponse to HTTP 413 downstream).
	resp, err := envoyCli.Check(ctx, &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST", Path: "/x", Body: bigBody,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Door A Check: %v", err)
	}
	if got := resp.GetStatus().GetCode(); got != int32(codes.ResourceExhausted) {
		t.Errorf("Door A: status code = %d, want ResourceExhausted (%d)",
			got, int32(codes.ResourceExhausted))
	}

	// Door B (native). Oversize body returns codes.ResourceExhausted
	// directly on the gRPC status.
	if _, err := nativeCli.Authorize(ctx, &authv1.AuthorizeRequest{
		Method: "POST", Resource: "/x", Body: []byte(bigBody),
	}); err == nil {
		t.Fatalf("Door B: expected error, got nil")
	} else if c := status.Code(err); c != codes.ResourceExhausted {
		t.Errorf("Door B: code = %v, want ResourceExhausted", c)
	}

	// Negative control: a body just under the cap does NOT trip the
	// cap on either door. The engine may still deny on auth grounds,
	// but we only assert the cap itself didn't fire.
	smallBody := strings.Repeat("A", limit-32)
	if _, err := envoyCli.Check(ctx, &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Method: "POST", Path: "/x", Body: smallBody},
			},
		},
	}); err != nil {
		t.Fatalf("Door A under-cap: %v", err)
	}
	if _, err := nativeCli.Authorize(ctx, &authv1.AuthorizeRequest{
		Method: "POST", Resource: "/x", Body: []byte(smallBody),
	}); err != nil && status.Code(err) == codes.ResourceExhausted {
		t.Errorf("Door B under-cap: got ResourceExhausted, want engine verdict")
	}
}
