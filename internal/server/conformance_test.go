// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// bootBothDoors compiles ONE engine and serves both Door A (ext_authz)
// and Door B (native) on the same gRPC server, returning a client for
// each. This is the harness that proves DESIGN.md §1's claim:
//
//	Door A handler ──► extauthz.toRequest()  ─┐
//	                                          ├─► pipeline.Evaluate
//	Door B handler ──► nativev1.toRequest() ─┘
//
// is symmetric: equivalent inputs produce equivalent decisions.
func bootBothDoors(t *testing.T) (authv3.AuthorizationClient, authv1.AuthClient) {
	t.Helper()
	eng, err := config.Compile(nativeTestConfig())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	holder := server.NewEngineHolder(eng)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, server.NewExtAuthzServer(holder))
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
	return authv3.NewAuthorizationClient(conn), authv1.NewAuthClient(conn)
}

// TestConformance_DoorAEqualsDoorB walks a small fixture table and asserts
// the allow/deny verdict is identical between the Envoy ext_authz and
// native authv1 surfaces for the *same* logical request.
//
// Notes on the comparison:
//   - Door A returns a gRPC status; OK ↔ allow, PermissionDenied ↔ deny.
//   - Door B always returns a normal AuthorizeResponse with Allow as a
//     bool; deny travels in the body, not in the gRPC status.
//   - We deliberately do NOT compare deny *reasons* byte-for-byte
//     because Door A's reason is the HTTP body Envoy will return to the
//     client, while Door B's is consumed programmatically by the
//     caller. Both originate from the same Decision.Reason though, so
//     the parity that matters (allow/deny + status code) is asserted.
func TestConformance_DoorAEqualsDoorB(t *testing.T) {
	t.Parallel()
	envoyCli, nativeCli := bootBothDoors(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cases := []struct {
		name      string
		header    string // "" means no API key sent
		wantAllow bool
		wantHTTP  int32 // expected http_status from Door B (0 on allow)
	}{
		{name: "admin allowed", header: "dev-admin-key", wantAllow: true, wantHTTP: 0},
		{name: "viewer denied", header: "dev-viewer-key", wantAllow: false, wantHTTP: 403},
		{name: "missing credential", header: "", wantAllow: false, wantHTTP: 401},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Door A.
			creq := &authv3.CheckRequest{
				Attributes: &authv3.AttributeContext{
					Request: &authv3.AttributeContext_Request{
						Http: &authv3.AttributeContext_HttpRequest{
							Method:  "GET",
							Path:    "/things",
							Host:    "api.test",
							Headers: map[string]string{},
						},
					},
				},
			}
			if tc.header != "" {
				creq.Attributes.Request.Http.Headers["x-api-key"] = tc.header
			}
			cresp, err := envoyCli.Check(ctx, creq)
			if err != nil {
				t.Fatalf("Door A Check: %v", err)
			}
			doorAAllow := codes.Code(cresp.Status.Code) == codes.OK

			// Door B.
			areq := &authv1.AuthorizeRequest{Method: "GET", Resource: "/things", Headers: map[string]string{}}
			if tc.header != "" {
				areq.Headers["x-api-key"] = tc.header
			}
			aresp, err := nativeCli.Authorize(ctx, areq)
			if err != nil {
				t.Fatalf("Door B Authorize: %v", err)
			}

			// Parity assertion.
			if doorAAllow != aresp.Allow {
				t.Errorf("allow mismatch: doorA=%v doorB=%v (doorA-msg=%q doorB-reason=%q)",
					doorAAllow, aresp.Allow, cresp.Status.Message, aresp.DenyReason)
			}
			if doorAAllow != tc.wantAllow {
				t.Errorf("doorA allow = %v, want %v", doorAAllow, tc.wantAllow)
			}

			// Door B carries the HTTP status hint as its own field.
			if !aresp.Allow && aresp.HttpStatus != tc.wantHTTP {
				t.Errorf("doorB http_status = %d, want %d", aresp.HttpStatus, tc.wantHTTP)
			}

			// On allow, Door B should also surface the identity. Door A
			// communicates identity to the upstream service via injected
			// headers (mutator concern), so we only check Door B here.
			if aresp.Allow && aresp.Identity == nil {
				t.Errorf("doorB allow without identity payload")
			}
		})
	}
}
