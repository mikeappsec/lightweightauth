package lwauthclient_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"
	lwauthclient "github.com/mikeappsec/lightweightauth/pkg/client/go"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// dialSDK boots an in-memory native server and returns an SDK Client
// pointed at it. Configuration matches internal/server/native_test
// (apikey + RBAC) so test reasoning is consistent across packages.
func dialSDK(t *testing.T) *lwauthclient.Client {
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
			Config: map[string]any{"rolesFrom": "claim:roles", "allow": []any{"admin"}},
		}},
		Response: []config.ModuleSpec{{
			Name: "x-user",
			Type: "header-add",
			Config: map[string]any{
				"upstream": map[string]any{"X-User": "${sub}"},
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
	return lwauthclient.NewWithConn(conn)
}

func TestClient_Authorize_AllowAndDeny(t *testing.T) {
	t.Parallel()
	cli := dialSDK(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	allow, err := cli.Authorize(ctx, &lwauthclient.Request{
		Method:   "GET",
		Resource: "/things",
		Headers:  map[string]string{"x-api-key": "dev-admin-key"},
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !allow.Allow {
		t.Fatalf("expected allow, got deny: %s", allow.DenyReason)
	}
	if allow.IdentitySubject != "alice" {
		t.Errorf("subject = %q, want alice", allow.IdentitySubject)
	}
	if got := allow.UpstreamHeaders["X-User"]; got != "alice" {
		t.Errorf("upstream X-User = %q, want alice", got)
	}

	deny, err := cli.Authorize(ctx, &lwauthclient.Request{
		Method:   "GET",
		Resource: "/things",
		Headers:  map[string]string{"x-api-key": "dev-viewer-key"},
	})
	if err != nil {
		t.Fatalf("Authorize (deny path): %v", err)
	}
	if deny.Allow {
		t.Fatalf("expected deny, got allow")
	}
	if deny.HTTPStatus != http.StatusForbidden {
		t.Errorf("http_status = %d, want 403", deny.HTTPStatus)
	}
}

// TestClient_HTTPMiddleware_Allow exercises the net/http middleware
// end-to-end: a real httptest server wrapped in the middleware,
// client → middleware → upstream, with header injection asserted.
func TestClient_HTTPMiddleware_Allow(t *testing.T) {
	t.Parallel()
	cli := dialSDK(t)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The middleware should have set X-User on the inbound request
		// before reaching us (UpstreamHeaders application).
		if got := r.Header.Get("X-User"); got != "alice" {
			t.Errorf("upstream saw X-User = %q, want alice", got)
		}
		_, _ = io.WriteString(w, "ok")
	})
	ts := httptest.NewServer(cli.HTTPMiddleware(upstream))
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/things", nil)
	req.Header.Set("X-Api-Key", "dev-admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestClient_HTTPMiddleware_Deny(t *testing.T) {
	t.Parallel()
	cli := dialSDK(t)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream must NOT be called on deny")
	})
	ts := httptest.NewServer(cli.HTTPMiddleware(upstream))
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/things", nil)
	req.Header.Set("X-Api-Key", "dev-viewer-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	// The SDK middleware proxies the native gRPC DenyReason to the
	// HTTP body. That reason is now redacted to a stable public
	// string ("forbidden" / "request denied" / ...) — the verbose
	// engine reason ("rbac: ...") must NOT cross the network.
	if bodyStr == "" {
		t.Errorf("body should surface a public deny reason; got empty")
	}
	for _, leak := range []string{"rbac", "subject", "allow-list", "lwauth:"} {
		if strings.Contains(bodyStr, leak) {
			t.Errorf("body leaks internal token %q: %q", leak, bodyStr)
		}
	}
}

// TestClient_UnaryInterceptor exercises the gRPC interceptor by
// running an in-memory dummy gRPC service ("ping") behind the
// interceptor and verifying that requests with valid keys reach the
// handler while invalid ones are rejected with PermissionDenied.
func TestClient_UnaryInterceptor(t *testing.T) {
	t.Parallel()
	cli := dialSDK(t)

	// The interceptor reads incoming metadata to forward as headers,
	// so we don't need a real proto; we use the grpc.Health service
	// as a no-op handler we can call from the test.
	calls := 0
	handler := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		calls++
		return "ok", nil
	}

	// Wire interceptor → handler manually. We don't need a real
	// listener — we drive the interceptor with synthesized contexts.
	intercept := cli.UnaryServerInterceptor()

	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("x-api-key", "dev-admin-key"))
	out, err := intercept(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc.Ping/Ping"},
		func(ctx context.Context, req any) (any, error) { return handler(ctx, req, nil, nil) })
	if err != nil {
		t.Fatalf("admin call: %v", err)
	}
	if out != "ok" || calls != 1 {
		t.Fatalf("handler not called for admin (out=%v calls=%d)", out, calls)
	}

	denyCtx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("x-api-key", "dev-viewer-key"))
	_, err = intercept(denyCtx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc.Ping/Ping"},
		func(ctx context.Context, req any) (any, error) {
			t.Fatalf("handler must NOT be invoked on deny")
			return nil, nil
		})
	if err == nil {
		t.Fatalf("expected PermissionDenied for viewer")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", status.Code(err))
	}
}
