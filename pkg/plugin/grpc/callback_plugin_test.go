package grpc

import (
	"context"
	"errors"
	"net"
	"testing"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
)

// callbackPlugin is a sibling of fakePlugin whose handlers receive the
// gRPC context, so they can call grpc.SetTrailer to attach the
// F-PLUGIN-2 signature trailer. fakePlugin's handlers don't see ctx
// (they predate this slice), so we keep the two side-by-side rather
// than retrofit fakePlugin and risk churning every existing test.
type callbackPlugin struct {
	pluginv1.UnimplementedIdentifierPluginServer
	pluginv1.UnimplementedAuthorizerPluginServer
	pluginv1.UnimplementedMutatorPluginServer

	cb callbacks
}

type callbacks struct {
	identify  func(context.Context, *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error)
	authorize func(context.Context, *pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error)
	mutate    func(context.Context, *pluginv1.MutateRequest) (*pluginv1.MutateResponse, error)
}

func (p *callbackPlugin) Identify(ctx context.Context, in *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
	if p.cb.identify == nil {
		return nil, errors.New("callbackPlugin: no identify handler installed")
	}
	return p.cb.identify(ctx, in)
}
func (p *callbackPlugin) Authorize(ctx context.Context, in *pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error) {
	if p.cb.authorize == nil {
		return nil, errors.New("callbackPlugin: no authorize handler installed")
	}
	return p.cb.authorize(ctx, in)
}
func (p *callbackPlugin) Mutate(ctx context.Context, in *pluginv1.MutateRequest) (*pluginv1.MutateResponse, error) {
	if p.cb.mutate == nil {
		return nil, errors.New("callbackPlugin: no mutate handler installed")
	}
	return p.cb.mutate(ctx, in)
}

// bootCallbackPlugin is the ctx-aware variant of bootFakePlugin. Same
// dialer-override mechanism so tests can run in parallel without
// stepping on each other.
func bootCallbackPlugin(t *testing.T, cb callbacks) string {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	cp := &callbackPlugin{cb: cb}
	pluginv1.RegisterIdentifierPluginServer(gs, cp)
	pluginv1.RegisterAuthorizerPluginServer(gs, cp)
	pluginv1.RegisterMutatorPluginServer(gs, cp)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	addr := "test://callback-plugin-" + t.Name()
	restore := setDialerOverrideForTest(func(want string) (*grpc.ClientConn, error) {
		if want != addr {
			return nil, errors.New("unexpected address: " + want)
		}
		return grpc.NewClient(
			"passthrough:///bufnet",
			grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(context.Background())
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	})
	t.Cleanup(restore)
	return addr
}
