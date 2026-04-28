package grpc

import (
	"context"
	"errors"
	"net"
	"testing"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// fakePlugin implements all three plugin services in-process so each
// test can pick which behaviour it wants per call. The host runtime
// doesn't care which ones a given remote actually serves — config
// dispatch is what binds an address to a service — but for these unit
// tests we register all three on the same bufconn server.
type fakePlugin struct {
	pluginv1.UnimplementedIdentifierPluginServer
	pluginv1.UnimplementedAuthorizerPluginServer
	pluginv1.UnimplementedMutatorPluginServer

	identify  func(*pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error)
	authorize func(*pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error)
	mutate    func(*pluginv1.MutateRequest) (*pluginv1.MutateResponse, error)
}

func (f *fakePlugin) Identify(_ context.Context, in *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
	return f.identify(in)
}
func (f *fakePlugin) Authorize(_ context.Context, in *pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error) {
	return f.authorize(in)
}
func (f *fakePlugin) Mutate(_ context.Context, in *pluginv1.MutateRequest) (*pluginv1.MutateResponse, error) {
	return f.mutate(in)
}

// bootFakePlugin starts an in-memory gRPC server and installs a dialer
// override that routes "test://<addr>" to its bufconn listener. The
// override is uninstalled by t.Cleanup so concurrent test files don't
// see each other's plugins.
func bootFakePlugin(t *testing.T, fp *fakePlugin) string {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	pluginv1.RegisterIdentifierPluginServer(gs, fp)
	pluginv1.RegisterAuthorizerPluginServer(gs, fp)
	pluginv1.RegisterMutatorPluginServer(gs, fp)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	addr := "test://fake-plugin-" + t.Name()
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

// --- Identifier ----------------------------------------------------------

func TestIdentifier_Identify_OK(t *testing.T) {
	addr := bootFakePlugin(t, &fakePlugin{
		identify: func(in *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			if in.GetRequest().GetMethod() != "GET" {
				t.Errorf("method not propagated: %q", in.GetRequest().GetMethod())
			}
			if in.GetRequest().GetResource() != "/things" {
				t.Errorf("path not propagated: %q", in.GetRequest().GetResource())
			}
			return &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{
					Subject: "alice",
					Source:  "remote-saml",
					Claims:  map[string]string{"email": "alice@example.com"},
				},
			}, nil
		},
	})

	id, err := module.BuildIdentifier("grpc-plugin", "remote-saml", map[string]any{
		"address": addr,
		"timeout": "200ms",
	})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	got, err := id.Identify(context.Background(), &module.Request{
		Method: "GET",
		Path:   "/things",
		Headers: map[string][]string{
			"Authorization": {"Bearer xyz"},
		},
	})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "alice" {
		t.Errorf("subject = %q, want alice", got.Subject)
	}
	if got.Claims["email"] != "alice@example.com" {
		t.Errorf("email claim missing: %v", got.Claims)
	}
	if got.Source != "remote-saml" {
		t.Errorf("source = %q, want remote-saml", got.Source)
	}
}

func TestIdentifier_NoMatch(t *testing.T) {
	addr := bootFakePlugin(t, &fakePlugin{
		identify: func(*pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			return &pluginv1.IdentifyResponse{NoMatch: true}, nil
		},
	})
	id, err := module.BuildIdentifier("grpc-plugin", "remote", map[string]any{"address": addr})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	if _, err := id.Identify(context.Background(), &module.Request{}); !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestIdentifier_PluginError(t *testing.T) {
	addr := bootFakePlugin(t, &fakePlugin{
		identify: func(*pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			return &pluginv1.IdentifyResponse{Error: "lookup failed"}, nil
		},
	})
	id, err := module.BuildIdentifier("grpc-plugin", "remote", map[string]any{"address": addr})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	_, err = id.Identify(context.Background(), &module.Request{})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream", err)
	}
}

// --- Authorizer ----------------------------------------------------------

func TestAuthorizer_AllowDeny(t *testing.T) {
	addr := bootFakePlugin(t, &fakePlugin{
		authorize: func(in *pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error) {
			if in.GetIdentity().GetSubject() == "alice" {
				return &pluginv1.AuthorizePluginResponse{
					Allow:           true,
					UpstreamHeaders: map[string]string{"X-User": "alice"},
				}, nil
			}
			return &pluginv1.AuthorizePluginResponse{
				Allow:      false,
				HttpStatus: 403,
				DenyReason: "not alice",
			}, nil
		},
	})
	az, err := module.BuildAuthorizer("grpc-plugin", "remote-az", map[string]any{"address": addr})
	if err != nil {
		t.Fatalf("BuildAuthorizer: %v", err)
	}
	allow, err := az.Authorize(context.Background(), &module.Request{}, &module.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("Authorize alice: %v", err)
	}
	if !allow.Allow || allow.UpstreamHeaders["X-User"] != "alice" {
		t.Errorf("alice decision = %+v", allow)
	}
	deny, err := az.Authorize(context.Background(), &module.Request{}, &module.Identity{Subject: "bob"})
	if err != nil {
		t.Fatalf("Authorize bob: %v", err)
	}
	if deny.Allow || deny.Status != 403 || deny.Reason != "not alice" {
		t.Errorf("bob decision = %+v", deny)
	}
}

// --- Mutator -------------------------------------------------------------

func TestMutator_MergesHeaders(t *testing.T) {
	addr := bootFakePlugin(t, &fakePlugin{
		mutate: func(in *pluginv1.MutateRequest) (*pluginv1.MutateResponse, error) {
			if !in.GetDecision().GetAllow() {
				t.Errorf("plugin should see Allow=true")
			}
			return &pluginv1.MutateResponse{
				UpstreamHeaders: map[string]string{"X-Internal-JWT": "abc"},
				ResponseHeaders: map[string]string{"X-Trace": "xyz"},
			}, nil
		},
	})
	mu, err := module.BuildMutator("grpc-plugin", "remote-mu", map[string]any{"address": addr})
	if err != nil {
		t.Fatalf("BuildMutator: %v", err)
	}
	dec := &module.Decision{
		Allow:           true,
		UpstreamHeaders: map[string]string{"X-Existing": "1"},
	}
	if err := mu.Mutate(context.Background(), &module.Request{}, &module.Identity{Subject: "alice"}, dec); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if dec.UpstreamHeaders["X-Internal-JWT"] != "abc" || dec.UpstreamHeaders["X-Existing"] != "1" {
		t.Errorf("upstream merged wrong: %v", dec.UpstreamHeaders)
	}
	if dec.ResponseHeaders["X-Trace"] != "xyz" {
		t.Errorf("response merged wrong: %v", dec.ResponseHeaders)
	}
}

// --- Config errors -------------------------------------------------------

func TestConfig_AddressRequired(t *testing.T) {
	if _, err := module.BuildIdentifier("grpc-plugin", "x", map[string]any{}); err == nil {
		t.Fatal("expected ErrConfig")
	} else if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestConfig_BadTimeout(t *testing.T) {
	_, err := module.BuildAuthorizer("grpc-plugin", "x", map[string]any{
		"address": "test://nope",
		"timeout": "garbage",
	})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}
