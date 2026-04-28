package grpc

import (
	"context"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// remoteMutator satisfies module.ResponseMutator by calling
// MutatorPlugin.Mutate over gRPC and merging any returned headers back
// onto the in-process Decision.
//
// The plugin sees the *same* AuthorizeResponse a Door B caller would
// receive at this point in the pipeline (post-Authorize, pre-Mutate);
// the mutator is free to add or rewrite headers but cannot flip allow.
// To deny based on response shape, run another authorizer in a
// composite chain — that's what the design doc recommends.
type remoteMutator struct {
	name   string
	cfg    commonConfig
	client pluginv1.MutatorPluginClient
}

func (m *remoteMutator) Name() string { return m.name }

func (m *remoteMutator) Mutate(ctx context.Context, r *module.Request, id *module.Identity, d *module.Decision) error {
	if d == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()

	resp, err := m.client.Mutate(ctx, &pluginv1.MutateRequest{
		Request:  reqToProto(r),
		Identity: idToProto(id),
		Decision: &authv1.AuthorizeResponse{
			Allow:           d.Allow,
			HttpStatus:      int32(d.Status),
			UpstreamHeaders: d.UpstreamHeaders,
			ResponseHeaders: d.ResponseHeaders,
			DenyReason:      d.Reason,
			Identity:        idToProto(id),
		},
	})
	if err != nil {
		return errPluginRPC(m.name, err)
	}
	if msg := resp.GetError(); msg != "" {
		return errPluginTransport(m.name, msg)
	}
	d.UpstreamHeaders = mergeHeaders(d.UpstreamHeaders, resp.GetUpstreamHeaders())
	d.ResponseHeaders = mergeHeaders(d.ResponseHeaders, resp.GetResponseHeaders())
	return nil
}

func mutatorFactory(name string, raw map[string]any) (module.ResponseMutator, error) {
	cfg, err := parseCommon(name, raw)
	if err != nil {
		return nil, err
	}
	cc, err := dial(cfg.Address)
	if err != nil {
		return nil, err
	}
	return &remoteMutator{
		name:   name,
		cfg:    cfg,
		client: pluginv1.NewMutatorPluginClient(cc),
	}, nil
}

// init registers the same type name "grpc-plugin" under all three
// kinds. They live in independent maps inside pkg/module/registry.go,
// so a config entry under `identifiers:` resolves to identifierFactory
// while one under `authorizers:` resolves to authorizerFactory — the
// caller never has to disambiguate.
func init() {
	module.RegisterIdentifier("grpc-plugin", identifierFactory)
	module.RegisterAuthorizer("grpc-plugin", authorizerFactory)
	module.RegisterMutator("grpc-plugin", mutatorFactory)
}
