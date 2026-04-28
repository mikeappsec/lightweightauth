package grpc

import (
	"context"

	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// remoteAuthorizer satisfies module.Authorizer by calling
// AuthorizerPlugin.Authorize over gRPC.
//
// On RPC failure or transport-level error string we fail closed —
// returning a *module.Decision with Allow=false and ErrUpstream so the
// pipeline emits a 503 (per pkg/module/errors.go semantics) rather than
// silently allowing the call.
type remoteAuthorizer struct {
	name   string
	cfg    commonConfig
	client pluginv1.AuthorizerPluginClient
}

func (a *remoteAuthorizer) Name() string { return a.name }

func (a *remoteAuthorizer) Authorize(ctx context.Context, r *module.Request, id *module.Identity) (*module.Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()

	resp, err := a.client.Authorize(ctx, &pluginv1.AuthorizePluginRequest{
		Request:  reqToProto(r),
		Identity: idToProto(id),
	})
	if err != nil {
		return nil, errPluginRPC(a.name, err)
	}
	if msg := resp.GetError(); msg != "" {
		return nil, errPluginTransport(a.name, msg)
	}
	return decisionFromProto(
		resp.GetAllow(),
		resp.GetHttpStatus(),
		resp.GetUpstreamHeaders(),
		resp.GetResponseHeaders(),
		resp.GetDenyReason(),
	), nil
}

func authorizerFactory(name string, raw map[string]any) (module.Authorizer, error) {
	cfg, err := parseCommon(name, raw)
	if err != nil {
		return nil, err
	}
	cc, err := dial(cfg.Address)
	if err != nil {
		return nil, err
	}
	return &remoteAuthorizer{
		name:   name,
		cfg:    cfg,
		client: pluginv1.NewAuthorizerPluginClient(cc),
	}, nil
}
