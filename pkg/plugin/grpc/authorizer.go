package grpc

import (
	"context"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/plugin/sign"
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

	var trailer metadata.MD
	resp, err := a.client.Authorize(ctx, &pluginv1.AuthorizePluginRequest{
		Request:  reqToProto(r),
		Identity: idToProto(id),
	}, grpc.Trailer(&trailer))
	if err != nil {
		return nil, errPluginRPC(a.name, err)
	}
	if err := a.cfg.Signing.verifyTrailer(
		a.name, trailer,
		sign.CanonicalAuthorizeResponse(trailerAlg(trailer), trailerKeyID(trailer), resp),
	); err != nil {
		return nil, err
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
	cc, err := dial(name, cfg)
	if err != nil {
		return nil, err
	}
	return &remoteAuthorizer{
		name:   name,
		cfg:    cfg,
		client: pluginv1.NewAuthorizerPluginClient(cc),
	}, nil
}
