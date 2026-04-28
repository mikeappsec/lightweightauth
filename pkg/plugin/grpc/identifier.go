package grpc

import (
	"context"
	"errors"

	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// remoteIdentifier satisfies module.Identifier by calling
// IdentifierPlugin.Identify over gRPC.
//
// Wire-level result handling, in priority order:
//
//  1. RPC-level error (timeout / Unavailable / etc.) → ErrUpstream.
//  2. response.error  (plugin reported its own failure) → ErrUpstream.
//  3. response.no_match=true (plugin says "not my credential") → ErrNoMatch.
//  4. response.identity present → return Identity.
//  5. anything else → ErrInvalidCredential (plugin replied OK but with
//     no usable identity, equivalent to a built-in returning a malformed
//     credential).
type remoteIdentifier struct {
	name    string
	cfg     commonConfig
	client  pluginv1.IdentifierPluginClient
}

func (i *remoteIdentifier) Name() string { return i.name }

func (i *remoteIdentifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, i.cfg.Timeout)
	defer cancel()

	resp, err := i.client.Identify(ctx, &pluginv1.IdentifyRequest{
		Request: reqToProto(r),
	})
	if err != nil {
		return nil, errPluginRPC(i.name, err)
	}
	if msg := resp.GetError(); msg != "" {
		return nil, errPluginTransport(i.name, msg)
	}
	if resp.GetNoMatch() {
		return nil, module.ErrNoMatch
	}
	id := idFromProto(resp.GetIdentity(), i.name)
	if id == nil || id.Subject == "" {
		return nil, errors.New("grpc-plugin: identifier returned empty identity")
	}
	return id, nil
}

func identifierFactory(name string, raw map[string]any) (module.Identifier, error) {
	cfg, err := parseCommon(name, raw)
	if err != nil {
		return nil, err
	}
	cc, err := dial(name, cfg)
	if err != nil {
		return nil, err
	}
	return &remoteIdentifier{
		name:   name,
		cfg:    cfg,
		client: pluginv1.NewIdentifierPluginClient(cc),
	}, nil
}
