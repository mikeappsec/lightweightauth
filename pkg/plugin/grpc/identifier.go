package grpc

import (
	"context"
	"errors"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/plugin/sign"
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

	var trailer metadata.MD
	resp, err := i.client.Identify(ctx, &pluginv1.IdentifyRequest{
		Request: reqToProto(r),
	}, grpc.Trailer(&trailer))
	if err != nil {
		return nil, errPluginRPC(i.name, err)
	}
	// Verify the F-PLUGIN-2 signature BEFORE inspecting the response
	// fields — we don't want to act on, log, or even differentiate
	// between an attacker-controlled "no_match=true" and a real one.
	if err := i.cfg.Signing.verifyTrailer(
		i.name, trailer,
		sign.CanonicalIdentifyResponse(trailerAlg(trailer), trailerKeyID(trailer), resp),
	); err != nil {
		return nil, err
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
	if err := startSupervisorIfConfigured(name, cfg, cfg.Lifecycle); err != nil {
		return nil, err
	}
	return &remoteIdentifier{
		name:   name,
		cfg:    cfg,
		client: pluginv1.NewIdentifierPluginClient(cc),
	}, nil
}
