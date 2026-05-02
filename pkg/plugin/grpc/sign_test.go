// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	grpcsrv "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	pluginv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/plugin/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
	"github.com/mikeappsec/lightweightauth/pkg/plugin/sign"
)

// signSecret is the 32-byte HMAC key used end-to-end in this file.
// Hex form so test config can drop it in directly.
const signSecretHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func signSecret(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(signSecretHex)
	if err != nil {
		t.Fatalf("decode test secret: %v", err)
	}
	return b
}

// signedPlugin returns a callbackPlugin whose handlers populate the
// gRPC response trailer with a freshly-computed HMAC over the
// canonical bytes of whatever response they're about to return.
// This is what a well-behaved F-PLUGIN-2 plugin SDK would do in
// production.
func signedPlugin(t *testing.T, kid string,
	identify func(*pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error),
	authorize func(*pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error),
	mutate func(*pluginv1.MutateRequest) (*pluginv1.MutateResponse, error),
) callbacks {
	t.Helper()
	secret := signSecret(t)
	cb := callbacks{}
	if identify != nil {
		cb.identify = func(ctx context.Context, in *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			resp, err := identify(in)
			if err != nil || resp == nil {
				return resp, err
			}
			payload := sign.CanonicalIdentifyResponse(sign.AlgHMACSHA256, kid, resp)
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, kid,
				sign.TrailerSig, sign.Sign(secret, payload),
			))
			return resp, nil
		}
	}
	if authorize != nil {
		cb.authorize = func(ctx context.Context, in *pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error) {
			resp, err := authorize(in)
			if err != nil || resp == nil {
				return resp, err
			}
			payload := sign.CanonicalAuthorizeResponse(sign.AlgHMACSHA256, kid, resp)
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, kid,
				sign.TrailerSig, sign.Sign(secret, payload),
			))
			return resp, nil
		}
	}
	if mutate != nil {
		cb.mutate = func(ctx context.Context, in *pluginv1.MutateRequest) (*pluginv1.MutateResponse, error) {
			resp, err := mutate(in)
			if err != nil || resp == nil {
				return resp, err
			}
			payload := sign.CanonicalMutateResponse(sign.AlgHMACSHA256, kid, resp)
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, kid,
				sign.TrailerSig, sign.Sign(secret, payload),
			))
			return resp, nil
		}
	}
	return cb
}

// signingConfig returns the YAML-shaped raw map for a `signing` block
// with one HMAC key and the requested mode.
func signingCfg(mode, kid, hexSecret string) map[string]any {
	return map[string]any{
		"mode": mode,
		"keys": []any{map[string]any{"id": kid, "hmacSecret": hexSecret}},
	}
}

// --- Identifier signing tests ------------------------------------

func TestSign_Identifier_RequireMode_AcceptsValidSig(t *testing.T) {
	const kid = "ops-2026-04"
	cb := signedPlugin(t, kid,
		func(*pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			return &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{Subject: "alice", Source: "remote-saml"},
			}, nil
		}, nil, nil)
	addr := bootCallbackPlugin(t, cb)

	id, err := module.BuildIdentifier("grpc-plugin", "remote-saml", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		"signing":  signingCfg("require", kid, signSecretHex),
	})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	got, err := id.Identify(context.Background(), &module.Request{Method: "GET", Path: "/"})
	if err != nil || got == nil || got.Subject != "alice" {
		t.Fatalf("Identify: (%+v, %v); want subject=alice", got, err)
	}
}

func TestSign_Identifier_RequireMode_RejectsUnsignedPlugin(t *testing.T) {
	// A *legacy* plugin that doesn't sign at all.
	addr := bootCallbackPlugin(t, callbacks{
		identify: func(_ context.Context, _ *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			return &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{Subject: "alice", Source: "remote-saml"},
			}, nil
		},
	})

	id, err := module.BuildIdentifier("grpc-plugin", "remote-saml", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		"signing":  signingCfg("require", "ops-2026-04", signSecretHex),
	})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	_, err = id.Identify(context.Background(), &module.Request{Method: "GET", Path: "/"})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream wrapping 'no sig trailer'", err)
	}
	if !strings.Contains(err.Error(), "no "+sign.TrailerSig+" trailer") {
		t.Errorf("err message %q should mention missing trailer", err.Error())
	}
}

func TestSign_Identifier_RequireMode_RejectsTamperedResponse(t *testing.T) {
	// Plugin signs Identity{Subject:"alice"}, returns Identity{Subject:"MALLORY"}.
	// The host re-canonicalizes from the wire and the signature won't match.
	const kid = "ops-2026-04"
	addr := bootCallbackPlugin(t, callbacks{
		identify: func(ctx context.Context, _ *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			actuallyReturned := &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{Subject: "MALLORY", Source: "remote-saml"},
			}
			signedOver := &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{Subject: "alice", Source: "remote-saml"},
			}
			payload := sign.CanonicalIdentifyResponse(sign.AlgHMACSHA256, kid, signedOver)
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, kid,
				sign.TrailerSig, sign.Sign(signSecret(t), payload),
			))
			return actuallyReturned, nil
		},
	})

	id, err := module.BuildIdentifier("grpc-plugin", "remote-saml", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		"signing":  signingCfg("require", kid, signSecretHex),
	})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	_, err = id.Identify(context.Background(), &module.Request{Method: "GET", Path: "/"})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream from signature mismatch", err)
	}
	if !strings.Contains(err.Error(), "signature mismatch") {
		t.Errorf("err = %q, want it to mention signature mismatch", err.Error())
	}
}

func TestSign_Identifier_RequireMode_RejectsUnknownKid(t *testing.T) {
	const wireKid = "leaked-test-key"
	addr := bootCallbackPlugin(t, callbacks{
		identify: func(ctx context.Context, _ *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			resp := &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{Subject: "alice", Source: "remote-saml"},
			}
			payload := sign.CanonicalIdentifyResponse(sign.AlgHMACSHA256, wireKid, resp)
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, wireKid,
				sign.TrailerSig, sign.Sign(signSecret(t), payload),
			))
			return resp, nil
		},
	})

	id, err := module.BuildIdentifier("grpc-plugin", "remote-saml", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		// Configured key id is a DIFFERENT one — the host sees a kid
		// it doesn't know about and refuses, regardless of the fact
		// that the secret happens to match.
		"signing": signingCfg("require", "ops-2026-04", signSecretHex),
	})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	_, err = id.Identify(context.Background(), &module.Request{})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("err = %v, want ErrUpstream from unknown kid", err)
	}
	if !strings.Contains(err.Error(), "key id") {
		t.Errorf("err = %q, want mention of unknown key id", err.Error())
	}
}

func TestSign_Identifier_VerifyMode_AllowsUnsignedLegacyPlugin(t *testing.T) {
	// In verify mode, an unsigned plugin (no trailer at all) is
	// accepted — this is the rolling-deployment escape valve.
	addr := bootFakePlugin(t, &fakePlugin{
		identify: func(*pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			return &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{Subject: "alice", Source: "remote-saml"},
			}, nil
		},
	})

	id, err := module.BuildIdentifier("grpc-plugin", "remote-saml", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		"signing":  signingCfg("verify", "ops-2026-04", signSecretHex),
	})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	got, err := id.Identify(context.Background(), &module.Request{})
	if err != nil || got.Subject != "alice" {
		t.Fatalf("verify-mode legacy plugin: (%+v, %v); want subject=alice", got, err)
	}
}

func TestSign_Identifier_VerifyMode_RejectsBadSignature(t *testing.T) {
	// Crucially: even in verify mode, a PRESENT-BUT-INVALID
	// signature MUST fail. Letting it slide would make verify mode
	// strictly worse than disabled.
	const kid = "ops-2026-04"
	addr := bootCallbackPlugin(t, callbacks{
		identify: func(ctx context.Context, _ *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			resp := &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{Subject: "alice", Source: "remote-saml"},
			}
			// Send a deliberately broken signature.
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, kid,
				sign.TrailerSig, "00"+strings.Repeat("11", 31),
			))
			return resp, nil
		},
	})

	id, err := module.BuildIdentifier("grpc-plugin", "remote-saml", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		"signing":  signingCfg("verify", kid, signSecretHex),
	})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	_, err = id.Identify(context.Background(), &module.Request{})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("verify-mode + bad sig: err=%v, want ErrUpstream", err)
	}
}

func TestSign_Identifier_DisabledMode_IgnoresTrailers(t *testing.T) {
	// Disabled is the v1.0 default. The plugin can send anything
	// in trailers and the host shouldn't care. This protects
	// existing operators from being surprised by a v1.1 upgrade.
	addr := bootCallbackPlugin(t, callbacks{
		identify: func(ctx context.Context, _ *pluginv1.IdentifyRequest) (*pluginv1.IdentifyResponse, error) {
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, "anything",
				sign.TrailerSig, "00",
			))
			return &pluginv1.IdentifyResponse{
				Identity: &authv1.Identity{Subject: "alice", Source: "remote-saml"},
			}, nil
		},
	})

	id, err := module.BuildIdentifier("grpc-plugin", "remote-saml", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		// No signing block at all → mode defaults to disabled.
	})
	if err != nil {
		t.Fatalf("BuildIdentifier: %v", err)
	}
	if _, err := id.Identify(context.Background(), &module.Request{}); err != nil {
		t.Fatalf("disabled-mode call failed: %v", err)
	}
}

// --- Authorizer signing tests ------------------------------------

func TestSign_Authorizer_RequireMode_AcceptsValidSig(t *testing.T) {
	const kid = "auth-kid"
	addr := bootCallbackPlugin(t, callbacks{
		authorize: func(ctx context.Context, _ *pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error) {
			resp := &pluginv1.AuthorizePluginResponse{
				Allow: true, HttpStatus: 200,
				UpstreamHeaders: map[string]string{"X-User": "alice"},
			}
			payload := sign.CanonicalAuthorizeResponse(sign.AlgHMACSHA256, kid, resp)
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, kid,
				sign.TrailerSig, sign.Sign(signSecret(t), payload),
			))
			return resp, nil
		},
	})

	az, err := module.BuildAuthorizer("grpc-plugin", "remote-rbac", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		"signing":  signingCfg("require", kid, signSecretHex),
	})
	if err != nil {
		t.Fatalf("BuildAuthorizer: %v", err)
	}
	d, err := az.Authorize(context.Background(),
		&module.Request{Method: "GET", Path: "/"},
		&module.Identity{Subject: "alice", Source: "saml"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allow || d.UpstreamHeaders["X-User"] != "alice" {
		t.Errorf("decision = %+v, want allow=true & X-User=alice", d)
	}
}

func TestSign_Authorizer_RequireMode_RejectsTamperedAllow(t *testing.T) {
	// Plugin signs a deny, returns an allow. This is the worst-case
	// substitution attack the F-PLUGIN-2 scheme is meant to catch.
	const kid = "auth-kid"
	addr := bootCallbackPlugin(t, callbacks{
		authorize: func(ctx context.Context, _ *pluginv1.AuthorizePluginRequest) (*pluginv1.AuthorizePluginResponse, error) {
			signedOver := &pluginv1.AuthorizePluginResponse{Allow: false, HttpStatus: 403, DenyReason: "no"}
			actuallyReturned := &pluginv1.AuthorizePluginResponse{Allow: true, HttpStatus: 200}
			payload := sign.CanonicalAuthorizeResponse(sign.AlgHMACSHA256, kid, signedOver)
			_ = grpcsrv.SetTrailer(ctx, metadata.Pairs(
				sign.TrailerAlg, sign.AlgHMACSHA256,
				sign.TrailerKeyID, kid,
				sign.TrailerSig, sign.Sign(signSecret(t), payload),
			))
			return actuallyReturned, nil
		},
	})

	az, err := module.BuildAuthorizer("grpc-plugin", "remote-rbac", map[string]any{
		"address":  addr,
		"timeout":  "200ms",
		"insecure": true,
		"signing":  signingCfg("require", kid, signSecretHex),
	})
	if err != nil {
		t.Fatalf("BuildAuthorizer: %v", err)
	}
	_, err = az.Authorize(context.Background(),
		&module.Request{}, &module.Identity{Subject: "alice", Source: "saml"})
	if !errors.Is(err, module.ErrUpstream) {
		t.Fatalf("tampered-allow err = %v, want ErrUpstream", err)
	}
}

// --- Config parser tests -----------------------------------------

func TestSigning_Config_ParseHappyPath(t *testing.T) {
	cfg, err := parseSigning("p", map[string]any{
		"signing": map[string]any{
			"mode": "require",
			"keys": []any{
				map[string]any{"id": "k1", "hmacSecret": signSecretHex},
				map[string]any{"id": "k2", "hmacSecret": strings.Repeat("ab", 16)},
			},
		},
	})
	if err != nil {
		t.Fatalf("parseSigning: %v", err)
	}
	if cfg.mode != signingRequire {
		t.Errorf("mode = %v, want require", cfg.mode)
	}
	if len(cfg.keys) != 2 {
		t.Errorf("keys = %d, want 2", len(cfg.keys))
	}
}

func TestSigning_Config_RejectsRequireWithoutKeys(t *testing.T) {
	_, err := parseSigning("p", map[string]any{
		"signing": map[string]any{"mode": "require"},
	})
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("err = %v, want ErrConfig", err)
	}
}

func TestSigning_Config_RejectsShortSecret(t *testing.T) {
	_, err := parseSigning("p", map[string]any{
		"signing": map[string]any{
			"mode": "require",
			"keys": []any{map[string]any{"id": "k1", "hmacSecret": "abcd"}}, // 2 bytes
		},
	})
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("err = %v, want ErrConfig", err)
	}
}

func TestSigning_Config_RejectsDuplicateKid(t *testing.T) {
	_, err := parseSigning("p", map[string]any{
		"signing": map[string]any{
			"mode": "require",
			"keys": []any{
				map[string]any{"id": "k1", "hmacSecret": signSecretHex},
				map[string]any{"id": "k1", "hmacSecret": signSecretHex},
			},
		},
	})
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("err = %v, want ErrConfig (duplicate kid)", err)
	}
}

func TestSigning_Config_AbsentBlockMeansDisabled(t *testing.T) {
	cfg, err := parseSigning("p", map[string]any{})
	if err != nil {
		t.Fatalf("parseSigning(empty): %v", err)
	}
	if cfg.mode != signingDisabled {
		t.Errorf("default mode = %v, want disabled", cfg.mode)
	}
}
