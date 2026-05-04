// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package server's gRPC adapter implements the Envoy External
// Authorization API (envoy.service.auth.v3) so Envoy / Istio / Gloo /
// AWS App Mesh can call lwauth as their `ext_authz` provider.
//
// The transport surface is intentionally narrow: this file translates
// CheckRequest -> *module.Request, calls pipeline.Engine.Evaluate, then
// translates *module.Decision -> CheckResponse. All policy logic lives
// in the Engine.
//
// See docs/DESIGN.md §1 ("Door A").
package server

import (
	"context"
	"net/http"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	codes "google.golang.org/grpc/codes"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// ExtAuthzServer implements envoy.service.auth.v3.AuthorizationServer.
//
// Decisions are produced by the Engine in the supplied EngineHolder; the
// holder pointer is swapped atomically on hot-reload so live RPCs always
// see a consistent pipeline.
type ExtAuthzServer struct {
	authv3.UnimplementedAuthorizationServer
	Engines *EngineHolder
	// MaxRequestBytes caps the request body lwauth ingests from
	// Envoy's HttpRequest.Body. 0 -> defaultMaxRequestBytes (1 MiB);
	// <0 -> unlimited (test-only). Pairs with the HTTP cap (F11) so
	// HMAC / body-claim / OPA-on-body modules behave identically
	// across doors.
	MaxRequestBytes int64
}

// NewExtAuthzServer constructs an ExtAuthzServer. The returned value is
// safe for registration with grpc.Server.
func NewExtAuthzServer(h *EngineHolder) *ExtAuthzServer {
	return &ExtAuthzServer{Engines: h}
}

// Check is the single RPC of envoy.service.auth.v3.Authorization.
//
// Envoy will:
//   - on OK   (code = OK) forward the request upstream, optionally with
//     headers we asked it to inject;
//   - on Deny (code != OK) return our DeniedHttpResponse to the client.
//
// `failure_mode_allow` on the Envoy side decides what to do if Check
// returns a transport error.
func (s *ExtAuthzServer) Check(ctx context.Context, in *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	eng := s.Engines.Load()
	if eng == nil {
		return denied(http.StatusServiceUnavailable, codes.Unavailable, "lwauth: no engine loaded"), nil
	}

	// F11: bound the body Envoy forwarded with `with_request_body`.
	// Without this, an operator who configured `max_request_bytes:
	// 4194304` on the Envoy filter pays 4 MiB allocations per
	// concurrent Check; the gRPC transport default (also 4 MiB) is
	// the only ceiling, and the HTTP 1 MiB cap is undermined.
	if limit := bodyLimit(s.MaxRequestBytes); limit > 0 {
		if r := in.GetAttributes().GetRequest(); r != nil && r.Http != nil {
			if int64(len(r.Http.Body)) > limit {
				return denied(http.StatusRequestEntityTooLarge, codes.ResourceExhausted, "lwauth: request body too large"), nil
			}
		}
	}

	req := requestFromCheck(in)
	dec, _, _ := eng.Evaluate(ctx, req)

	if dec.Allow {
		return ok(dec), nil
	}
	status := dec.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	// Verbose internal reason stays on the audit record; the network
	// reply gets a generic status-aligned string so module and policy
	// internals don't leak to downstream callers.
	return denied(status, statusToGRPC(status), publicReason(status, dec.Reason)), nil
}

// requestFromCheck folds Envoy's nested AttributeContext into the flat
// transport-agnostic *module.Request the pipeline understands.
//
// Normalization: header keys are lowercased so module code can rely on
// the [module.Request.Headers] invariant regardless of which door
// delivered the request. (HTTP/2 already mandates lowercase on the
// wire, so for Door A this is usually a no-op — we apply it
// defensively in case a future Envoy version forwards mixed-case keys
// from an HTTP/1.1 hop.)
func requestFromCheck(in *authv3.CheckRequest) *module.Request {
	out := &module.Request{Headers: map[string][]string{}}
	if in == nil || in.Attributes == nil {
		return out
	}
	attrs := in.Attributes

	// HTTP attributes (method/path/host/headers/body).
	if r := attrs.Request; r != nil && r.Http != nil {
		out.Method = strings.ToUpper(r.Http.Method)
		out.Host = r.Http.Host
		out.Path = r.Http.Path
		out.Body = []byte(r.Http.Body)
		for k, v := range r.Http.Headers {
			out.Headers[strings.ToLower(k)] = []string{v}
		}
	}

	// Note on PeerCerts: we deliberately do NOT populate it from
	// attrs.Source.Certificate. That field carries Envoy's XFCC value
	// (a URL-encoded PEM string), not raw DER — stuffing it into
	// PeerCerts (which the mtls module parses with x509.ParseCertificate)
	// would yield ErrInvalidCredential on every request. The mtls
	// module reads XFCC from the configured header instead (default
	// "x-forwarded-client-cert"), gated by trustForwardedClientCert.
	// PeerCerts is reserved for the in-process TLS-termination path
	// where lwauth itself parsed the chain and has DER bytes.

	// Envoy passes the per-route filter metadata under a well-known key.
	// We expose anything in `lwauth.tenant` to the pipeline so policies
	// can be tenant-scoped without us hardcoding any one provider.
	if md := attrs.MetadataContext; md != nil {
		if v, ok := md.FilterMetadata["lwauth"]; ok && v != nil {
			if t, ok := v.Fields["tenant"]; ok {
				out.TenantID = t.GetStringValue()
			}
		}
	}

	return out
}

// ok builds a CheckResponse(OK) with any headers the mutators asked for.
func ok(d *module.Decision) *authv3.CheckResponse {
	resp := &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: toHeaderValueOptions(d.UpstreamHeaders),
				ResponseHeadersToAdd: toHeaderValueOptions(d.ResponseHeaders),
			},
		},
	}
	return resp
}

// denied builds a CheckResponse(Deny) with the given HTTP status, gRPC
// code, and human-readable reason. Envoy returns this verbatim to the
// downstream client.
func denied(httpStatus int, grpcCode codes.Code, reason string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(grpcCode), Message: reason},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode(httpStatus)},
				Body:   reason,
				Headers: []*corev3.HeaderValueOption{
					{Header: &corev3.HeaderValue{Key: "X-Lwauth-Reason", Value: reason}},
				},
			},
		},
	}
}

func toHeaderValueOptions(h map[string]string) []*corev3.HeaderValueOption {
	if len(h) == 0 {
		return nil
	}
	out := make([]*corev3.HeaderValueOption, 0, len(h))
	for k, v := range h {
		out = append(out, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: k, Value: sanitizeHeaderValue(v)},
		})
	}
	return out
}

// sanitizeHeaderValue strips CR, LF, and NUL to prevent HTTP header injection.
// Security hardening: defense-in-depth at the transport boundary.
func sanitizeHeaderValue(s string) string {
	if !strings.ContainsAny(s, "\r\n\x00") {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
}

// statusToGRPC maps the HTTP statuses the Engine emits back to gRPC codes
// so non-HTTP callers (native gRPC clients) get the right code too.
func statusToGRPC(http int) codes.Code {
	switch http {
	case 401:
		return codes.Unauthenticated
	case 403:
		return codes.PermissionDenied
	case 503:
		return codes.Unavailable
	case 500:
		return codes.Internal
	default:
		return codes.PermissionDenied
	}
}
