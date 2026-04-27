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

	req := requestFromCheck(in)
	dec, _, _ := eng.Evaluate(ctx, req)

	if dec.Allow {
		return ok(dec), nil
	}
	status := dec.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	return denied(status, statusToGRPC(status), dec.Reason), nil
}

// requestFromCheck folds Envoy's nested AttributeContext into the flat
// transport-agnostic *module.Request the pipeline understands.
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
			out.Headers[k] = []string{v}
		}
	}

	// mTLS peer certificate URI-SAN, base64-DER, etc., live under source.
	if src := attrs.Source; src != nil {
		if src.Certificate != "" {
			out.PeerCerts = []byte(src.Certificate)
		}
	}

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
			Header: &corev3.HeaderValue{Key: k, Value: v},
		})
	}
	return out
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
