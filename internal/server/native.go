// This file implements Door B (DESIGN.md §1, M8): the native
// `lightweightauth.v1.Auth` gRPC service. It mirrors the ext_authz
// adapter (grpc.go) but uses our own, smaller proto so non-Envoy
// callers don't have to pull in `envoyproxy/go-control-plane`.
//
// Both adapters share one pipeline.Engine via the EngineHolder, so a
// given module.Request produces an identical module.Decision through
// either door (verified by internal/server/conformance_test.go).

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// NativeAuthServer implements authv1.AuthServer.
//
// Like ExtAuthzServer, it holds an *EngineHolder so the active
// pipeline can be swapped atomically by the config layer without
// disrupting in-flight RPCs.
type NativeAuthServer struct {
	authv1.UnimplementedAuthServer
	Engines *EngineHolder
}

// NewNativeAuthServer returns a NativeAuthServer ready for
// `authv1.RegisterAuthServer(s, NewNativeAuthServer(holder))`.
func NewNativeAuthServer(h *EngineHolder) *NativeAuthServer {
	return &NativeAuthServer{Engines: h}
}

// Authorize is the unary one-shot decision RPC. Most callers use this.
func (s *NativeAuthServer) Authorize(ctx context.Context, req *authv1.AuthorizeRequest) (*authv1.AuthorizeResponse, error) {
	eng := s.Engines.Load()
	if eng == nil {
		return nil, status.Error(codes.Unavailable, "lwauth: no engine loaded")
	}
	mreq := requestFromAuthorize(req)
	dec, id, _ := eng.Evaluate(ctx, mreq)
	return responseFromDecision(dec, id), nil
}

// AuthorizeStream evaluates each inbound AuthorizeRequest and returns a
// matching AuthorizeResponse. It is a bidirectional stream so callers
// can keep a long-lived session (e.g. a WebSocket) and re-check
// authorization on every message without a per-call dial cost.
//
// The stream is independent: a deny on message N does NOT close the
// stream — the *caller* decides whether to disconnect. This lets a
// chat server, say, deliver a "you've been demoted" message and then
// close the socket on its own terms.
func (s *NativeAuthServer) AuthorizeStream(stream authv1.Auth_AuthorizeStreamServer) error {
	ctx := stream.Context()
	for {
		in, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		eng := s.Engines.Load()
		if eng == nil {
			return status.Error(codes.Unavailable, "lwauth: no engine loaded")
		}
		dec, id, _ := eng.Evaluate(ctx, requestFromAuthorize(in))
		if err := stream.Send(responseFromDecision(dec, id)); err != nil {
			return err
		}
	}
}

// requestFromAuthorize is the only place that knows about authv1's
// shape. It is the dual of [requestFromCheck] for Door A and produces
// the same module.Request given equivalent inputs (this is what makes
// the conformance tests possible).
func requestFromAuthorize(in *authv1.AuthorizeRequest) *module.Request {
	out := &module.Request{Headers: map[string][]string{}}
	if in == nil {
		return out
	}
	out.Method = strings.ToUpper(in.GetMethod())
	// Native callers send a free-form `resource` (URL path, gRPC FQN,
	// Kafka topic, ...). The pipeline's policies key off Path, so we
	// surface it there — that keeps RBAC/OPA/CEL configs identical
	// between Door A and Door B.
	out.Path = in.GetResource()
	out.Body = in.GetBody()
	out.TenantID = in.GetTenantId()
	for k, v := range in.GetHeaders() {
		out.Headers[k] = []string{v}
	}
	if peer := in.GetPeer(); peer != nil {
		out.Host = peer.GetRemoteAddr() // best-effort; Door A also leaves Host empty for non-HTTP
		if cert := peer.GetCertChain(); len(cert) > 0 {
			out.PeerCerts = cert
		}
	}
	if ctxMap := in.GetContext(); len(ctxMap) > 0 {
		out.Context = make(map[string]any, len(ctxMap))
		for k, v := range ctxMap {
			out.Context[k] = v
		}
	}
	return out
}

// responseFromDecision is the dual of [ok]/[denied] for Door B. It
// always returns a normal AuthorizeResponse (gRPC status OK); deny is
// signalled in the *body* via Allow=false rather than via the gRPC
// status code, because callers usually want both the deny reason and
// any response_headers (e.g. WWW-Authenticate) the mutators set.
func responseFromDecision(d *module.Decision, id *module.Identity) *authv1.AuthorizeResponse {
	if d == nil {
		return &authv1.AuthorizeResponse{
			Allow:      false,
			HttpStatus: http.StatusInternalServerError,
			DenyReason: "lwauth: nil decision",
		}
	}
	resp := &authv1.AuthorizeResponse{
		Allow:            d.Allow,
		HttpStatus:       int32(d.Status),
		UpstreamHeaders:  d.UpstreamHeaders,
		ResponseHeaders:  d.ResponseHeaders,
		DenyReason:       d.Reason,
	}
	if !d.Allow && resp.HttpStatus == 0 {
		resp.HttpStatus = http.StatusForbidden
	}
	if id != nil {
		resp.Identity = &authv1.Identity{
			Subject: id.Subject,
			Source:  id.Source,
			Claims:  flattenClaims(id.Claims),
		}
	}
	return resp
}

// flattenClaims projects an identity's claim map into the simpler
// map<string,string> on the wire. Numbers and booleans are stringified;
// nested objects/arrays go through fmt.Sprint("%v") so a logging caller
// still gets *something* useful (for full fidelity, callers should
// re-introspect their tokens — claims here are a courtesy field).
func flattenClaims(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case string:
			out[k] = t
		case nil:
			out[k] = ""
		default:
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}
