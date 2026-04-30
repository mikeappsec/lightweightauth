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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
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
	// MaxRequestBytes caps the AuthorizeRequest.body field. 0 ->
	// defaultMaxRequestBytes (1 MiB); <0 -> unlimited (test-only).
	// Pairs with the HTTP cap and the Door A cap (F11) so a caller
	// can't bypass the HTTP 1 MiB limit by speaking gRPC instead.
	MaxRequestBytes int64
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
	if limit := bodyLimit(s.MaxRequestBytes); limit > 0 && int64(len(req.GetBody())) > limit {
		return nil, status.Error(codes.ResourceExhausted, "lwauth: request body too large")
	}
	mreq := requestFromAuthorize(req)
	mreq.PeerCerts = verifiedPeerCertFromContext(ctx)
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
	// The verified TLS peer cert is a property of the gRPC
	// connection, not of any individual message, so we extract it
	// once and reuse it for every request on the stream.
	verifiedCert := verifiedPeerCertFromContext(ctx)
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
		if limit := bodyLimit(s.MaxRequestBytes); limit > 0 && int64(len(in.GetBody())) > limit {
			return status.Error(codes.ResourceExhausted, "lwauth: request body too large")
		}
		mreq := requestFromAuthorize(in)
		mreq.PeerCerts = verifiedCert
		dec, id, _ := eng.Evaluate(ctx, mreq)
		if err := stream.Send(responseFromDecision(dec, id)); err != nil {
			return err
		}
	}
}

// requestFromAuthorize is the only place that knows about authv1's
// shape. It is the dual of [requestFromCheck] for Door A and produces
// an identical module.Request given equivalent inputs (this is what
// makes Door A vs Door B parity hold for every shipped module).
//
// Normalization rules (see [module.Request.Headers] invariant):
//   - Header keys are lowercased. Native gRPC clients (Go SDK,
//     grpcurl, ...) typically send title-case keys; HTTP/2 mandates
//     lowercase on the wire on the Door A side. Lowercasing here
//     means modules can use direct map lookups identically across
//     both transports.
//   - Host is taken from the "host" header first (the HTTP authority
//     the client targeted) and falls back to the gRPC peer's remote
//     address only when no host header was sent. Door A populates
//     Host from envoy.AttributeContext_HttpRequest.Host (the HTTP
//     authority); using peer.RemoteAddr unconditionally on Door B
//     would break DPoP's htu binding and HMAC's canonical string.
//
// Trust note: PeerCerts is NEVER populated from the request body.
// Trusting application-level cert bytes would let any caller forge a
// certificate with a chosen subject and have the mtls identifier
// treat it as verified, bypassing every authentication anchor. The
// proto reserves field number 3 in PeerInfo so no future field
// silently reuses the slot. PeerCerts is populated by the caller of
// requestFromAuthorize from the gRPC connection's verified TLS
// chain only — see [verifiedPeerCertFromContext].
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
		out.Headers[strings.ToLower(k)] = []string{v}
	}
	// Prefer the HTTP authority from the "host" header (matches Door
	// A's Http.Host semantics). Only fall back to the gRPC peer's
	// remote address — which is a transport-level IP, not an HTTP
	// authority — when the caller did not set the header.
	if hosts, ok := out.Headers["host"]; ok && len(hosts) > 0 && hosts[0] != "" {
		out.Host = hosts[0]
	}
	if p := in.GetPeer(); p != nil && out.Host == "" {
		out.Host = p.GetRemoteAddr()
	}
	if ctxMap := in.GetContext(); len(ctxMap) > 0 {
		out.Context = make(map[string]any, len(ctxMap))
		for k, v := range ctxMap {
			out.Context[k] = v
		}
	}
	return out
}

// verifiedPeerCertFromContext returns the DER-encoded leaf certificate
// of the gRPC client that opened the current connection, when (and
// only when) the connection used TLS and the server-side handshake
// produced verified peer certificates.
//
// This is the trusted source of Request.PeerCerts. The mtls
// identifier treats PeerCerts as already-verified DER bytes (no
// chain check), so the bytes MUST come from a TLS stack that did the
// chain verification — not from anything the client put on the wire
// after the handshake.
//
// Returns nil when:
//   - the connection is plaintext (no TLS),
//   - the client did not present a cert (server is not configured
//     for mTLS), or
//   - the auth info is some non-TLS credential type.
func verifiedPeerCertFromContext(ctx context.Context) []byte {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.AuthInfo == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	// VerifiedChains is populated by the TLS stack only after
	// successful chain validation against the server's configured
	// client CA pool. PeerCertificates without VerifiedChains means
	// the server is not requiring/verifying client certs; in that
	// mode we have no trusted DER to publish to the engine.
	cs := tlsInfo.State
	if !isTLSConnVerified(&cs) {
		return nil
	}
	return cs.VerifiedChains[0][0].Raw
}

func isTLSConnVerified(cs *tls.ConnectionState) bool {
	if cs == nil {
		return false
	}
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return false
	}
	return cs.VerifiedChains[0][0] != nil
}

// responseFromDecision is the dual of [ok]/[denied] for Door B. It
// always returns a normal AuthorizeResponse (gRPC status OK); deny is
// signalled in the *body* via Allow=false rather than via the gRPC
// status code, because callers usually want both the deny reason and
// any response_headers (e.g. WWW-Authenticate) the mutators set.
//
// DenyReason is redacted to a stable, status-aligned public string
// via publicReason — the verbose decision reason still flows through
// the engine's audit/log path for operators. Door A (HTTP) and the
// Envoy ext_authz adapter already do this; Door B was previously
// leaking d.Reason raw to native gRPC clients.
func responseFromDecision(d *module.Decision, id *module.Identity) *authv1.AuthorizeResponse {
	if d == nil {
		return &authv1.AuthorizeResponse{
			Allow:      false,
			HttpStatus: http.StatusInternalServerError,
			DenyReason: publicReason(http.StatusInternalServerError, ""),
		}
	}
	httpStatus := int(d.Status)
	if !d.Allow && httpStatus == 0 {
		httpStatus = http.StatusForbidden
	}
	resp := &authv1.AuthorizeResponse{
		Allow:           d.Allow,
		HttpStatus:      int32(httpStatus),
		UpstreamHeaders: d.UpstreamHeaders,
		ResponseHeaders: d.ResponseHeaders,
	}
	if !d.Allow {
		resp.DenyReason = publicReason(httpStatus, d.Reason)
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
