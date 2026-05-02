// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package lwauthclient is the lightweight Go SDK for callers of the
// native Door B service (`lightweightauth.v1.Auth`). It is published
// from the core repo because it is small and shares the wire format —
// language SDKs in lightweightauth-plugins (Python, Rust, ...) follow
// this same surface.
//
// Why a tiny SDK at all (vs. having callers do `authv1.NewAuthClient`
// directly)?
//
//   1. We hide the generated proto types behind a small Request /
//      Response struct, so callers don't import `api/proto/...`.
//   2. We ship gRPC/HTTP-server interceptors with a sane default
//      authorize call, so the most common integration is one line.
//   3. We can evolve the wire schema in M9+ (e.g. adding fields)
//      without breaking caller code that uses the SDK shape.
//
// Usage — gRPC server interceptor:
//
//	cli, _ := lwauthclient.Dial("lwauth:9001")
//	defer cli.Close()
//
//	grpc.NewServer(grpc.UnaryInterceptor(cli.UnaryServerInterceptor()))
//
// Usage — HTTP middleware:
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/", cli.HTTPMiddleware(myAPIHandler))
package lwauthclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
)

// Request is the SDK's narrowed view of authv1.AuthorizeRequest. It
// exists so callers don't have to import the generated proto package.
type Request struct {
	Method   string
	Resource string
	Headers  map[string]string
	Body     []byte
	TenantID string
	Context  map[string]string
	Peer     *Peer
}

// Peer mirrors authv1.PeerInfo without the proto types. Note: peer
// certificates are NOT carried in the request body — lwauth derives
// the verified peer cert from its own gRPC TLS stack (mTLS
// handshake, server-side client-CA pool). To use mTLS-based
// authorization, dial lwauth with a client TLS config; do not try to
// forward certs as application data.
type Peer struct {
	RemoteAddr string
	SpiffeID   string
}

// Response mirrors authv1.AuthorizeResponse with a flat shape callers
// can return directly.
type Response struct {
	Allow            bool
	HTTPStatus       int
	UpstreamHeaders  map[string]string
	ResponseHeaders  map[string]string
	DenyReason       string
	IdentitySubject  string
	IdentitySource   string
	IdentityClaims   map[string]string
}

// Client is a thin wrapper around authv1.AuthClient.
type Client struct {
	conn *grpc.ClientConn
	auth authv1.AuthClient

	// HTTPStatusOnError is what HTTPMiddleware returns when the
	// gRPC call to lwauth itself fails (network error, lwauth down,
	// etc.). Defaults to 503 (Service Unavailable). Set to 200 to
	// "fail open" — strongly discouraged outside of dev.
	HTTPStatusOnError int
}

// Dial connects to a running lwauth Door B server. Pass
// `grpc.WithTransportCredentials(...)` etc. via opts.
//
// In production, prefer mTLS:
//
//	creds := credentials.NewTLS(&tls.Config{ /* ... */ })
//	cli, _ := lwauthclient.Dial("lwauth.svc:9001",
//	    grpc.WithTransportCredentials(creds))
func Dial(target string, opts ...grpc.DialOption) (*Client, error) {
	if len(opts) == 0 {
		opts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("lwauthclient: dial %s: %w", target, err)
	}
	return &Client{
		conn:              conn,
		auth:              authv1.NewAuthClient(conn),
		HTTPStatusOnError: http.StatusServiceUnavailable,
	}, nil
}

// NewWithConn is for tests / advanced callers that already have a
// *grpc.ClientConn (e.g. one shared with another service).
func NewWithConn(cc *grpc.ClientConn) *Client {
	return &Client{
		auth:              authv1.NewAuthClient(cc),
		HTTPStatusOnError: http.StatusServiceUnavailable,
	}
}

// Close closes the underlying gRPC connection (if owned by Dial).
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Authorize runs a single authorize call.
func (c *Client) Authorize(ctx context.Context, req *Request) (*Response, error) {
	resp, err := c.auth.Authorize(ctx, requestToProto(req))
	if err != nil {
		return nil, err
	}
	return responseFromProto(resp), nil
}

func requestToProto(req *Request) *authv1.AuthorizeRequest {
	if req == nil {
		return &authv1.AuthorizeRequest{}
	}
	out := &authv1.AuthorizeRequest{
		Method:   req.Method,
		Resource: req.Resource,
		Headers:  req.Headers,
		Body:     req.Body,
		TenantId: req.TenantID,
		Context:  req.Context,
	}
	if req.Peer != nil {
		out.Peer = &authv1.PeerInfo{
			RemoteAddr: req.Peer.RemoteAddr,
			SpiffeId:   req.Peer.SpiffeID,
		}
	}
	return out
}

func responseFromProto(in *authv1.AuthorizeResponse) *Response {
	if in == nil {
		return &Response{}
	}
	out := &Response{
		Allow:           in.GetAllow(),
		HTTPStatus:      int(in.GetHttpStatus()),
		UpstreamHeaders: in.GetUpstreamHeaders(),
		ResponseHeaders: in.GetResponseHeaders(),
		DenyReason:      in.GetDenyReason(),
	}
	if id := in.GetIdentity(); id != nil {
		out.IdentitySubject = id.GetSubject()
		out.IdentitySource = id.GetSource()
		out.IdentityClaims = id.GetClaims()
	}
	return out
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that
// calls Authorize on every inbound RPC, using the gRPC method name as
// both `method` and `resource`. Incoming metadata becomes the request
// headers (lower-cased per gRPC convention; first value wins).
//
// On deny, the interceptor returns codes.PermissionDenied (401-ish
// HTTP statuses become Unauthenticated) with the deny reason.
func (c *Client) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		hdrs := make(map[string]string, len(md))
		for k, vs := range md {
			if len(vs) > 0 {
				hdrs[strings.ToLower(k)] = vs[0]
			}
		}
		resp, err := c.auth.Authorize(ctx, &authv1.AuthorizeRequest{
			Method:   "POST", // gRPC over HTTP/2 is always POST
			Resource: info.FullMethod,
			Headers:  hdrs,
		})
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "lwauthclient: %v", err)
		}
		if !resp.GetAllow() {
			return nil, status.Error(httpStatusToGRPCCode(int(resp.GetHttpStatus())), resp.GetDenyReason())
		}
		// Surface upstream headers as outgoing trailing metadata so the
		// gRPC handler / its callers can see e.g. the resolved subject.
		if extra := resp.GetUpstreamHeaders(); len(extra) > 0 {
			pairs := make([]string, 0, 2*len(extra))
			for k, v := range extra {
				pairs = append(pairs, k, v)
			}
			_ = grpc.SetHeader(ctx, metadata.Pairs(pairs...))
		}
		return handler(ctx, req)
	}
}

// HTTPMiddleware returns net/http middleware that calls Authorize for
// every request, denies with the lwauth-supplied status and reason on
// deny, and otherwise forwards to next.
//
// On allow, UpstreamHeaders are added to the inbound request before
// next sees it; ResponseHeaders are added to the outbound response.
func (c *Client) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdrs := make(map[string]string, len(r.Header))
		for k, vs := range r.Header {
			if len(vs) > 0 {
				hdrs[strings.ToLower(k)] = vs[0]
			}
		}
		resp, err := c.auth.Authorize(r.Context(), &authv1.AuthorizeRequest{
			Method:   r.Method,
			Resource: r.URL.Path,
			Headers:  hdrs,
		})
		if err != nil {
			http.Error(w, "lwauth unavailable", c.HTTPStatusOnError)
			return
		}
		if !resp.GetAllow() {
			st := int(resp.GetHttpStatus())
			if st == 0 {
				st = http.StatusForbidden
			}
			for k, v := range resp.GetResponseHeaders() {
				w.Header().Set(k, v)
			}
			http.Error(w, resp.GetDenyReason(), st)
			return
		}
		for k, v := range resp.GetUpstreamHeaders() {
			r.Header.Set(k, v)
		}
		for k, v := range resp.GetResponseHeaders() {
			w.Header().Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

// httpStatusToGRPCCode mirrors internal/server.statusToGRPC so HTTP
// status hints from lwauth become idiomatic gRPC codes for callers
// using the unary interceptor.
func httpStatusToGRPCCode(s int) codes.Code {
	switch s {
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusForbidden:
		return codes.PermissionDenied
	case http.StatusServiceUnavailable:
		return codes.Unavailable
	case http.StatusInternalServerError:
		return codes.Internal
	default:
		return codes.PermissionDenied
	}
}

// ErrNotConfigured is returned by SDK helpers that require a Dial-built
// Client (rather than a NewWithConn one).
var ErrNotConfigured = errors.New("lwauthclient: client not configured for this operation")
