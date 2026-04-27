// Package module defines the stable plugin contracts of LightweightAuth.
//
// Everything inside this package is part of the public API: built-in modules
// (JWT, OAuth2, OPA, RBAC, ...) and third-party modules implement these
// interfaces, and the auth pipeline composes them at runtime based on config.
//
// Design notes:
//
//   - Each interface is intentionally narrow. A module does ONE phase of the
//     pipeline (identify, verify, authorize, mutate-response).
//   - All methods take a *Request value carrying the incoming HTTP/gRPC
//     metadata plus a mutable Context map that later stages can read.
//   - Modules MUST be safe for concurrent use; the pipeline calls them from
//     many goroutines and may fan-out parallel evaluations.
package module

import (
	"context"
	"net/http"
	"strings"
)

// Request is the normalized view of the inbound call being authenticated.
// It is populated by the server layer (HTTP handler or Envoy ext_authz
// adapter) so downstream modules don't care which transport was used.
//
// A Request value is owned by a single goroutine for the duration of an
// Evaluate call. Modules MAY add entries to Context but MUST NOT retain
// references after their method returns.
type Request struct {
	// TenantID identifies the tenant this request belongs to. Set by the
	// server layer (from a header, mTLS SAN, or ext_authz attribute) and
	// used by the pipeline as a cache-key prefix and metric label.
	// See DESIGN.md §8 (multi-tenancy).
	TenantID string

	Method  string
	Host    string
	Path    string
	Headers map[string][]string

	// Body is populated only when an AuthConfig opts in via withBody.
	// See DESIGN.md §8 (request body access).
	Body []byte

	// PeerCerts is non-nil when mTLS termination happened upstream
	// (e.g. Envoy's x-forwarded-client-cert) or in-process.
	PeerCerts []byte

	// Context carries values produced by earlier pipeline stages
	// (e.g. parsed JWT claims) for use by later stages (e.g. OPA input).
	Context map[string]any
}

// Header returns the first value of the named header, case-insensitively,
// or "" if it is not present.
func (r *Request) Header(name string) string {
	if r == nil || r.Headers == nil {
		return ""
	}
	for k, vs := range r.Headers {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// Identity is the result of a successful Identifier run.
type Identity struct {
	Subject string
	Claims  map[string]any
	Source  string // name of the module that produced it
}

// Decision is what the pipeline ultimately returns to the caller / Envoy.
type Decision struct {
	Allow            bool
	Status           int               // HTTP status to return on deny
	ResponseHeaders  map[string]string // headers to add on allow (e.g. X-User)
	UpstreamHeaders  map[string]string // headers Envoy should inject upstream
	Reason           string
}

// Identifier extracts a credential from the request (JWT, API key, mTLS cert,
// HMAC signature, ...). Returning (nil, ErrNoMatch) means "this module
// doesn't apply to this request" — the pipeline tries the next configured
// identifier. Any other error is fatal for this stage.
type Identifier interface {
	Name() string
	Identify(ctx context.Context, r *Request) (*Identity, error)
}

// Authorizer makes the allow/deny call given an established Identity.
// Built-ins: OPA (rego), RBAC (roles+bindings), allow-all, deny-all.
type Authorizer interface {
	Name() string
	Authorize(ctx context.Context, r *Request, id *Identity) (*Decision, error)
}

// ResponseMutator runs after Authorize on allow, e.g. to inject a signed
// internal JWT for the upstream service or strip sensitive headers.
type ResponseMutator interface {
	Name() string
	Mutate(ctx context.Context, r *Request, id *Identity, d *Decision) error
}

// HTTPMounter is an OPTIONAL interface a module may implement to add
// extra HTTP routes to the lwauth server, beyond the standard
// /v1/authorize + /healthz surface.
//
// Today this is used by the OAuth2 auth-code identifier to expose
// /oauth2/start, /oauth2/callback, /oauth2/logout. Mounts are namespaced
// under MountPrefix() (e.g. "/oauth2/") and the server registers them
// directly on its mux; handlers see the FULL request path.
type HTTPMounter interface {
	// MountPrefix is the URL prefix this module wants to own, including
	// the trailing slash (e.g. "/oauth2/").
	MountPrefix() string
	// HTTPHandler is invoked for every request whose path matches
	// MountPrefix().
	HTTPHandler() http.Handler
}

// Factory is what plugin packages register so config can instantiate them
// by name. Built-ins call Register() in their init().
type Factory func(cfg map[string]any) (any, error)
