package grpc

import (
	"fmt"
	"strings"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// reqToProto is the dual of internal/server/native.go's
// requestFromAuthorize: it projects an in-process *module.Request back
// onto the authv1 wire shape so the plugin sees exactly what a Door B
// caller would see.
//
// The mapping is intentionally lossy in two places:
//
//   - Headers are flattened from []string to string by joining with ",".
//     The plugin proto reuses authv1.AuthorizeRequest, which is map<string,string>;
//     callers needing per-value fidelity should split on "," (the same
//     contract Door B exposes).
//   - module.Request.Context is JSON-string-flattened so a plugin can
//     read upstream pipeline state (e.g. the JWT identifier's parsed claims)
//     even though the wire is map<string,string>.
//
// Path / Host / Method are mapped per the conformance contract: the
// plugin sees Path in the AuthorizeRequest.Resource field, matching the
// way Door B native callers use that field.
func reqToProto(r *module.Request) *authv1.AuthorizeRequest {
	if r == nil {
		return &authv1.AuthorizeRequest{}
	}
	out := &authv1.AuthorizeRequest{
		Method:   r.Method,
		Resource: r.Path,
		TenantId: r.TenantID,
		Body:     r.Body,
	}
	if len(r.Headers) > 0 {
		out.Headers = make(map[string]string, len(r.Headers)+1)
		for k, vs := range r.Headers {
			if len(vs) == 0 {
				continue
			}
			// Lowercase keys per the [module.Request.Headers]
			// invariant. r.Headers should already be lowercase if it
			// came through one of the in-process adapters, but a
			// module that constructed a Request by hand might not be;
			// normalize defensively so the plugin sees the same shape
			// Door B clients see.
			out.Headers[strings.ToLower(k)] = joinHeaderValues(vs)
		}
	}
	// Surface Host as a synthetic "host" header if the caller did not
	// already include one — plugins that route by virtual-host (e.g.
	// a SAML bridge handling multiple IdPs by URL) need it.
	if r.Host != "" {
		if out.Headers == nil {
			out.Headers = map[string]string{}
		}
		if _, ok := out.Headers["host"]; !ok {
			out.Headers["host"] = r.Host
		}
	}
	// Verified peer certificates are not forwarded to plugins over
	// the wire. The cert bytes are trust-bearing, and serialising
	// them into application data would invite a downstream plugin
	// (or anything that proxies for one) to start treating
	// non-handshake-derived bytes as verified. Plugins that need
	// peer identity should read the SPIFFE ID from PeerInfo, the
	// XFCC string from Headers["x-forwarded-client-cert"], or
	// claims surfaced by an upstream identifier.
	if len(r.Context) > 0 {
		out.Context = make(map[string]string, len(r.Context))
		for k, v := range r.Context {
			out.Context[k] = stringifyContextValue(v)
		}
	}
	return out
}

// idToProto flattens an in-process Identity onto the wire shape the
// plugin sees. Mirror of internal/server/native.go:flattenClaims, kept
// duplicated rather than exported so the plugin host can evolve its
// flattening rules independently of Door B (e.g. emit JSON for nested
// objects in the future).
func idToProto(id *module.Identity) *authv1.Identity {
	if id == nil {
		return nil
	}
	return &authv1.Identity{
		Subject: id.Subject,
		Source:  id.Source,
		Claims:  flattenClaims(id.Claims),
	}
}

// idFromProto rehydrates the in-process Identity from the plugin's
// reply. Claims come back as map<string,string>; we promote them to
// `any` so downstream stages (e.g. RBAC's `claim:roles` extraction)
// see the same shape they would from a built-in identifier whose
// claims happen to be strings. Plugins that need richer claim types
// should JSON-encode them on the wire and the policy code can decode.
func idFromProto(in *authv1.Identity, fallbackSource string) *module.Identity {
	if in == nil {
		return nil
	}
	out := &module.Identity{
		Subject: in.GetSubject(),
		Source:  in.GetSource(),
	}
	if out.Source == "" {
		out.Source = fallbackSource
	}
	if len(in.GetClaims()) > 0 {
		out.Claims = make(map[string]any, len(in.GetClaims()))
		for k, v := range in.GetClaims() {
			out.Claims[k] = v
		}
	}
	return out
}

// decisionFromProto translates a plugin-side AuthorizePluginResponse
// onto a *module.Decision. The plugin's deny_reason becomes the
// Decision.Reason, http_status its Status, and the two header maps are
// copied verbatim.
func decisionFromProto(allow bool, status int32, upstream, response map[string]string, denyReason string) *module.Decision {
	d := &module.Decision{
		Allow:           allow,
		Status:          int(status),
		UpstreamHeaders: copyHeaders(upstream),
		ResponseHeaders: copyHeaders(response),
		Reason:          denyReason,
	}
	return d
}

func copyHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeHeaders(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

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
			out[k] = fmt.Sprintf("%v", t)
		}
	}
	return out
}

func joinHeaderValues(vs []string) string {
	if len(vs) == 1 {
		return vs[0]
	}
	out := vs[0]
	for _, v := range vs[1:] {
		out += "," + v
	}
	return out
}

func stringifyContextValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
