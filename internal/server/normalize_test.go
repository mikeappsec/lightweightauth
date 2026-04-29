package server

// Adapter normalization tests.
//
// The two doors (and the JSON HTTP handler) all funnel into the same
// pipeline.Engine via *module.Request. For modules to be authored
// against [module.Request] without caring which transport delivered
// the call, the adapters must agree on the canonical shape:
//
//   - Header keys are lowercase.
//   - Host is the HTTP authority (not the gRPC peer's IP).
//   - Method is uppercase.
//   - PeerCerts carries DER bytes only (XFCC strings stay in the
//     header where the mtls module reads them).
//
// These tests fence the rules at the adapter boundary so a future
// contributor cannot regress them in isolation.

import (
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
)

func TestRequestFromCheck_LowercasesHeaderKeys(t *testing.T) {
	t.Parallel()
	in := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "get",
					Host:    "api.test",
					Path:    "/things",
					Headers: map[string]string{"Authorization": "Bearer t", "X-Tenant": "acme"},
				},
			},
		},
	}
	got := requestFromCheck(in)

	if _, ok := got.Headers["authorization"]; !ok {
		t.Errorf("Headers missing lowercase 'authorization': %v", got.Headers)
	}
	if _, ok := got.Headers["x-tenant"]; !ok {
		t.Errorf("Headers missing lowercase 'x-tenant': %v", got.Headers)
	}
	for k := range got.Headers {
		if k != toLower(k) {
			t.Errorf("Headers contain non-lowercase key %q", k)
		}
	}
	if got.Method != "GET" {
		t.Errorf("Method = %q, want GET", got.Method)
	}
}

func TestRequestFromCheck_DoesNotPolluteCertWithXFCCString(t *testing.T) {
	t.Parallel()
	// Envoy's attrs.Source.Certificate is the XFCC string (URL-encoded
	// PEM), not raw DER. Stuffing it into PeerCerts would make
	// x509.ParseCertificate fail in the mtls module. The adapter must
	// leave PeerCerts nil and rely on the mtls module reading the XFCC
	// header itself.
	in := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{
				Certificate: `By=spiffe://x;Cert="-----BEGIN CERTIFICATE-----..."`,
			},
		},
	}
	got := requestFromCheck(in)
	if got.PeerCerts != nil {
		t.Errorf("PeerCerts should be nil for XFCC-only Door A inputs (got %d bytes)", len(got.PeerCerts))
	}
}

func TestRequestFromAuthorize_LowercasesHeaderKeys(t *testing.T) {
	t.Parallel()
	in := &authv1.AuthorizeRequest{
		Method:   "post",
		Resource: "/things",
		Headers: map[string]string{
			"Authorization": "Bearer t",
			"X-Tenant":      "acme",
			"Host":          "api.test",
		},
	}
	got := requestFromAuthorize(in)
	for _, want := range []string{"authorization", "x-tenant", "host"} {
		if _, ok := got.Headers[want]; !ok {
			t.Errorf("Headers missing lowercase %q: %v", want, got.Headers)
		}
	}
	for k := range got.Headers {
		if k != toLower(k) {
			t.Errorf("Headers contain non-lowercase key %q", k)
		}
	}
	if got.Method != "POST" {
		t.Errorf("Method = %q, want POST", got.Method)
	}
}

func TestRequestFromAuthorize_HostFromHeaderNotPeer(t *testing.T) {
	t.Parallel()
	// Door A's Host comes from envoy.HttpRequest.Host (the HTTP
	// authority). Door B must do the same: prefer the "host" header
	// over peer.RemoteAddr (which is just a TCP IP). DPoP htu-binding
	// and HMAC canonical-string both depend on this.
	in := &authv1.AuthorizeRequest{
		Method:   "GET",
		Resource: "/things",
		Headers:  map[string]string{"Host": "api.example.com"},
		Peer:     &authv1.PeerInfo{RemoteAddr: "10.0.0.5:54321"},
	}
	got := requestFromAuthorize(in)
	if got.Host != "api.example.com" {
		t.Errorf("Host = %q, want api.example.com (from header, not peer)", got.Host)
	}
}

func TestRequestFromAuthorize_HostFallsBackToPeer(t *testing.T) {
	t.Parallel()
	// When no host header is present (non-HTTP gRPC caller), fall
	// back to the peer's remote address so the field is at least
	// populated for audit logs and tenant-resolution code.
	in := &authv1.AuthorizeRequest{
		Method:   "GET",
		Resource: "/things",
		Peer:     &authv1.PeerInfo{RemoteAddr: "10.0.0.5:54321"},
	}
	got := requestFromAuthorize(in)
	if got.Host != "10.0.0.5:54321" {
		t.Errorf("Host = %q, want 10.0.0.5:54321 fallback", got.Host)
	}
}

// toLower avoids importing strings for one call site in the test
// helper (and makes "lowercase" intent explicit).
func toLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// Compile-time assertion that the Envoy peer struct path we read from
// in TestRequestFromCheck_DoesNotPolluteCertWithXFCCString is the same
// one production code reads from. If someone renames it, this won't
// build.
var _ = (&authv3.AttributeContext_Peer{}).Certificate
var _ = (&corev3.HeaderValue{}).Key
