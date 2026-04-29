package server

// Security regression tests for the native Door B adapter.
//
// Trust-boundary rule: peer certificates used for mTLS-based
// identification must come exclusively from the gRPC server's
// verified TLS handshake, never from anything the caller put in the
// request body. requestFromAuthorize never populates PeerCerts;
// verifiedPeerCertFromContext() is the only path that does, and it
// only returns a leaf when the TLS stack produced VerifiedChains.
//
// These tests live in package server (not server_test) so they can
// reach the unexported helpers directly.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
)

// TestRequestFromAuthorize_DoesNotPopulatePeerCertsFromBody is the
// primary trust-boundary fence: nothing in the request body is
// allowed to materialise as module.Request.PeerCerts. The mtls
// identifier treats PeerCerts as already-verified DER, so this
// boundary is the only thing standing between a caller and a forged
// "verified" identity.
//
// The proto reserves field number 3 in PeerInfo (formerly
// `bytes cert_chain`) so a future contributor can't accidentally
// re-introduce a body-derived cert source by reusing the slot.
func TestRequestFromAuthorize_DoesNotPopulatePeerCertsFromBody(t *testing.T) {
	t.Parallel()
	in := &authv1.AuthorizeRequest{
		Method:   "GET",
		Resource: "/things",
		Peer: &authv1.PeerInfo{
			RemoteAddr: "10.0.0.5:54321",
			SpiffeId:   "spiffe://forged/identity",
		},
		// Headers an attacker might use to try to smuggle cert
		// material through. None of these are trusted as DER.
		Headers: map[string]string{
			"x-client-cert":              "-----BEGIN CERTIFICATE-----...",
			"x-forwarded-client-cert":    `By=spiffe://x;Cert="..."`,
			"x-peer-cert":                "ZmFrZQ==",
		},
	}
	got := requestFromAuthorize(in)
	if got.PeerCerts != nil {
		t.Fatalf("PeerCerts = %d bytes, want nil (request body is never a trust source)", len(got.PeerCerts))
	}
}

// TestVerifiedPeerCertFromContext_NoTLS asserts the helper returns
// nil when the gRPC connection isn't TLS at all (e.g. dev-mode
// plaintext, bufconn). PeerCerts must stay empty so the mtls module
// short-circuits to ErrNoMatch instead of trusting forged bytes.
func TestVerifiedPeerCertFromContext_NoTLS(t *testing.T) {
	t.Parallel()
	if got := verifiedPeerCertFromContext(context.Background()); got != nil {
		t.Errorf("no peer in ctx: got %d bytes, want nil", len(got))
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr:     fakeAddr{},
		AuthInfo: nil, // plaintext / insecure transport
	})
	if got := verifiedPeerCertFromContext(ctx); got != nil {
		t.Errorf("plaintext peer: got %d bytes, want nil", len(got))
	}
}

// TestVerifiedPeerCertFromContext_TLSWithoutVerifiedChains asserts
// that even if the connection is TLS, an unverified PeerCertificates
// list (server doesn't require client certs) does NOT end up in
// PeerCerts. Only VerifiedChains[0][0] counts as trusted.
func TestVerifiedPeerCertFromContext_TLSWithoutVerifiedChains(t *testing.T) {
	t.Parallel()
	leaf := &x509.Certificate{Raw: []byte("unverified-leaf")}
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			// VerifiedChains intentionally empty — server didn't
			// configure ClientAuth=RequireAndVerify, or the
			// handshake produced no chain.
		},
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr:     fakeAddr{},
		AuthInfo: tlsInfo,
	})
	if got := verifiedPeerCertFromContext(ctx); got != nil {
		t.Errorf("TLS without VerifiedChains: got %d bytes, want nil", len(got))
	}
}

// TestVerifiedPeerCertFromContext_VerifiedChain asserts the positive
// path: when the gRPC stack produced a verified chain, the leaf DER
// bytes flow through.
func TestVerifiedPeerCertFromContext_VerifiedChain(t *testing.T) {
	t.Parallel()
	leafDER := []byte("verified-leaf-DER")
	leaf := &x509.Certificate{Raw: leafDER}
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf}},
		},
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr:     fakeAddr{},
		AuthInfo: tlsInfo,
	})
	got := verifiedPeerCertFromContext(ctx)
	if string(got) != string(leafDER) {
		t.Errorf("got %q, want %q", got, leafDER)
	}
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "10.0.0.5:54321" }
