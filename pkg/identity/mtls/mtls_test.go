// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// makeCert mints a self-signed leaf cert for testing. Optional spiffeID
// adds a SPIFFE URI SAN; CN is always set so we can verify CN fallback.
func makeCert(t *testing.T, cn, issuerCN, spiffeID string) ([]byte, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: issuerCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn + ".svc"},
	}
	if spiffeID != "" {
		u, _ := url.Parse(spiffeID)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return der, pemStr
}

// makeCAandLeaf mints a self-signed CA and a leaf certificate signed by
// that CA. Returns (caPEM, leafPEM, leafDER) — leafDER lets a test
// stuff the cert into Request.PeerCerts; caPEM goes into the
// trustedCAs config so the chain verifies.
func makeCAandLeaf(t *testing.T, caCN, leafCN, spiffeID string) (caPEM, leafPEM string, leafDER []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: caCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: leafCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if spiffeID != "" {
		u, _ := url.Parse(spiffeID)
		leafTmpl.URIs = []*url.URL{u}
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	return caPEM, leafPEM, leafDER
}

func TestMTLS_PeerCertsPath(t *testing.T) {
	t.Parallel()
	der, _ := makeCert(t, "alice", "Corp Root", "")
	id, err := factory("mtls", map[string]any{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	got, err := id.Identify(context.Background(), &module.Request{PeerCerts: der})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", got.Subject)
	}
	if got.Claims["cn"] != "alice" {
		t.Errorf("cn claim = %v, want alice", got.Claims["cn"])
	}
}

func TestMTLS_XFCCPath(t *testing.T) {
	t.Parallel()
	_, pemStr := makeCert(t, "bob", "Corp Root", "spiffe://example.org/ns/default/sa/bob")
	encoded := url.QueryEscape(pemStr)
	xfcc := `By=spiffe://example.org;Hash=abc;Cert="` + encoded + `";Subject="CN=bob"`

	// Operator opts in: a verified Envoy/Istio hop sits in front and
	// emits XFCC. Without trustForwardedClientCert, the header is
	// ignored entirely (covered by TestMTLS_XFCC_DefaultIgnored below).
	// We also pin a trusted issuer so the SEC-MTLS-1 anchor gate is
	// satisfied — trustForwardedClientCert: true alone is rejected.
	// makeCert produces a self-signed cert (parent==template), so the
	// effective Issuer DN is CN=bob, not CN=Corp Root.
	id, err := factory("mtls", map[string]any{
		"trustForwardedClientCert": true,
		"trustedIssuers":           []any{"CN=bob"},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	got, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-Forwarded-Client-Cert": {xfcc}},
	})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	// SPIFFE URI SAN should win over CN.
	if got.Subject != "spiffe://example.org/ns/default/sa/bob" {
		t.Errorf("Subject = %q, want SPIFFE id", got.Subject)
	}
	if got.Claims["spiffe"] != "spiffe://example.org/ns/default/sa/bob" {
		t.Errorf("spiffe claim missing: %v", got.Claims)
	}
}

// TestMTLS_XFCC_DefaultIgnored asserts that with the default config,
// a forged XFCC header from an attacker-generated self-signed cert is
// treated as if no credential was presented at all — never as identity
// material.
func TestMTLS_XFCC_DefaultIgnored(t *testing.T) {
	t.Parallel()
	_, pemStr := makeCert(t, "attacker", "CN=Corp Root CA", "spiffe://example.org/ns/default/sa/admin")
	xfcc := `Cert="` + url.QueryEscape(pemStr) + `";Subject="CN=admin"`

	// Default factory: trustForwardedClientCert is false.
	id, err := factory("mtls", map[string]any{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	_, err = id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-Forwarded-Client-Cert": {xfcc}},
	})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch (forged XFCC must be ignored without trustForwardedClientCert)", err)
	}
}

// TestMTLS_XFCC_SelfSignedRejectedByCAPool: even when XFCC is trusted,
// a self-signed cert that does not chain to the configured CA pool is
// rejected. The legacy trustedIssuers DN allow-list is no longer the
// only check.
func TestMTLS_XFCC_SelfSignedRejectedByCAPool(t *testing.T) {
	t.Parallel()
	// Real CA + cert it signed (the "good" path).
	caPEM, _, _ := makeCAandLeaf(t, "Corp Root CA", "alice", "")
	// Attacker-controlled self-signed cert with a matching Issuer DN
	// to bypass the legacy DN-only check.
	_, attackerPEM := makeCert(t, "alice", "CN=Corp Root CA", "")

	id, err := factory("mtls", map[string]any{
		"trustForwardedClientCert": true,
		"trustedCAs":               caPEM,
		"trustedIssuers":           []any{"CN=Corp Root CA"},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	xfcc := `Cert="` + url.QueryEscape(attackerPEM) + `"`
	_, err = id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-Forwarded-Client-Cert": {xfcc}},
	})
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (self-signed cert must fail chain verify)", err)
	}
}

// TestMTLS_XFCC_TrustedChainAccepted is the positive case: a real cert
// signed by the configured CA passes both chain verification and the
// optional DN allow-list.
func TestMTLS_XFCC_TrustedChainAccepted(t *testing.T) {
	t.Parallel()
	caPEM, leafPEM, _ := makeCAandLeaf(t, "Corp Root CA", "alice", "")

	id, err := factory("mtls", map[string]any{
		"trustForwardedClientCert": true,
		"trustedCAs":               caPEM,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	xfcc := `Cert="` + url.QueryEscape(leafPEM) + `"`
	got, err := id.Identify(context.Background(), &module.Request{
		Headers: map[string][]string{"X-Forwarded-Client-Cert": {xfcc}},
	})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", got.Subject)
	}
}

// TestMTLS_CAPoolRequiresTrustFlag rejects the configuration mistake of
// supplying CA material without enabling the XFCC path — the operator
// almost certainly meant to enable it.
func TestMTLS_CAPoolRequiresTrustFlag(t *testing.T) {
	t.Parallel()
	caPEM, _, _ := makeCAandLeaf(t, "Corp Root CA", "alice", "")
	_, err := factory("mtls", map[string]any{
		"trustedCAs": caPEM,
		// trustForwardedClientCert deliberately omitted
	})
	if err == nil {
		t.Fatal("factory accepted trustedCAs without trustForwardedClientCert")
	}
}

// TestMTLS_TrustFlagRequiresAnchor pins SEC-MTLS-1: enabling
// trustForwardedClientCert without ANY anchor (CA bundle, inline PEM,
// or issuer allow-list) silently re-enables the original blind-XFCC
// behavior — anyone who can reach the listener could spoof any
// subject. The factory must reject this at compile time.
func TestMTLS_TrustFlagRequiresAnchor(t *testing.T) {
	t.Parallel()

	// Bare trust=true with no anchor: must fail.
	if _, err := factory("mtls", map[string]any{
		"trustForwardedClientCert": true,
	}); err == nil {
		t.Fatal("factory accepted trustForwardedClientCert: true without any anchor (CA / issuer)")
	}

	// Empty issuer list still counts as no anchor.
	if _, err := factory("mtls", map[string]any{
		"trustForwardedClientCert": true,
		"trustedIssuers":           []any{},
	}); err == nil {
		t.Fatal("factory accepted trustForwardedClientCert: true with empty trustedIssuers")
	}

	// Each individual anchor is sufficient on its own.
	caPEM, _, _ := makeCAandLeaf(t, "Corp Root CA", "alice", "")
	for label, raw := range map[string]map[string]any{
		"trustedCAs": {
			"trustForwardedClientCert": true,
			"trustedCAs":               caPEM,
		},
		"trustedIssuers": {
			"trustForwardedClientCert": true,
			"trustedIssuers":           []any{"CN=Corp Root CA"},
		},
	} {
		if _, err := factory("mtls", raw); err != nil {
			t.Errorf("anchor %q rejected: %v", label, err)
		}
	}
}

func TestMTLS_TrustedIssuersAllowList(t *testing.T) {
	t.Parallel()
	der, _ := makeCert(t, "carol", "Untrusted CA", "")
	id, _ := factory("mtls", map[string]any{
		"trustedIssuers": []any{"CN=Corp Root"},
	})
	_, err := id.Identify(context.Background(), &module.Request{PeerCerts: der})
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestMTLS_NoCertNoMatch(t *testing.T) {
	t.Parallel()
	id, _ := factory("mtls", map[string]any{})
	_, err := id.Identify(context.Background(), &module.Request{})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}
