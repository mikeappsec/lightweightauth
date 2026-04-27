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

	"github.com/yourorg/lightweightauth/pkg/module"
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

	id, _ := factory("mtls", map[string]any{})
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
