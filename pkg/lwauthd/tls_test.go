package lwauthd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCertPair generates a throwaway self-signed ECDSA cert/key
// pair and writes them as PEM files under tmp. Returns the
// (certPath, keyPath) tuple. Callers control the lifetime via t.TempDir.
func writeTestCertPair(t *testing.T, tmp string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// TestBuildServerTLS_Plaintext: no cert/key -> nil config (plaintext).
func TestBuildServerTLS_Plaintext(t *testing.T) {
	t.Parallel()
	cfg, err := buildServerTLS("", "", "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cfg != nil {
		t.Fatalf("cfg = %v, want nil", cfg)
	}
}

// TestBuildServerTLS_HalfConfigured: cert without key (or vice versa)
// must fail closed at startup, not silently downgrade to plaintext.
func TestBuildServerTLS_HalfConfigured(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cert, _ := writeTestCertPair(t, tmp)
	if _, err := buildServerTLS(cert, "", ""); err == nil {
		t.Fatalf("cert without key: want error, got nil")
	}
	if _, err := buildServerTLS("", cert, ""); err == nil {
		t.Fatalf("key without cert: want error, got nil")
	}
}

// TestBuildServerTLS_ClientCANeedsServerCert: setting ClientCA without
// the server cert is a misconfiguration (mTLS server has nothing to
// present); reject at startup.
func TestBuildServerTLS_ClientCANeedsServerCert(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cert, _ := writeTestCertPair(t, tmp)
	if _, err := buildServerTLS("", "", cert); err == nil {
		t.Fatalf("clientCA without server cert: want error, got nil")
	}
}

// TestBuildServerTLS_FullMTLS: cert + key + clientCA produces a config
// with RequireAndVerifyClientCert.
func TestBuildServerTLS_FullMTLS(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cert, key := writeTestCertPair(t, tmp)
	cfg, err := buildServerTLS(cert, key, cert) // reuse cert as its own CA
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cfg == nil {
		t.Fatalf("cfg = nil")
	}
	if cfg.MinVersion < 0x0303 { // TLS 1.2
		t.Errorf("MinVersion = %x, want >= TLS 1.2", cfg.MinVersion)
	}
	if cfg.ClientCAs == nil {
		t.Errorf("ClientCAs = nil, want pool")
	}
	// 4 == tls.RequireAndVerifyClientCert
	if int(cfg.ClientAuth) != 4 {
		t.Errorf("ClientAuth = %d, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
}

// TestLoadCAPool_RejectsEmptyPEM: a blank or non-PEM file must not
// silently produce an empty pool that would pass mTLS configuration
// while accepting nothing.
func TestLoadCAPool_RejectsEmptyPEM(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem block"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadCAPool(bad); err == nil {
		t.Fatalf("loadCAPool: want error on non-PEM, got nil")
	}
}
