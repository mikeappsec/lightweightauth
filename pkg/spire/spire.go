// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package spire provides optional integration with SPIFFE/SPIRE for
// automated workload identity and certificate lifecycle management.
//
// When enabled, lwauth nodes obtain their X.509-SVIDs from the local
// SPIRE agent via the Workload API. This provides:
//
//   - Automatic certificate issuance (no manual cert provisioning)
//   - Automatic rotation (SPIRE handles renewal before expiry)
//   - Workload attestation (identity tied to k8s service account)
//   - Trust bundle distribution (automatic CA bundle updates)
//   - SPIFFE ID-based identity (spiffe://trust-domain/ns/x/sa/y)
//
// # Usage
//
// Set LWAUTH_SPIRE_ENABLED=true and optionally LWAUTH_SPIRE_SOCKET_PATH
// (defaults to unix:///tmp/spire-agent/public/api.sock on Linux or the
// CSI driver socket path in Kubernetes).
//
// The SPIRE agent must be running on the same node with a registration
// entry that matches the lwauth workload (typically by k8s service account).
//
// # Architecture
//
//	┌──────────────┐    Workload API     ┌─────────────┐
//	│  lwauth node │ ◀──────────────────▶│ SPIRE Agent │
//	│              │   (Unix socket)      └──────┬──────┘
//	│  • gets SVID │                              │
//	│  • auto-rotate│                             │
//	│  • trust bundle│                    ┌───────▼──────┐
//	└──────────────┘                      │ SPIRE Server │
//	                                      │  (CA)        │
//	                                      └──────────────┘
//
// The Source returned by Connect() implements crypto/tls.Config
// generation for both server and client mTLS, with automatic rotation.
package spire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// DefaultSocketPath is the standard SPIRE agent Workload API socket.
const DefaultSocketPath = "unix:///tmp/spire-agent/public/api.sock"

// KubernetesCSISocketPath is the socket path when using the SPIFFE CSI driver.
const KubernetesCSISocketPath = "unix:///spiffe-workload-api/spire-agent.sock"

// Config configures the SPIRE integration.
type Config struct {
	// Enabled turns on SPIRE-based identity. When false, falls back to
	// file-based certificates.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// SocketPath is the SPIRE agent Workload API socket address.
	// Default: unix:///tmp/spire-agent/public/api.sock
	SocketPath string `json:"socketPath,omitempty" yaml:"socketPath,omitempty"`

	// TrustDomain is the expected SPIFFE trust domain. If set, the
	// Source will reject SVIDs from other trust domains.
	TrustDomain string `json:"trustDomain,omitempty" yaml:"trustDomain,omitempty"`

	// Audience is the expected audience for JWT-SVIDs (if used).
	Audience string `json:"audience,omitempty" yaml:"audience,omitempty"`
}

// LoadConfigFromEnv loads SPIRE config from environment variables.
func LoadConfigFromEnv() Config {
	cfg := Config{
		Enabled:     os.Getenv("LWAUTH_SPIRE_ENABLED") == "true",
		SocketPath:  os.Getenv("LWAUTH_SPIRE_SOCKET_PATH"),
		TrustDomain: os.Getenv("LWAUTH_SPIRE_TRUST_DOMAIN"),
		Audience:    os.Getenv("LWAUTH_SPIRE_AUDIENCE"),
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}
	return cfg
}

// Source provides X.509 certificates and trust bundles from SPIRE.
// It watches for updates and automatically rotates credentials.
//
// This is a lightweight abstraction over the SPIRE Workload API that
// doesn't import the full go-spiffe SDK — allowing the dependency to
// be optional. The actual SPIRE SDK integration is in source_spire.go
// (build-tagged).
type Source struct {
	mu          sync.RWMutex
	certificate *tls.Certificate
	trustBundle *x509.CertPool
	spiffeID    string
	lastUpdate  time.Time
	cancel      context.CancelFunc
	cfg         Config
}

// SVID represents a SPIFFE Verifiable Identity Document (X.509 flavor).
type SVID struct {
	// Certificate is the X.509 certificate chain.
	Certificate *tls.Certificate

	// TrustBundle is the CA cert pool for verifying peers.
	TrustBundle *x509.CertPool

	// SPIFFEID is the SPIFFE ID from the certificate (e.g., spiffe://domain/ns/x/sa/y).
	SPIFFEID string

	// ExpiresAt is when the SVID expires.
	ExpiresAt time.Time
}

// Connect establishes a connection to the SPIRE agent and begins
// watching for SVID updates. Returns a Source that provides TLS configs.
//
// The returned Source automatically rotates certificates when SPIRE
// issues new ones (typically at ~50% of the SVID lifetime).
//
// Call Close() when done to release resources.
func Connect(ctx context.Context, cfg Config) (*Source, error) {
	if !cfg.Enabled {
		return nil, errors.New("spire: not enabled")
	}

	slog.Info("spire: connecting to workload API", "socket", cfg.SocketPath)

	ctx, cancel := context.WithCancel(ctx)
	src := &Source{
		cfg:    cfg,
		cancel: cancel,
	}

	// Attempt initial connection to the SPIRE agent.
	if err := src.fetchInitialSVID(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("spire: initial SVID fetch failed: %w", err)
	}

	// Start background watcher for SVID rotation.
	go src.watchUpdates(ctx)

	slog.Info("spire: connected and received SVID",
		"spiffe_id", src.spiffeID,
		"expires_at", src.certificate.Leaf.NotAfter,
	)

	return src, nil
}

// TLSServerConfig returns a tls.Config for serving with the current SVID.
// The config uses the latest certificate and requires client mTLS verification
// against the SPIRE trust bundle.
func (s *Source) TLSServerConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			if s.certificate == nil {
				return nil, errors.New("spire: no certificate available")
			}
			return s.certificate, nil
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  s.getTrustBundle(),
		MinVersion: tls.VersionTLS13,
	}
}

// TLSClientConfig returns a tls.Config for connecting to a peer using
// the current SVID as the client certificate.
func (s *Source) TLSClientConfig() *tls.Config {
	return &tls.Config{
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			if s.certificate == nil {
				return nil, errors.New("spire: no certificate available")
			}
			return s.certificate, nil
		},
		RootCAs:    s.getTrustBundle(),
		MinVersion: tls.VersionTLS13,
	}
}

// SPIFFEID returns the current SPIFFE ID.
func (s *Source) SPIFFEID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.spiffeID
}

// Certificate returns the current X.509 certificate.
func (s *Source) Certificate() *tls.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certificate
}

// TrustBundle returns the current CA trust bundle.
func (s *Source) TrustBundle() *x509.CertPool {
	return s.getTrustBundle()
}

// Close stops the background SVID watcher and releases resources.
func (s *Source) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

// getTrustBundle returns the current trust bundle.
func (s *Source) getTrustBundle() *x509.CertPool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trustBundle
}

// updateSVID atomically updates the certificate and trust bundle.
func (s *Source) updateSVID(cert *tls.Certificate, bundle *x509.CertPool, spiffeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certificate = cert
	s.trustBundle = bundle
	s.spiffeID = spiffeID
	s.lastUpdate = time.Now()
	slog.Info("spire: SVID updated",
		"spiffe_id", spiffeID,
		"expires_at", cert.Leaf.NotAfter,
		"rotation_in", time.Until(cert.Leaf.NotAfter).Round(time.Minute),
	)
}

// fetchInitialSVID performs the initial SVID fetch.
// This is the integration point with the SPIRE Workload API SDK.
// In production, this calls workloadapi.NewX509Source().
// For builds without the go-spiffe dependency, this returns an error
// indicating SPIRE is not available.
func (s *Source) fetchInitialSVID(ctx context.Context) error {
	return fetchSVIDFromWorkloadAPI(ctx, s)
}

// watchUpdates monitors for SVID rotation events from SPIRE.
func (s *Source) watchUpdates(ctx context.Context) {
	watchSVIDUpdates(ctx, s)
}
