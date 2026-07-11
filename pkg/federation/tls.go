// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package federation

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadPeerTLSConfig loads the TLS configuration for connecting to a peer.
// If no TLS files are configured, returns nil (plaintext fallback for dev).
// When TLS files are set, enforces mTLS with certificate verification.
func LoadPeerTLSConfig(peer PeerConfig) (*tls.Config, error) {
	// No TLS configured — plaintext (dev/test only).
	if peer.TLSCertFile == "" && peer.TLSKeyFile == "" && peer.TLSCAFile == "" {
		return nil, nil
	}

	// All three must be provided together.
	if peer.TLSCertFile == "" || peer.TLSKeyFile == "" || peer.TLSCAFile == "" {
		return nil, fmt.Errorf("federation: peer %q: all TLS fields (cert, key, ca) must be set together", peer.ClusterID)
	}

	// Load client certificate.
	cert, err := tls.LoadX509KeyPair(peer.TLSCertFile, peer.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("federation: peer %q: load client cert: %w", peer.ClusterID, err)
	}

	// Load CA for verifying the peer's server certificate.
	caPEM, err := os.ReadFile(peer.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("federation: peer %q: read CA file: %w", peer.ClusterID, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("federation: peer %q: CA file contains no valid certificates", peer.ClusterID)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
		// Verify the peer's certificate against the CA.
		// The server name is derived from the endpoint.
	}, nil
}

// LoadServerTLSConfig loads TLS config for the federation gRPC server.
// This enables mTLS: the server presents its cert and requires clients
// to present a valid certificate signed by the CA.
func LoadServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, nil // No TLS — plaintext server.
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("federation: load server cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// If CA is provided, require and verify client certificates (mTLS).
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("federation: read CA file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("federation: CA file contains no valid certificates")
		}
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}
