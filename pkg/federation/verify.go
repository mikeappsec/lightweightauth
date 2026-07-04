// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// PeerVerifier performs independent verification of peer identity
// before allowing them to join the federation. This implements the
// principle: "the node decides if it trusts this peer", not the
// control plane alone.
type PeerVerifier struct {
	cfg *Config

	// RevocationChecker optionally checks if a peer's certificate or
	// identity has been revoked. If nil, revocation checks are skipped.
	RevocationChecker RevocationChecker

	// TrustedCAs is the CA pool for verifying peer certificates.
	// If nil, system CAs are used.
	TrustedCAs *x509.CertPool
}

// RevocationChecker is the interface for checking certificate/identity revocation.
type RevocationChecker interface {
	// IsRevoked returns true if the given key (e.g., serial number,
	// SPIFFE ID, or cluster ID) is currently revoked.
	IsRevoked(ctx context.Context, key string) (bool, error)
}

// NewPeerVerifier creates a new peer verifier.
func NewPeerVerifier(cfg *Config, revChecker RevocationChecker, trustedCAs *x509.CertPool) *PeerVerifier {
	return &PeerVerifier{
		cfg:               cfg,
		RevocationChecker: revChecker,
		TrustedCAs:        trustedCAs,
	}
}

// VerifyPeerIdentity performs full identity verification of a connecting peer:
//  1. Check the peer is in the configured peer list (allowlist)
//  2. Verify the TLS certificate chain against trusted CAs
//  3. Validate the SPIFFE ID or CN matches the expected cluster identity
//  4. Check revocation status
//
// Returns nil if the peer is verified, or an error describing the failure.
func (v *PeerVerifier) VerifyPeerIdentity(ctx context.Context, clusterID ClusterID, connState *tls.ConnectionState) error {
	// Step 1: Verify the peer is in the configured allowlist.
	if !v.isAllowedPeer(clusterID) {
		return fmt.Errorf("federation: peer %q not in configured peers list", clusterID)
	}

	// Step 2 & 3: If TLS is active, verify certificates and identity.
	if connState != nil && len(connState.PeerCertificates) > 0 {
		if err := v.verifyCertificate(ctx, clusterID, connState); err != nil {
			return err
		}
	}

	// Step 4: Check revocation.
	if v.RevocationChecker != nil {
		revoked, err := v.RevocationChecker.IsRevoked(ctx, "cluster:"+string(clusterID))
		if err != nil {
			slog.Warn("federation: revocation check failed, denying peer",
				"peer", clusterID, "error", err)
			return fmt.Errorf("federation: revocation check failed for peer %q: %w", clusterID, err)
		}
		if revoked {
			slog.Warn("federation: peer is revoked", "peer", clusterID)
			return fmt.Errorf("federation: peer %q is revoked", clusterID)
		}
	}

	slog.Info("federation: peer identity verified", "peer", clusterID)
	return nil
}

// isAllowedPeer checks the configured peer allowlist.
func (v *PeerVerifier) isAllowedPeer(id ClusterID) bool {
	for _, p := range v.cfg.Peers {
		if p.ClusterID == id {
			return true
		}
	}
	return false
}

// verifyCertificate validates the peer's TLS certificate:
// - Checks the chain against trusted CAs
// - Validates the identity (SPIFFE URI or CN) matches the expected cluster
func (v *PeerVerifier) verifyCertificate(ctx context.Context, expectedCluster ClusterID, connState *tls.ConnectionState) error {
	peerCert := connState.PeerCertificates[0]

	// Verify certificate chain against our trusted CAs.
	if v.TrustedCAs != nil {
		opts := x509.VerifyOptions{
			Roots:         v.TrustedCAs,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		for _, cert := range connState.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := peerCert.Verify(opts); err != nil {
			return fmt.Errorf("federation: peer %q: certificate chain verification failed: %w", expectedCluster, err)
		}
	}

	// Check identity: SPIFFE URI SAN takes priority, then CN.
	if !v.matchesExpectedIdentity(peerCert, expectedCluster) {
		return fmt.Errorf("federation: peer %q: certificate identity mismatch (CN=%q, SANs=%v)",
			expectedCluster, peerCert.Subject.CommonName, peerCert.URIs)
	}

	// Check if the specific certificate serial is revoked.
	if v.RevocationChecker != nil {
		serialKey := "cert:" + peerCert.SerialNumber.String()
		revoked, err := v.RevocationChecker.IsRevoked(ctx, serialKey)
		if err != nil {
			return fmt.Errorf("federation: certificate revocation check failed: %w", err)
		}
		if revoked {
			return fmt.Errorf("federation: peer %q: certificate serial %s is revoked", expectedCluster, peerCert.SerialNumber)
		}
	}

	return nil
}

// matchesExpectedIdentity checks if the certificate identifies the expected cluster.
// Checks SPIFFE URIs first (preferred), then falls back to CN.
func (v *PeerVerifier) matchesExpectedIdentity(cert *x509.Certificate, expectedCluster ClusterID) bool {
	// Check SPIFFE URI SANs: spiffe://<trust-domain>/cluster/<cluster-id>
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			path := uri.Path
			// Accept: /cluster/<id> or /ns/<ns>/sa/<sa> patterns.
			if strings.Contains(path, "/cluster/"+string(expectedCluster)) {
				return true
			}
			// Also accept if the host (trust domain) contains the cluster ID.
			if matchesSPIFFECluster(uri, expectedCluster) {
				return true
			}
		}
	}

	// Fallback: check CN contains the cluster ID.
	if strings.Contains(cert.Subject.CommonName, string(expectedCluster)) {
		return true
	}

	// Check DNS SANs.
	for _, dns := range cert.DNSNames {
		if strings.Contains(dns, string(expectedCluster)) {
			return true
		}
	}

	return false
}

// matchesSPIFFECluster checks if a SPIFFE URI matches the expected cluster.
func matchesSPIFFECluster(uri *url.URL, expectedCluster ClusterID) bool {
	// spiffe://trust-domain/cluster/<cluster-id>
	// spiffe://trust-domain/lwauth/<cluster-id>
	parts := strings.Split(uri.Path, "/")
	for i, part := range parts {
		if (part == "cluster" || part == "lwauth") && i+1 < len(parts) {
			if parts[i+1] == string(expectedCluster) {
				return true
			}
		}
	}
	return false
}
