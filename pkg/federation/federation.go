// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package federation implements multi-cluster config replication and
// revocation sync for LightweightAuth (DESIGN.md §F8).
//
// Architecture:
//
//	┌──────────┐   SyncConfig stream   ┌──────────┐
//	│ Cluster A├───────────────────────▶│ Cluster B│
//	│ (source) │◀───PushRevocation──────┤(follower)│
//	└──────────┘                        └──────────┘
//
// Each cluster runs a federation.Server (gRPC service) and a
// federation.Peer client per remote cluster. The PeerSet manages
// connections, health checks, and retry.
//
// Trust model: all exchanged payloads are HMAC-SHA256 signed with a
// pre-shared federation key. Peers MUST verify the HMAC before
// accepting any snapshot or revocation. The federation key is
// independent of per-pod HMAC keys used for cache/eventbus.
package federation

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// MaxSnapshotSize is the maximum accepted config snapshot payload.
const MaxSnapshotSize = 16 << 20 // 16 MiB

// MaxRevocationKeyLen caps revocation key length.
const MaxRevocationKeyLen = 512

// MaxClusterIDLen caps cluster ID length.
const MaxClusterIDLen = 253 // DNS-compatible

// Errors.
var (
	ErrInvalidHMAC   = errors.New("federation: HMAC verification failed")
	ErrSnapshotTooLarge = errors.New("federation: snapshot exceeds size limit")
	ErrInvalidClusterID = errors.New("federation: invalid cluster ID")
	ErrStaleSnapshot    = errors.New("federation: stale snapshot (version <= local)")
)

// ClusterID is a unique identifier for a cluster in the federation.
// It follows DNS subdomain naming rules (RFC 1123).
type ClusterID string

// Validate checks the cluster ID is non-empty and within length limits.
func (c ClusterID) Validate() error {
	if len(c) == 0 || len(c) > MaxClusterIDLen {
		return fmt.Errorf("%w: length %d", ErrInvalidClusterID, len(c))
	}
	return nil
}

// String implements fmt.Stringer.
func (c ClusterID) String() string { return string(c) }

// PeerConfig describes a remote cluster to federate with.
type PeerConfig struct {
	// ClusterID is the unique identifier of the remote cluster.
	ClusterID ClusterID `json:"clusterId" yaml:"clusterId"`

	// Endpoint is the gRPC address (host:port) of the remote federation server.
	Endpoint string `json:"endpoint" yaml:"endpoint"`

	// TLSCertFile is the path to the client TLS certificate for mTLS.
	TLSCertFile string `json:"tlsCertFile,omitempty" yaml:"tlsCertFile,omitempty"`

	// TLSKeyFile is the path to the client TLS key.
	TLSKeyFile string `json:"tlsKeyFile,omitempty" yaml:"tlsKeyFile,omitempty"`

	// TLSCAFile is the path to the CA cert for verifying the peer.
	TLSCAFile string `json:"tlsCaFile,omitempty" yaml:"tlsCaFile,omitempty"`

	// Namespaces restricts which namespaces to replicate. Empty = all.
	Namespaces []string `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
}

// Config is the top-level federation configuration.
type Config struct {
	// Enabled toggles federation on/off.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// ClusterID is this cluster's identity in the federation.
	ClusterID ClusterID `json:"clusterId" yaml:"clusterId"`

	// FederationKey is the HMAC-SHA256 pre-shared key for signing/verifying
	// all federated payloads. Must be at least 32 bytes.
	FederationKey []byte `json:"-" yaml:"-"` // never serialized

	// Peers is the list of remote clusters to connect to.
	Peers []PeerConfig `json:"peers" yaml:"peers"`

	// SyncInterval is how often to re-push config snapshots to peers
	// even if nothing changed (heartbeat). Default: 30s.
	SyncInterval time.Duration `json:"syncInterval,omitempty" yaml:"syncInterval,omitempty"`

	// RevocationTTL is the default TTL for federated revocation entries.
	// Default: 24h.
	RevocationTTL time.Duration `json:"revocationTtl,omitempty" yaml:"revocationTtl,omitempty"`
}

// Validate checks the federation config for correctness.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if err := c.ClusterID.Validate(); err != nil {
		return err
	}
	if len(c.FederationKey) < 32 {
		return fmt.Errorf("federation: key must be at least 32 bytes")
	}
	for i, p := range c.Peers {
		if err := p.ClusterID.Validate(); err != nil {
			return fmt.Errorf("federation: peer[%d]: %w", i, err)
		}
		if p.Endpoint == "" {
			return fmt.Errorf("federation: peer[%d] %q: endpoint is required", i, p.ClusterID)
		}
	}
	return nil
}

// Sign computes HMAC-SHA256 of data using the federation key.
func (c *Config) Sign(data []byte) []byte {
	mac := hmac.New(sha256.New, c.FederationKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// Verify checks the HMAC-SHA256 signature of data against the federation key.
func (c *Config) Verify(data, signature []byte) bool {
	expected := c.Sign(data)
	return hmac.Equal(expected, signature)
}
