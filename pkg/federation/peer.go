// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package federation

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Peer represents a connection to a remote cluster in the federation.
// It handles subscribing to config snapshots and pushing revocations.
type Peer struct {
	config  PeerConfig
	fedCfg  *Config
	mu      sync.Mutex
	healthy bool
	lastSeen time.Time
	version  uint64 // highest snapshot version received from this peer
}

// NewPeer creates a peer connection manager.
func NewPeer(peerCfg PeerConfig, fedCfg *Config) *Peer {
	return &Peer{
		config: peerCfg,
		fedCfg: fedCfg,
	}
}

// ClusterID returns the peer's cluster identifier.
func (p *Peer) ClusterID() ClusterID { return p.config.ClusterID }

// Endpoint returns the peer's gRPC endpoint.
func (p *Peer) Endpoint() string { return p.config.Endpoint }

// IsHealthy returns whether the peer is reachable.
func (p *Peer) IsHealthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.healthy
}

// LastSeen returns the last time we received data from this peer.
func (p *Peer) LastSeen() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastSeen
}

// Version returns the highest snapshot version received from this peer.
func (p *Peer) Version() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// AcceptSnapshot validates and records a snapshot from this peer.
// Returns an error if the HMAC is invalid or the snapshot is stale.
func (p *Peer) AcceptSnapshot(snap *Snapshot, signature []byte) error {
	// Security hardening: reject oversized payloads before expensive HMAC
	// computation to prevent CPU exhaustion attacks.
	if len(snap.SpecJSON) > MaxSnapshotSize {
		return ErrSnapshotTooLarge
	}

	// Verify HMAC over full payload (version + source + timestamp + spec).
	if !p.fedCfg.Verify(snapshotPayload(snap), signature) {
		slog.Warn("federation: peer snapshot HMAC mismatch",
			"peer", p.config.ClusterID, "version", snap.Version)
		return ErrInvalidHMAC
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Security hardening: reject any snapshot with a version lower than
	// what we have already accepted, regardless of timestamp, to prevent
	// policy rollback via version downgrade.
	if snap.Version < p.version {
		return ErrStaleSnapshot
	}

	// Accept if version is higher, OR same version with newer timestamp.
	if snap.Version == p.version && !snap.Timestamp.After(p.lastSeen) {
		return ErrStaleSnapshot
	}

	p.version = snap.Version
	p.healthy = true
	p.lastSeen = time.Now()

	slog.Info("federation: accepted snapshot from peer",
		"peer", p.config.ClusterID, "version", snap.Version)
	return nil
}

// MarkHealthy updates the peer's health status.
func (p *Peer) MarkHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
	if healthy {
		p.lastSeen = time.Now()
	}
}

// PeerSet manages all peer connections for a cluster.
type PeerSet struct {
	mu    sync.RWMutex
	peers map[ClusterID]*Peer
	cfg   *Config
}

// NewPeerSet creates a PeerSet from the federation config.
func NewPeerSet(cfg *Config) *PeerSet {
	ps := &PeerSet{
		peers: make(map[ClusterID]*Peer, len(cfg.Peers)),
		cfg:   cfg,
	}
	for _, pc := range cfg.Peers {
		ps.peers[pc.ClusterID] = NewPeer(pc, cfg)
	}
	return ps
}

// Get returns a peer by cluster ID.
func (ps *PeerSet) Get(id ClusterID) (*Peer, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	p, ok := ps.peers[id]
	return p, ok
}

// All returns all peers.
func (ps *PeerSet) All() []*Peer {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]*Peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		out = append(out, p)
	}
	return out
}

// HealthyPeers returns peers that are currently healthy.
func (ps *PeerSet) HealthyPeers() []*Peer {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var out []*Peer
	for _, p := range ps.peers {
		if p.IsHealthy() {
			out = append(out, p)
		}
	}
	return out
}

// BroadcastRevocation signs and delivers a revocation to all peers.
// It's fire-and-forget with logging — failures don't block the caller.
func (ps *PeerSet) BroadcastRevocation(ctx context.Context, entry *RevocationEntry, pushFn func(ctx context.Context, peer *Peer, entry *RevocationEntry, sig []byte) error) {
	sig := ps.cfg.Sign(revocationPayload(entry))

	ps.mu.RLock()
	peers := make([]*Peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		peers = append(peers, p)
	}
	ps.mu.RUnlock()

	for _, peer := range peers {
		if err := pushFn(ctx, peer, entry, sig); err != nil {
			slog.Warn("federation: failed to push revocation to peer",
				"peer", peer.ClusterID(), "key", entry.Key, "err", err)
		}
	}
}
