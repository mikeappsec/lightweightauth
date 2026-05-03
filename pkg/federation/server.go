// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Snapshot is an internal representation of a federated config snapshot.
type Snapshot struct {
	Version         uint64    `json:"version"`
	SourceClusterID ClusterID `json:"sourceClusterId"`
	SpecJSON        []byte    `json:"specJson"`
	Timestamp       time.Time `json:"timestamp"`
}

// RevocationEntry is a federated revocation event.
type RevocationEntry struct {
	SourceClusterID ClusterID     `json:"sourceClusterId"`
	Key             string        `json:"key"`
	Reason          string        `json:"reason"`
	TTL             time.Duration `json:"ttl"`
	Timestamp       time.Time     `json:"timestamp"`
}

// SnapshotHandler is called when a verified snapshot is received from a peer.
type SnapshotHandler func(ctx context.Context, snap *Snapshot) error

// RevocationHandler is called when a verified revocation is received from a peer.
type RevocationHandler func(ctx context.Context, entry *RevocationEntry) error

// Server is the federation gRPC server that accepts incoming connections
// from peer clusters. It serves config snapshots and accepts revocations.
type Server struct {
	cfg    *Config
	mu     sync.RWMutex
	latest *Snapshot

	subscribers     map[string]chan *Snapshot // clusterID -> channel
	subscribersMu   sync.Mutex

	revocationHandler RevocationHandler
}

// NewServer creates a federation server.
func NewServer(cfg *Config, revHandler RevocationHandler) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Server{
		cfg:               cfg,
		subscribers:       make(map[string]chan *Snapshot),
		revocationHandler: revHandler,
	}, nil
}

// Publish updates the latest snapshot and notifies all subscribers.
func (s *Server) Publish(ctx context.Context, specJSON []byte) error {
	if len(specJSON) > MaxSnapshotSize {
		return ErrSnapshotTooLarge
	}

	// Validate JSON.
	if !json.Valid(specJSON) {
		return fmt.Errorf("federation: spec_json is not valid JSON")
	}

	s.mu.Lock()
	var version uint64
	if s.latest != nil {
		version = s.latest.Version + 1
	} else {
		version = 1
	}
	snap := &Snapshot{
		Version:         version,
		SourceClusterID: s.cfg.ClusterID,
		SpecJSON:        specJSON,
		Timestamp:       time.Now(),
	}
	s.latest = snap
	s.mu.Unlock()

	// Fan out to subscribers (non-blocking).
	s.subscribersMu.Lock()
	for cid, ch := range s.subscribers {
		select {
		case ch <- snap:
		default:
			slog.Warn("federation: subscriber slow, dropping snapshot",
				"peer", cid, "version", version)
		}
	}
	s.subscribersMu.Unlock()

	slog.Info("federation: published snapshot", "version", version)
	return nil
}

// Subscribe registers a peer cluster for config streaming.
// Returns a channel that receives snapshots. Call Unsubscribe to clean up.
func (s *Server) Subscribe(clusterID ClusterID) (<-chan *Snapshot, error) {
	if err := clusterID.Validate(); err != nil {
		return nil, err
	}

	ch := make(chan *Snapshot, 8) // buffered to absorb bursts

	s.subscribersMu.Lock()
	s.subscribers[string(clusterID)] = ch
	s.subscribersMu.Unlock()

	// Send current snapshot if available.
	s.mu.RLock()
	if s.latest != nil {
		select {
		case ch <- s.latest:
		default:
		}
	}
	s.mu.RUnlock()

	slog.Info("federation: peer subscribed", "peer", clusterID)
	return ch, nil
}

// Unsubscribe removes a peer from the subscriber list.
func (s *Server) Unsubscribe(clusterID ClusterID) {
	s.subscribersMu.Lock()
	if ch, ok := s.subscribers[string(clusterID)]; ok {
		close(ch)
		delete(s.subscribers, string(clusterID))
	}
	s.subscribersMu.Unlock()
	slog.Info("federation: peer unsubscribed", "peer", clusterID)
}

// HandleRevocation processes an incoming revocation from a peer.
// It verifies the HMAC before accepting.
func (s *Server) HandleRevocation(ctx context.Context, entry *RevocationEntry, signature []byte) error {
	// Build the signed payload: key + reason + ttl + timestamp.
	payload := revocationPayload(entry)
	if !s.cfg.Verify(payload, signature) {
		slog.Warn("federation: rejected revocation with invalid HMAC",
			"source", entry.SourceClusterID, "key", entry.Key)
		return ErrInvalidHMAC
	}

	if len(entry.Key) > MaxRevocationKeyLen {
		return fmt.Errorf("federation: revocation key too long (%d > %d)", len(entry.Key), MaxRevocationKeyLen)
	}

	if s.revocationHandler != nil {
		return s.revocationHandler(ctx, entry)
	}
	return nil
}

// SignSnapshot signs a snapshot's spec_json with the federation key.
func (s *Server) SignSnapshot(snap *Snapshot) []byte {
	return s.cfg.Sign(snap.SpecJSON)
}

// VerifySnapshot checks a snapshot's HMAC.
func (s *Server) VerifySnapshot(specJSON, signature []byte) bool {
	return s.cfg.Verify(specJSON, signature)
}

// Latest returns the current highest-version snapshot, if any.
func (s *Server) Latest() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest
}

// SignRevocation signs a revocation entry.
func (s *Server) SignRevocation(entry *RevocationEntry) []byte {
	return s.cfg.Sign(revocationPayload(entry))
}

func revocationPayload(entry *RevocationEntry) []byte {
	// Deterministic: clusterID + key + reason + ttl + timestamp
	b, _ := json.Marshal(struct {
		S string `json:"s"`
		K string `json:"k"`
		R string `json:"r"`
		T int64  `json:"t"`
		U int64  `json:"u"`
	}{
		S: string(entry.SourceClusterID),
		K: entry.Key,
		R: entry.Reason,
		T: int64(entry.TTL.Seconds()),
		U: entry.Timestamp.Unix(),
	})
	return b
}
