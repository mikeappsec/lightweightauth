// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package federation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return &Config{
		Enabled:       true,
		ClusterID:     "cluster-a",
		FederationKey: key,
		Peers: []PeerConfig{
			{ClusterID: "cluster-b", Endpoint: "cluster-b.example.com:8443"},
			{ClusterID: "cluster-c", Endpoint: "cluster-c.example.com:8443"},
		},
		SyncInterval:  30 * time.Second,
		RevocationTTL: 24 * time.Hour,
	}
}

func TestConfig_Validate(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

func TestConfig_Validate_DisabledSkipsChecks(t *testing.T) {
	cfg := &Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled config should pass: %v", err)
	}
}

func TestConfig_Validate_ShortKey(t *testing.T) {
	cfg := testConfig(t)
	cfg.FederationKey = []byte("tooshort")
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestConfig_Validate_EmptyClusterID(t *testing.T) {
	cfg := testConfig(t)
	cfg.ClusterID = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty cluster ID")
	}
}

func TestConfig_Validate_PeerMissingEndpoint(t *testing.T) {
	cfg := testConfig(t)
	cfg.Peers[0].Endpoint = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for peer missing endpoint")
	}
}

func TestConfig_SignVerify(t *testing.T) {
	cfg := testConfig(t)
	data := []byte(`{"version":1,"configs":[]}`)

	sig := cfg.Sign(data)
	if !cfg.Verify(data, sig) {
		t.Fatal("signature should verify")
	}

	// Tampered data should fail.
	tampered := []byte(`{"version":2,"configs":[]}`)
	if cfg.Verify(tampered, sig) {
		t.Fatal("tampered data should not verify")
	}

	// Wrong key should fail.
	otherCfg := testConfig(t)
	if otherCfg.Verify(data, sig) {
		t.Fatal("different key should not verify")
	}
}

func TestClusterID_Validate(t *testing.T) {
	cases := []struct {
		id   ClusterID
		ok   bool
	}{
		{"valid-cluster", true},
		{"a", true},
		{"", false},
		{ClusterID(string(make([]byte, 254))), false},
	}
	for _, tc := range cases {
		err := tc.id.Validate()
		if tc.ok && err != nil {
			t.Errorf("ClusterID(%q) should be valid: %v", tc.id, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("ClusterID(%q) should be invalid", tc.id)
		}
	}
}

func TestServer_PublishAndSubscribe(t *testing.T) {
	cfg := testConfig(t)
	srv, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	ch, err := srv.Subscribe("cluster-b")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Unsubscribe("cluster-b")

	spec := []byte(`[{"hosts":["example.com"]}]`)
	if err := srv.Publish(context.Background(), spec); err != nil {
		t.Fatal(err)
	}

	select {
	case snap := <-ch:
		if snap.Version != 1 {
			t.Fatalf("version = %d, want 1", snap.Version)
		}
		if string(snap.SourceClusterID) != "cluster-a" {
			t.Fatalf("source = %q, want cluster-a", snap.SourceClusterID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for snapshot")
	}
}

func TestServer_PublishSendsCurrentOnSubscribe(t *testing.T) {
	cfg := testConfig(t)
	srv, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Publish first.
	if err := srv.Publish(context.Background(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}

	// Subscribe after — should get current snapshot.
	ch, err := srv.Subscribe("cluster-c")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Unsubscribe("cluster-c")

	select {
	case snap := <-ch:
		if snap.Version != 1 {
			t.Fatalf("version = %d, want 1", snap.Version)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for initial snapshot")
	}
}

func TestServer_RejectOversizedSnapshot(t *testing.T) {
	cfg := testConfig(t)
	srv, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	bigSpec := make([]byte, MaxSnapshotSize+1)
	bigSpec[0] = '['
	bigSpec[len(bigSpec)-1] = ']'
	if err := srv.Publish(context.Background(), bigSpec); err == nil {
		t.Fatal("expected error for oversized snapshot")
	}
}

func TestServer_HandleRevocation_ValidHMAC(t *testing.T) {
	cfg := testConfig(t)
	var received *RevocationEntry
	srv, err := NewServer(cfg, func(_ context.Context, entry *RevocationEntry) error {
		received = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	entry := &RevocationEntry{
		SourceClusterID: "cluster-b",
		Key:             "jti:abc123",
		Reason:          "compromised",
		TTL:             time.Hour,
		Timestamp:       time.Now(),
	}
	sig := srv.SignRevocation(entry)

	if err := srv.HandleRevocation(context.Background(), entry, sig); err != nil {
		t.Fatalf("HandleRevocation: %v", err)
	}
	if received == nil || received.Key != "jti:abc123" {
		t.Fatal("handler not called or wrong key")
	}
}

func TestServer_HandleRevocation_InvalidHMAC(t *testing.T) {
	cfg := testConfig(t)
	srv, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	entry := &RevocationEntry{
		SourceClusterID: "cluster-b",
		Key:             "jti:abc123",
		Reason:          "compromised",
		TTL:             time.Hour,
		Timestamp:       time.Now(),
	}

	if err := srv.HandleRevocation(context.Background(), entry, []byte("bad")); err != ErrInvalidHMAC {
		t.Fatalf("expected ErrInvalidHMAC, got: %v", err)
	}
}

func TestPeer_AcceptSnapshot(t *testing.T) {
	cfg := testConfig(t)
	peer := NewPeer(cfg.Peers[0], cfg)

	spec := []byte(`[{"hosts":["peer.example.com"]}]`)
	sig := cfg.Sign(spec)

	snap := &Snapshot{
		Version:         1,
		SourceClusterID: "cluster-b",
		SpecJSON:        spec,
		Timestamp:       time.Now(),
	}

	if err := peer.AcceptSnapshot(snap, sig); err != nil {
		t.Fatalf("AcceptSnapshot: %v", err)
	}
	if peer.Version() != 1 {
		t.Fatalf("version = %d, want 1", peer.Version())
	}
	if !peer.IsHealthy() {
		t.Fatal("peer should be healthy")
	}
}

func TestPeer_AcceptSnapshot_InvalidHMAC(t *testing.T) {
	cfg := testConfig(t)
	peer := NewPeer(cfg.Peers[0], cfg)

	snap := &Snapshot{
		Version:         1,
		SourceClusterID: "cluster-b",
		SpecJSON:        []byte("{}"),
		Timestamp:       time.Now(),
	}

	if err := peer.AcceptSnapshot(snap, []byte("forged")); err != ErrInvalidHMAC {
		t.Fatalf("expected ErrInvalidHMAC, got: %v", err)
	}
}

func TestPeer_AcceptSnapshot_StaleVersion(t *testing.T) {
	cfg := testConfig(t)
	peer := NewPeer(cfg.Peers[0], cfg)

	spec := []byte(`{}`)
	sig := cfg.Sign(spec)

	// Accept version 5.
	snap := &Snapshot{Version: 5, SourceClusterID: "cluster-b", SpecJSON: spec, Timestamp: time.Now()}
	if err := peer.AcceptSnapshot(snap, sig); err != nil {
		t.Fatal(err)
	}

	// Reject version 3 (stale).
	stale := &Snapshot{Version: 3, SourceClusterID: "cluster-b", SpecJSON: spec, Timestamp: time.Now()}
	if err := peer.AcceptSnapshot(stale, sig); err != ErrStaleSnapshot {
		t.Fatalf("expected ErrStaleSnapshot, got: %v", err)
	}
}

func TestPeerSet_BroadcastRevocation(t *testing.T) {
	cfg := testConfig(t)
	ps := NewPeerSet(cfg)

	entry := &RevocationEntry{
		SourceClusterID: cfg.ClusterID,
		Key:             "sub:evil-user",
		Reason:          "account compromise",
		TTL:             time.Hour,
		Timestamp:       time.Now(),
	}

	var pushed []ClusterID
	pushFn := func(_ context.Context, peer *Peer, _ *RevocationEntry, _ []byte) error {
		pushed = append(pushed, peer.ClusterID())
		return nil
	}

	ps.BroadcastRevocation(context.Background(), entry, pushFn)
	if len(pushed) != 2 {
		t.Fatalf("expected 2 pushes, got %d", len(pushed))
	}
}

func TestRevocationPayload_Deterministic(t *testing.T) {
	entry := &RevocationEntry{
		SourceClusterID: "cluster-a",
		Key:             "jti:token123",
		Reason:          "expired",
		TTL:             time.Hour,
		Timestamp:       time.Unix(1000000, 0),
	}

	p1 := revocationPayload(entry)
	p2 := revocationPayload(entry)
	if string(p1) != string(p2) {
		t.Fatal("payload should be deterministic")
	}

	// Verify it's valid JSON.
	var m map[string]any
	if err := json.Unmarshal(p1, &m); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
}
