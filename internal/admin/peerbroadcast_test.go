package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

var testPeerSecret = []byte("test-peer-secret-16bytes!")

func TestPeerBroadcaster_NilIsNoop(t *testing.T) {
	var pb *PeerBroadcaster
	// Should not panic.
	pb.BroadcastRevocation([]byte(`{}`))
	pb.BroadcastInvalidation([]byte(`{}`))
}

func TestPeerBroadcaster_BroadcastRevocation(t *testing.T) {
	t.Parallel()
	var received atomic.Int64
	var lastBody atomic.Value

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/peer/revoke" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		token := r.Header.Get("X-Peer-Token")
		if !VerifyPeerToken(token, testPeerSecret) {
			t.Error("invalid or missing X-Peer-Token header")
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		lastBody.Store(string(body))
		received.Add(1)
		w.WriteHeader(202)
	}))
	defer peer.Close()

	// Extract host:port from the test server URL.
	addr := peer.Listener.Addr().String()

	pb := NewPeerBroadcaster(PeerBroadcasterOptions{
		Resolver:   &StaticPeerResolver{Peers: []string{addr}},
		SelfAddr:   "not-this-one:8080",
		Timeout:    2 * time.Second,
		PeerSecret: testPeerSecret,
	})

	payload, _ := json.Marshal(map[string]string{"jti": "abc-123"})
	pb.BroadcastRevocation(payload)

	if got := received.Load(); got != 1 {
		t.Fatalf("expected 1 peer to receive broadcast, got %d", got)
	}
	if got, ok := lastBody.Load().(string); ok {
		if got != string(payload) {
			t.Fatalf("body mismatch: %q", got)
		}
	}
}

func TestPeerBroadcaster_SkipsSelf(t *testing.T) {
	t.Parallel()
	var received atomic.Int64

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(202)
	}))
	defer peer.Close()

	addr := peer.Listener.Addr().String()

	// Self addr matches the peer — should be skipped.
	pb := NewPeerBroadcaster(PeerBroadcasterOptions{
		Resolver:   &StaticPeerResolver{Peers: []string{addr}},
		SelfAddr:   addr,
		PeerSecret: testPeerSecret,
	})

	pb.BroadcastRevocation([]byte(`{}`))

	if got := received.Load(); got != 0 {
		t.Fatalf("expected self to be skipped, got %d calls", got)
	}
}

func TestPeerBroadcaster_BroadcastInvalidation(t *testing.T) {
	t.Parallel()
	var received atomic.Int64

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/peer/invalidate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		received.Add(1)
		w.WriteHeader(200)
	}))
	defer peer.Close()

	addr := peer.Listener.Addr().String()

	pb := NewPeerBroadcaster(PeerBroadcasterOptions{
		Resolver:   &StaticPeerResolver{Peers: []string{addr}},
		SelfAddr:   "other:8080",
		PeerSecret: testPeerSecret,
	})

	pb.BroadcastInvalidation([]byte(`{"scope":"all"}`))

	if got := received.Load(); got != 1 {
		t.Fatalf("expected 1 invalidation broadcast, got %d", got)
	}
}

func TestPeerBroadcaster_MultiplePeers(t *testing.T) {
	t.Parallel()
	var received atomic.Int64

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(202)
	})

	peer1 := httptest.NewServer(handler)
	defer peer1.Close()
	peer2 := httptest.NewServer(handler)
	defer peer2.Close()

	pb := NewPeerBroadcaster(PeerBroadcasterOptions{
		Resolver: &StaticPeerResolver{Peers: []string{
			peer1.Listener.Addr().String(),
			peer2.Listener.Addr().String(),
		}},
		SelfAddr:   "other:8080",
		PeerSecret: testPeerSecret,
	})

	pb.BroadcastRevocation([]byte(`{"jti":"x"}`))

	if got := received.Load(); got != 2 {
		t.Fatalf("expected 2 peers to receive broadcast, got %d", got)
	}
}

func TestPeerBroadcaster_PeerUnreachable(t *testing.T) {
	t.Parallel()

	// Use an address that won't connect.
	pb := NewPeerBroadcaster(PeerBroadcasterOptions{
		Resolver:   &StaticPeerResolver{Peers: []string{"127.0.0.1:1"}},
		SelfAddr:   "other:8080",
		Timeout:    100 * time.Millisecond,
		PeerSecret: testPeerSecret,
	})

	// Should not panic or block; fire-and-forget.
	pb.BroadcastRevocation([]byte(`{}`))
}

func TestPeerBroadcaster_NilWithoutSecret(t *testing.T) {
	pb := NewPeerBroadcaster(PeerBroadcasterOptions{
		Resolver: &StaticPeerResolver{Peers: []string{"10.0.0.1:8080"}},
		SelfAddr: "other:8080",
	})
	if pb != nil {
		t.Fatal("expected nil broadcaster when PeerSecret is empty")
	}
}

func TestVerifyPeerToken(t *testing.T) {
	secret := []byte("my-secret-key-for-testing")
	pb := &PeerBroadcaster{peerSecret: secret}

	token := pb.signPeerToken()
	if !VerifyPeerToken(token, secret) {
		t.Fatal("valid token rejected")
	}
	if VerifyPeerToken(token, []byte("wrong-secret")) {
		t.Fatal("wrong secret should fail")
	}
	if VerifyPeerToken("", secret) {
		t.Fatal("empty token should fail")
	}
	if VerifyPeerToken("notanumber.abcdef", secret) {
		t.Fatal("non-numeric timestamp should fail")
	}
}

func TestIsAllowedPeerIP(t *testing.T) {
	tests := []struct {
		ip      string
		allowed bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.100", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"169.254.169.254", false},
		{"169.254.1.1", false},
		{"fe80::1", false},
		{"", false},
		{"not-an-ip", false},
	}
	for _, tc := range tests {
		if got := isAllowedPeerIP(tc.ip); got != tc.allowed {
			t.Errorf("isAllowedPeerIP(%q) = %v, want %v", tc.ip, got, tc.allowed)
		}
	}
}

func TestDNSPeerResolver_CachesResults(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64

	oldFn := lookupHostFn
	lookupHostFn = func(_ context.Context, host string) ([]string, error) {
		calls.Add(1)
		return []string{"10.0.0.1", "10.0.0.2"}, nil
	}
	defer func() { lookupHostFn = oldFn }()

	r := NewDNSPeerResolver("my-svc.ns.svc.cluster.local", "8080")

	peers1, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(peers1) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers1))
	}
	if peers1[0] != "10.0.0.1:8080" {
		t.Fatalf("unexpected peer: %s", peers1[0])
	}

	// Second call should use cache.
	peers2, _ := r.Resolve(context.Background())
	if len(peers2) != 2 {
		t.Fatalf("expected cached result")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 DNS call (cached), got %d", calls.Load())
	}
}

func TestDNSPeerResolver_FiltersUnsafeIPs(t *testing.T) {
	t.Parallel()

	oldFn := lookupHostFn
	lookupHostFn = func(_ context.Context, host string) ([]string, error) {
		return []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "10.0.0.2"}, nil
	}
	defer func() { lookupHostFn = oldFn }()

	r := NewDNSPeerResolver("my-svc.ns.svc.cluster.local", "8080")
	peers, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 safe peers, got %d: %v", len(peers), peers)
	}
}
