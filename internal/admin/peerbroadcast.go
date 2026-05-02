package admin

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// PeerBroadcaster fans out revocation events to all known replica peers
// via direct HTTP POST. This ensures revocations propagate even when
// Valkey Pub/Sub is unavailable (E4 hardening).
//
// Peers are discovered via a PeerResolver (typically backed by a Kubernetes
// headless Service DNS lookup). The broadcaster is fire-and-forget: failures
// are logged but do not block the calling handler. Pub/Sub remains the
// primary propagation channel; peer broadcast is belt-and-suspenders.
type PeerBroadcaster struct {
	resolver   PeerResolver
	httpClient *http.Client
	selfAddr   string // this pod's address, excluded from fan-out
}

// PeerResolver returns the current set of peer addresses (host:port).
// Implementations typically resolve a headless Kubernetes Service.
type PeerResolver interface {
	// Resolve returns all peer addresses excluding the caller.
	Resolve(ctx context.Context) ([]string, error)
}

// PeerBroadcasterOptions configures the broadcaster.
type PeerBroadcasterOptions struct {
	// Resolver discovers peer pod addresses.
	Resolver PeerResolver
	// SelfAddr is this pod's address (to skip self-broadcast).
	SelfAddr string
	// Timeout caps each peer HTTP call. Default 2s.
	Timeout time.Duration
}

// NewPeerBroadcaster constructs a broadcaster. Returns nil if Resolver is nil.
func NewPeerBroadcaster(opts PeerBroadcasterOptions) *PeerBroadcaster {
	if opts.Resolver == nil {
		return nil
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &PeerBroadcaster{
		resolver: opts.Resolver,
		selfAddr: opts.SelfAddr,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// BroadcastRevocation sends revocation entries to all peers in parallel.
// Fire-and-forget: logs errors but never returns them to the caller.
func (pb *PeerBroadcaster) BroadcastRevocation(ctx context.Context, body []byte) {
	if pb == nil {
		return
	}
	peers, err := pb.resolver.Resolve(ctx)
	if err != nil {
		slog.Warn("peer broadcast: resolve failed", "err", err)
		return
	}
	if len(peers) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, peer := range peers {
		if peer == pb.selfAddr {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			pb.sendToPeer(ctx, addr, "/v1/admin/revoke", body)
		}(peer)
	}
	wg.Wait()
}

// BroadcastInvalidation sends cache invalidation to all peers in parallel.
func (pb *PeerBroadcaster) BroadcastInvalidation(ctx context.Context, body []byte) {
	if pb == nil {
		return
	}
	peers, err := pb.resolver.Resolve(ctx)
	if err != nil {
		slog.Warn("peer broadcast: resolve failed", "err", err)
		return
	}
	if len(peers) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, peer := range peers {
		if peer == pb.selfAddr {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			pb.sendToPeer(ctx, addr, "/v1/admin/cache/invalidate", body)
		}(peer)
	}
	wg.Wait()
}

func (pb *PeerBroadcaster) sendToPeer(ctx context.Context, addr, path string, body []byte) {
	url := fmt.Sprintf("http://%s%s", addr, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("peer broadcast: create request failed", "peer", addr, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Peer-Broadcast", "true") // marker to prevent infinite fan-out

	resp, err := pb.httpClient.Do(req)
	if err != nil {
		slog.Warn("peer broadcast: send failed", "peer", addr, "path", path, "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Warn("peer broadcast: peer rejected", "peer", addr, "path", path, "status", resp.StatusCode)
	}
}

// --- Static peer resolver (for non-Kubernetes or testing) ---

// StaticPeerResolver returns a fixed set of peer addresses.
type StaticPeerResolver struct {
	Peers []string
}

func (s *StaticPeerResolver) Resolve(_ context.Context) ([]string, error) {
	return s.Peers, nil
}

// --- DNS peer resolver (headless Service) ---

// DNSPeerResolver resolves a headless Kubernetes Service to discover
// all pod IPs. The port is appended to each resolved address.
type DNSPeerResolver struct {
	// Hostname is the DNS name to resolve (e.g. "lwauth-headless.ns.svc.cluster.local").
	Hostname string
	// Port is the admin port (e.g. "8080").
	Port string
	// cacheTTL bounds how long resolved addresses are cached.
	cacheTTL time.Duration

	mu       sync.RWMutex
	cached   []string
	cachedAt time.Time
}

// NewDNSPeerResolver creates a resolver that looks up a headless Service.
func NewDNSPeerResolver(hostname, port string) *DNSPeerResolver {
	return &DNSPeerResolver{
		Hostname: hostname,
		Port:     port,
		cacheTTL: 5 * time.Second,
	}
}

func (d *DNSPeerResolver) Resolve(ctx context.Context) ([]string, error) {
	d.mu.RLock()
	if time.Since(d.cachedAt) < d.cacheTTL && len(d.cached) > 0 {
		peers := d.cached
		d.mu.RUnlock()
		return peers, nil
	}
	d.mu.RUnlock()

	addrs, err := lookupHostFn(ctx, d.Hostname)
	if err != nil {
		return nil, fmt.Errorf("dns peer resolve %s: %w", d.Hostname, err)
	}

	peers := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		peers = append(peers, addr+":"+d.Port)
	}

	d.mu.Lock()
	d.cached = peers
	d.cachedAt = time.Now()
	d.mu.Unlock()

	return peers, nil
}

// lookupHostFn is a variable so tests can override DNS resolution.
var lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}
