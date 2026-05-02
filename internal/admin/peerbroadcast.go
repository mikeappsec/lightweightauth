package admin

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// maxPeers caps the number of peers we broadcast to, preventing goroutine
// explosion from DNS misconfiguration.
const maxPeers = 50

// maxConcurrentBroadcast limits parallel outbound HTTP calls.
const maxConcurrentBroadcast = 20

// broadcastTimeout is the detached context timeout for the entire fan-out.
const broadcastTimeout = 5 * time.Second

// PeerBroadcaster fans out revocation events to all known replica peers
// via direct HTTP POST to an internal peer endpoint. This ensures
// revocations propagate even when Valkey Pub/Sub is unavailable.
//
// Peers are discovered via a PeerResolver (typically backed by a Kubernetes
// headless Service DNS lookup). The broadcaster is fire-and-forget: failures
// are logged but do not block the calling handler. Pub/Sub remains the
// primary propagation channel; peer broadcast is belt-and-suspenders.
//
// Authentication: each request carries an X-Peer-Token header containing
// a timestamp and HMAC signature using the shared peer secret. Receiving
// peers verify the token to prevent spoofing.
type PeerBroadcaster struct {
	resolver   PeerResolver
	httpClient *http.Client
	selfAddr   string // this pod's address, excluded from fan-out
	peerSecret []byte // shared secret for peer authentication
	scheme     string // "http" or "https"
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
	// PeerSecret is the shared HMAC secret for peer-to-peer authentication.
	// Required; if empty, the broadcaster is disabled.
	PeerSecret []byte
	// TLSTransport optionally provides a TLS-configured transport for
	// peer-to-peer HTTPS communication. When set, broadcast uses https://.
	TLSTransport http.RoundTripper
}

// NewPeerBroadcaster constructs a broadcaster. Returns nil if Resolver
// or PeerSecret is nil/empty.
func NewPeerBroadcaster(opts PeerBroadcasterOptions) *PeerBroadcaster {
	if opts.Resolver == nil || len(opts.PeerSecret) == 0 {
		return nil
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	scheme := "http"
	client := &http.Client{Timeout: timeout}
	if opts.TLSTransport != nil {
		client.Transport = opts.TLSTransport
		scheme = "https"
	}
	return &PeerBroadcaster{
		resolver:   opts.Resolver,
		selfAddr:   opts.SelfAddr,
		httpClient: client,
		peerSecret: opts.PeerSecret,
		scheme:     scheme,
	}
}

// BroadcastRevocation sends revocation entries to all peers in parallel.
// Fire-and-forget: logs errors but never returns them to the caller.
// Uses a detached context with bounded timeout (not tied to request lifecycle).
func (pb *PeerBroadcaster) BroadcastRevocation(body []byte) {
	if pb == nil {
		return
	}
	pb.broadcast("/internal/peer/revoke", body)
}

// BroadcastInvalidation sends cache invalidation to all peers in parallel.
func (pb *PeerBroadcaster) BroadcastInvalidation(body []byte) {
	if pb == nil {
		return
	}
	pb.broadcast("/internal/peer/invalidate", body)
}

func (pb *PeerBroadcaster) broadcast(path string, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), broadcastTimeout)
	defer cancel()

	peers, err := pb.resolver.Resolve(ctx)
	if err != nil {
		slog.Warn("peer broadcast: resolve failed", "err", err)
		return
	}
	if len(peers) == 0 {
		return
	}

	// SF6: Cap resolved peer count.
	if len(peers) > maxPeers {
		slog.Warn("peer broadcast: too many peers, capping", "count", len(peers), "max", maxPeers)
		peers = peers[:maxPeers]
	}

	// SF6: Bounded concurrency via semaphore channel.
	sem := make(chan struct{}, maxConcurrentBroadcast)
	var wg sync.WaitGroup

	for _, peer := range peers {
		if peer == pb.selfAddr {
			continue
		}
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore slot
			pb.sendToPeer(ctx, addr, path, body)
		}(peer)
	}
	wg.Wait()
}

func (pb *PeerBroadcaster) sendToPeer(ctx context.Context, addr, path string, body []byte) {
	url := fmt.Sprintf("%s://%s%s", pb.scheme, addr, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("peer broadcast: create request failed", "peer", addr, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// SF1+SF3: Authenticate with HMAC-signed peer token.
	req.Header.Set("X-Peer-Token", pb.signPeerToken())

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

// signPeerToken produces "<unix_ts>.<hex_hmac>" for peer authentication.
func (pb *PeerBroadcaster) signPeerToken() string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, pb.peerSecret)
	mac.Write([]byte(ts))
	sig := hex.EncodeToString(mac.Sum(nil))
	return ts + "." + sig
}

// VerifyPeerToken validates a peer token header value. Returns true if
// the token is valid and within the allowed time skew (±60s).
func VerifyPeerToken(token string, secret []byte) bool {
	if len(token) < 3 || len(secret) == 0 {
		return false
	}
	// Find the dot separator.
	dotIdx := -1
	for i, c := range token {
		if c == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx <= 0 || dotIdx >= len(token)-1 {
		return false
	}
	tsStr := token[:dotIdx]
	sigHex := token[dotIdx+1:]

	// Verify HMAC.
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tsStr))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sigHex), []byte(expected)) {
		return false
	}

	// Verify timestamp within ±60s.
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	diff := time.Now().Unix() - ts
	if diff < -60 || diff > 60 {
		return false
	}
	return true
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

	// SF2+SF8: Validate resolved IPs — reject loopback, link-local, metadata.
	peers := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if !isAllowedPeerIP(addr) {
			slog.Warn("peer broadcast: rejected unsafe resolved IP", "ip", addr, "hostname", d.Hostname)
			continue
		}
		peers = append(peers, addr+":"+d.Port)
	}

	d.mu.Lock()
	d.cached = peers
	d.cachedAt = time.Now()
	d.mu.Unlock()

	return peers, nil
}

// isAllowedPeerIP returns false for loopback, link-local, metadata, and
// non-unicast addresses that should never be broadcast targets.
func isAllowedPeerIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// Cloud metadata endpoint (AWS/GCP/Azure).
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return false
	}
	return true
}

// lookupHostFn is a variable so tests can override DNS resolution.
var lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

