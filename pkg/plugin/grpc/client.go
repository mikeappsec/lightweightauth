package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// commonConfig is the slice of the YAML body shared by all three
// "grpc-plugin" factory variants. Each adapter parses this plus
// (optionally) its own kind-specific keys — today none exist, but the
// shape leaves room for things like `pluginName` overrides.
type commonConfig struct {
	Address string
	Timeout time.Duration

	// Transport security. The default is "TLS required for any
	// non-loopback TCP address". Operators must opt into plaintext
	// with `insecure: true`, which is intended for local development
	// and unix sockets co-located in the same pod.
	TLS      tlsConfig
	Insecure bool

	// Signing is the F-PLUGIN-2 application-layer signature policy:
	// HMAC-SHA256 over a canonical encoding of the plugin's response,
	// carried as gRPC trailing metadata. Independent of TLS — a
	// well-configured deployment uses both.
	Signing signingConfig
}

// tlsConfig captures the optional credentials a gRPC plugin client
// presents and verifies. All four fields are independent:
//   - CAFile only       -> verify server cert against operator CA bundle.
//   - Cert+KeyFile      -> mTLS client auth (server side decides if it's required).
//   - ServerName        -> SNI / hostname override (useful when dialing by IP or
//     when the plugin pod uses a stable internal DNS name).
type tlsConfig struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
}

func parseCommon(name string, raw map[string]any) (commonConfig, error) {
	var c commonConfig
	addr, _ := raw["address"].(string)
	if addr == "" {
		return c, fmt.Errorf("%w: grpc-plugin %q: address is required", module.ErrConfig, name)
	}
	c.Address = addr

	c.Timeout = time.Second
	if v, ok := raw["timeout"]; ok {
		switch t := v.(type) {
		case string:
			d, err := time.ParseDuration(t)
			if err != nil {
				return c, fmt.Errorf("%w: grpc-plugin %q: timeout: %v", module.ErrConfig, name, err)
			}
			c.Timeout = d
		case time.Duration:
			c.Timeout = t
		default:
			return c, fmt.Errorf("%w: grpc-plugin %q: timeout must be a duration string", module.ErrConfig, name)
		}
	}
	if c.Timeout <= 0 {
		return c, fmt.Errorf("%w: grpc-plugin %q: timeout must be > 0", module.ErrConfig, name)
	}

	if v, ok := raw["insecure"].(bool); ok {
		c.Insecure = v
	}
	if t, ok := raw["tls"].(map[string]any); ok {
		if s, ok := t["caFile"].(string); ok {
			c.TLS.CAFile = s
		}
		if s, ok := t["certFile"].(string); ok {
			c.TLS.CertFile = s
		}
		if s, ok := t["keyFile"].(string); ok {
			c.TLS.KeyFile = s
		}
		if s, ok := t["serverName"].(string); ok {
			c.TLS.ServerName = s
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return c, fmt.Errorf("%w: grpc-plugin %q: tls.certFile and tls.keyFile must be set together", module.ErrConfig, name)
	}

	tlsConfigured := c.TLS.CAFile != "" || c.TLS.CertFile != "" || c.TLS.ServerName != ""
	if c.Insecure && tlsConfigured {
		return c, fmt.Errorf("%w: grpc-plugin %q: insecure: true cannot be combined with tls.* settings", module.ErrConfig, name)
	}

	// Fail-closed for non-loopback TCP without TLS. Plaintext over a
	// shared network would let any attacker who can reach the plugin
	// port forge identity/authorization/mutation responses, which the
	// pipeline trusts by construction.
	if !tlsConfigured && !c.Insecure && requiresTLS(c.Address) {
		return c, fmt.Errorf("%w: grpc-plugin %q: address %q requires TLS (set tls.caFile/certFile/keyFile) or explicit insecure: true for loopback/dev use", module.ErrConfig, name, c.Address)
	}

	sigCfg, err := parseSigning(name, raw)
	if err != nil {
		return c, err
	}
	c.Signing = sigCfg
	return c, nil
}

// requiresTLS returns true when the address points to a TCP host that
// is NOT clearly loopback or a unix socket. The check is intentionally
// conservative: anything we can't classify as loopback is treated as
// "remote" so misconfiguration fails closed.
func requiresTLS(address string) bool {
	addr := strings.TrimPrefix(address, "passthrough:///")
	if strings.HasPrefix(addr, "unix:") || strings.HasPrefix(addr, "unix-abstract:") || strings.HasPrefix(addr, "/") {
		return false
	}
	// Test bufconn / dnsname:authority-style addresses use schemes like
	// "test://" or "dns:///"; both end up dialing in-memory or via
	// real DNS. We treat them as needing TLS unless they're loopback.
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port -> probably a bufconn-style logical name. Be safe.
		host = addr
	}
	switch host {
	case "", "localhost", "127.0.0.1", "::1", "[::1]":
		return false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}

// connPool de-duplicates *grpc.ClientConn across multiple plugin
// instances pointed at the same address+credentials. Two identifiers,
// one authorizer, and one mutator all wired to the same socket share
// one HTTP/2 stream pool — that's the cheap-and-correct default for
// reverse-proxy-style plugin processes that host several services.
//
// The pool is process-wide (package-level) on purpose: the registry
// itself is process-wide. Tests that need an isolated pool inject a
// dialer override via dialerOverride below.
var connPool = struct {
	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}{conns: map[string]*grpc.ClientConn{}}

// dialerOverride lets tests substitute an in-memory bufconn dialer for
// a specific address without touching the real network. When set, the
// returned ClientConn is used as-is (the pool does NOT cache it,
// because tests want fresh state per call).
var (
	dialerOverrideMu sync.RWMutex
	dialerOverride   func(address string) (*grpc.ClientConn, error)
)

func setDialerOverrideForTest(f func(string) (*grpc.ClientConn, error)) func() {
	dialerOverrideMu.Lock()
	prev := dialerOverride
	dialerOverride = f
	dialerOverrideMu.Unlock()
	return func() {
		dialerOverrideMu.Lock()
		dialerOverride = prev
		dialerOverrideMu.Unlock()
	}
}

// poolKey distinguishes connections by address AND credentials so two
// configs that point at the same host with different TLS material
// don't accidentally share a connection.
func poolKey(c commonConfig) string {
	return c.Address + "|" + c.TLS.CAFile + "|" + c.TLS.CertFile + "|" + c.TLS.KeyFile + "|" + c.TLS.ServerName + "|" + boolStr(c.Insecure)
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// buildCreds returns the gRPC TransportCredentials implied by cfg.
// Nothing in this function reaches the network — file reads happen
// here so a misconfigured plugin fails at engine-compile time, not on
// the first authorize call.
func buildCreds(name string, cfg commonConfig) (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		return insecure.NewCredentials(), nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLS.ServerName != "" {
		tlsCfg.ServerName = cfg.TLS.ServerName
	}
	if cfg.TLS.CAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%w: grpc-plugin %q: tls.caFile: %v", module.ErrConfig, name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: grpc-plugin %q: tls.caFile %q contained no PEM certificates", module.ErrConfig, name, cfg.TLS.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("%w: grpc-plugin %q: tls keypair: %v", module.ErrConfig, name, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return credentials.NewTLS(tlsCfg), nil
}

// dial returns a (possibly shared) ClientConn for cfg.
//
// Transport security is selected from cfg: TLS (with optional client
// auth and CA pinning) by default, plaintext only when the operator
// explicitly opts in via `insecure: true`. parseCommon already
// rejected unsafe combinations.
func dial(name string, cfg commonConfig) (*grpc.ClientConn, error) {
	dialerOverrideMu.RLock()
	override := dialerOverride
	dialerOverrideMu.RUnlock()
	if override != nil {
		return override(cfg.Address)
	}

	creds, err := buildCreds(name, cfg)
	if err != nil {
		return nil, err
	}

	key := poolKey(cfg)
	connPool.mu.Lock()
	defer connPool.mu.Unlock()
	if cc, ok := connPool.conns[key]; ok {
		return cc, nil
	}
	cc, err := grpc.NewClient(
		cfg.Address,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc-plugin: dial %q: %w", cfg.Address, err)
	}
	connPool.conns[key] = cc
	return cc, nil
}

// errPluginTransport wraps a transport-level error string the plugin
// returned in its response.error field. It maps to module.ErrUpstream
// so the pipeline reports it with a 502/503-equivalent code.
func errPluginTransport(name, msg string) error {
	return fmt.Errorf("%w: grpc-plugin %q: %s", module.ErrUpstream, name, msg)
}

// errPluginRPC wraps a gRPC-level failure (Unavailable / DeadlineExceeded
// / etc.). Same mapping as transport errors above.
func errPluginRPC(name string, err error) error {
	if errors.Is(err, module.ErrNoMatch) {
		return err
	}
	return fmt.Errorf("%w: grpc-plugin %q: %v", module.ErrUpstream, name, err)
}
