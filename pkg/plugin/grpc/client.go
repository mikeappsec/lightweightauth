package grpc

import (
	"errors"
	"fmt"
	"sync"
	"time"

	grpc "google.golang.org/grpc"
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
	return c, nil
}

// connPool de-duplicates *grpc.ClientConn across multiple plugin
// instances pointed at the same address. Two identifiers, one
// authorizer, and one mutator all wired to the same socket share one
// HTTP/2 stream pool — that's the cheap-and-correct default for
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

// dial returns a (possibly shared) ClientConn for address.
//
// TLS support is deferred to M11 (mTLS to plugins). Today the dial is
// always insecure — fine for unix sockets and for TCP plugins co-located
// in the same pod via localhost, which is the documented topology.
func dial(address string) (*grpc.ClientConn, error) {
	dialerOverrideMu.RLock()
	override := dialerOverride
	dialerOverrideMu.RUnlock()
	if override != nil {
		return override(address)
	}

	connPool.mu.Lock()
	defer connPool.mu.Unlock()
	if cc, ok := connPool.conns[address]; ok {
		return cc, nil
	}
	cc, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc-plugin: dial %q: %w", address, err)
	}
	connPool.conns[address] = cc
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
