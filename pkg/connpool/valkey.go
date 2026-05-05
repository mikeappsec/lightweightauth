// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package connpool provides a process-wide connection pool for shared
// infrastructure clients (Valkey, gRPC, HTTP). This eliminates TCP
// connection churn during config hot-reloads and allows subsystems
// (cache, revocation, event bus) targeting the same server to share a
// single multiplexed client.
//
// The design follows the proven pattern from pkg/plugin/grpc/connPool:
// connections are keyed by (address + credentials hash), created on
// first request, and live for the process lifetime. Tests can use
// SetValkeyOverride to inject in-memory alternatives.
package connpool

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
)

// ValkeyConfig is the minimal configuration needed to build or lookup
// a shared Valkey client.
type ValkeyConfig struct {
	Addr     string
	Username string
	Password string
	TLS      bool

	// PipelineMultiplex controls how many connections are used for
	// pipelining. Zero uses the library default (GOMAXPROCS × 2).
	PipelineMultiplex int
}

// valkeyKey uniquely identifies a connection by address + credentials
// so different auth configs targeting different servers remain isolated.
func valkeyKey(cfg ValkeyConfig) string {
	h := sha256.New()
	// Use length-prefixed encoding to prevent null-byte field confusion
	// where field values containing \x00 could collide across boundaries.
	hashField(h, []byte(cfg.Addr))
	hashField(h, []byte(cfg.Username))
	hashField(h, []byte(cfg.Password))
	if cfg.TLS {
		h.Write([]byte("tls"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// valkeyPool is the process-wide Valkey connection pool.
var valkeyPool = struct {
	mu      sync.Mutex
	clients map[string]valkey.Client
}{clients: map[string]valkey.Client{}}

// valkeyOverride allows tests to inject a mock client for any address.
var (
	valkeyOverrideMu sync.RWMutex
	valkeyOverride   func(cfg ValkeyConfig) (valkey.Client, error)
)

// SetValkeyOverride installs a test hook that replaces real Valkey
// connections. Returns a cleanup function that restores the previous
// state. NOT safe for concurrent use from multiple tests.
func SetValkeyOverride(fn func(ValkeyConfig) (valkey.Client, error)) func() {
	valkeyOverrideMu.Lock()
	prev := valkeyOverride
	valkeyOverride = fn
	valkeyOverrideMu.Unlock()
	return func() {
		valkeyOverrideMu.Lock()
		valkeyOverride = prev
		valkeyOverrideMu.Unlock()
	}
}

// GetValkey returns a shared Valkey client for the given config. If a
// client for this (addr, creds) tuple already exists, it is returned
// directly. Otherwise a new client is created, pinged, and cached.
//
// The returned client MUST NOT be closed by callers — it is owned by
// the pool and lives for the process lifetime.
func GetValkey(cfg ValkeyConfig) (valkey.Client, error) {
	// Check override (tests).
	valkeyOverrideMu.RLock()
	override := valkeyOverride
	valkeyOverrideMu.RUnlock()
	if override != nil {
		return override(cfg)
	}

	if cfg.Addr == "" {
		return nil, fmt.Errorf("connpool/valkey: addr is required")
	}

	key := valkeyKey(cfg)

	valkeyPool.mu.Lock()
	defer valkeyPool.mu.Unlock()

	if c, ok := valkeyPool.clients[key]; ok {
		return c, nil
	}

	// Create new client.
	opt := valkey.ClientOption{
		InitAddress: []string{cfg.Addr},
		Username:    cfg.Username,
		Password:    cfg.Password,
	}
	if cfg.TLS {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if cfg.PipelineMultiplex > 0 {
		opt.PipelineMultiplex = cfg.PipelineMultiplex
	}

	client, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("connpool/valkey: dial %s: %w", cfg.Addr, err)
	}

	// Fail-fast ping.
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Do(pingCtx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("connpool/valkey: ping %s: %w", cfg.Addr, err)
	}

	valkeyPool.clients[key] = client
	return client, nil
}

// ResetForTest clears all pooled connections. Only for use in tests.
func ResetForTest() {
	valkeyPool.mu.Lock()
	defer valkeyPool.mu.Unlock()
	for k, c := range valkeyPool.clients {
		c.Close()
		delete(valkeyPool.clients, k)
	}
}

// hashField writes a length-prefixed field into a hash to prevent
// boundary confusion when field values contain null bytes.
func hashField(h interface{ Write([]byte) (int, error) }, data []byte) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(data)))
	h.Write(buf[:])
	h.Write(data)
}
