// Package cachevalkey implements the shared decision-cache backend
// described in DESIGN.md §5: a Valkey-backed cache.Backend that lets
// multiple lwauth replicas share decisions, JWKS responses, and
// introspection results.
//
// It is registered as the "valkey" backend on import. The package speaks
// the RESP protocol via github.com/valkey-io/valkey-go and is wire-
// compatible with both Valkey 7.2+ and Redis 7.x. We document Valkey
// because (a) it is BSD-3 (Apache-2.0-friendly), and (b) it is the
// default in-cloud option after AWS / GCP forked from Redis Inc.
//
// Configuration (cache.BackendSpec):
//
//	cache:
//	  backend: valkey
//	  addr: valkey-master.cache.svc:6379
//	  username: default            # optional, ACLs
//	  password: ${VALKEY_PASSWORD} # optional
//	  tls: true                    # uses InsecureSkipVerify=false
//	  keyPrefix: lwauth/           # so multiple lwauths can share a server
package cachevalkey

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/mikeappsec/lightweightauth/internal/cache"
)

// Backend is the cache.Backend implementation. It holds a single
// auto-pipelined valkey.Client; concurrent Get / Set calls are
// transparently coalesced into shared round-trips by the client.
type Backend struct {
	client    valkey.Client
	keyPrefix string
}

// New constructs a Valkey backend. Exposed for tests that want to feed
// a pre-built valkey.Client (e.g. miniredis).
func New(client valkey.Client, keyPrefix string) *Backend {
	return &Backend{client: client, keyPrefix: keyPrefix}
}

func (b *Backend) prefixed(key string) string {
	if b.keyPrefix == "" {
		return key
	}
	return b.keyPrefix + key
}

// Get returns the stored bytes or ok=false on miss. valkey.IsValkeyNil
// distinguishes a real miss from a transport error.
func (b *Backend) Get(ctx context.Context, key string) ([]byte, bool, error) {
	resp := b.client.Do(ctx, b.client.B().Get().Key(b.prefixed(key)).Build())
	v, err := resp.AsBytes()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("valkey get %s: %w", key, err)
	}
	return v, true, nil
}

// Set stores value with the given TTL. ttl <= 0 stores without
// expiration; the server's eviction policy (typically allkeys-lru) is
// then responsible for reclaiming memory.
func (b *Backend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	cmd := b.client.B().Set().Key(b.prefixed(key)).Value(valkey.BinaryString(value))
	var built valkey.Completed
	if ttl > 0 {
		built = cmd.PxMilliseconds(ttl.Milliseconds()).Build()
	} else {
		built = cmd.Build()
	}
	if err := b.client.Do(ctx, built).Error(); err != nil {
		return fmt.Errorf("valkey set %s: %w", key, err)
	}
	return nil
}

// Delete removes a key. Missing keys are NOT an error so the surface
// matches the in-process LRU's semantics.
func (b *Backend) Delete(ctx context.Context, key string) error {
	if err := b.client.Do(ctx, b.client.B().Del().Key(b.prefixed(key)).Build()).Error(); err != nil {
		return fmt.Errorf("valkey del %s: %w", key, err)
	}
	return nil
}

// Close releases the underlying client. Safe to call multiple times.
func (b *Backend) Close() {
	if b.client != nil {
		b.client.Close()
	}
}

// init registers the backend factory under the name "valkey". The
// factory dials the configured address; tests can bypass this by
// constructing a Backend via New directly.
func init() {
	cache.RegisterBackend("valkey", factory)
}

func factory(spec cache.BackendSpec, _ *cache.Stats) (cache.Backend, error) {
	if spec.Addr == "" {
		return nil, errors.New("valkey: addr is required")
	}
	opt := valkey.ClientOption{
		InitAddress: []string{spec.Addr},
		Username:    spec.Username,
		Password:    spec.Password,
	}
	if spec.TLS {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("valkey: dial %s: %w", spec.Addr, err)
	}
	// Fail fast if the server is unreachable so misconfiguration surfaces
	// at AuthConfig compile time rather than on the first hot-path call.
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Do(pingCtx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("valkey: ping %s: %w", spec.Addr, err)
	}
	return &Backend{client: client, keyPrefix: spec.KeyPrefix}, nil
}
