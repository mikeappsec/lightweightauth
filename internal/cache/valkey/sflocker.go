// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cachevalkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/mikeappsec/lightweightauth/internal/cache"
)

// unlockScript is a Lua script for conditional key deletion.
// Only deletes the key if its current value matches the caller's lock token,
// preventing one replica from releasing another replica's lock.
const unlockScript = `if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end`

// SFLocker implements cache.DistSFLocker using Valkey SET NX PX.
// Each instance uses the same client as the cache Backend so no
// additional connections are needed.
type SFLocker struct {
	client    valkey.Client
	keyPrefix string

	// mu protects the tokens map.
	mu     sync.Mutex
	tokens map[string]string // lockKey → random token
}

// NewSFLocker constructs a distributed singleflight locker.
func NewSFLocker(client valkey.Client, keyPrefix string) *SFLocker {
	return &SFLocker{client: client, keyPrefix: keyPrefix, tokens: make(map[string]string)}
}

// NewSFLockerFromBackend creates an SFLocker by extracting the Valkey
// client from a cache.Backend. Returns nil if the backend is not a Valkey
// backend (e.g. in-memory LRU).
func NewSFLockerFromBackend(b cache.Backend, keyPrefix string) *SFLocker {
	vb, ok := b.(*Backend)
	if !ok {
		return nil
	}
	return &SFLocker{client: vb.client, keyPrefix: keyPrefix + "sf:", tokens: make(map[string]string)}
}

// compile-time interface check.
var _ cache.DistSFLocker = (*SFLocker)(nil)

func (l *SFLocker) prefixed(key string) string {
	return l.keyPrefix + key
}

// randomToken generates a cryptographically random 16-byte hex token.
func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TryLock uses SET key <random_token> NX PX <ms>. Returns true if the
// key was set (this replica won); false if the key already existed.
// The random token is stored locally for conditional Unlock.
func (l *SFLocker) TryLock(ctx context.Context, key string, holdDuration time.Duration) (bool, error) {
	ms := holdDuration.Milliseconds()
	if ms <= 0 {
		ms = 200
	}
	token := randomToken()
	pkey := l.prefixed(key)
	resp := l.client.Do(ctx,
		l.client.B().Set().Key(pkey).Value(token).Nx().PxMilliseconds(ms).Build(),
	)
	err := resp.Error()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			// NX not satisfied → another replica holds the lock.
			return false, nil
		}
		return false, fmt.Errorf("distsf trylock %s: %w", key, err)
	}
	// SET returned OK → we won. Store token for conditional unlock.
	l.mu.Lock()
	l.tokens[pkey] = token
	l.mu.Unlock()
	return true, nil
}

// Unlock conditionally deletes the lock key only if the stored value
// matches our token (Lua script). This prevents releasing a lock held
// by a different replica after TTL expiry + re-acquire.
func (l *SFLocker) Unlock(ctx context.Context, key string) error {
	pkey := l.prefixed(key)
	l.mu.Lock()
	token, ok := l.tokens[pkey]
	if ok {
		delete(l.tokens, pkey)
	}
	l.mu.Unlock()

	if !ok {
		// No token stored — nothing to unlock.
		return nil
	}

	resp := l.client.Do(ctx,
		l.client.B().Eval().Script(unlockScript).Numkeys(1).Key(pkey).Arg(token).Build(),
	)
	if err := resp.Error(); err != nil {
		return fmt.Errorf("distsf unlock %s: %w", key, err)
	}
	return nil
}
