package cachevalkey

import (
	"context"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/mikeappsec/lightweightauth/internal/cache"
)

// SFLocker implements cache.DistSFLocker using Valkey SET NX PX.
// Each instance uses the same client as the cache Backend so no
// additional connections are needed.
type SFLocker struct {
	client    valkey.Client
	keyPrefix string
}

// NewSFLocker constructs a distributed singleflight locker.
func NewSFLocker(client valkey.Client, keyPrefix string) *SFLocker {
	return &SFLocker{client: client, keyPrefix: keyPrefix}
}

// NewSFLockerFromBackend creates an SFLocker by extracting the Valkey
// client from a cache.Backend. Returns nil if the backend is not a Valkey
// backend (e.g. in-memory LRU).
func NewSFLockerFromBackend(b cache.Backend, keyPrefix string) *SFLocker {
	vb, ok := b.(*Backend)
	if !ok {
		return nil
	}
	return &SFLocker{client: vb.client, keyPrefix: keyPrefix + "sf:"}
}

// compile-time interface check.
var _ cache.DistSFLocker = (*SFLocker)(nil)

func (l *SFLocker) prefixed(key string) string {
	return l.keyPrefix + key
}

// TryLock uses SET key "1" NX PX <ms>. Returns true if the key was set
// (this replica won); false if the key already existed (another replica
// holds the lock).
func (l *SFLocker) TryLock(ctx context.Context, key string, holdDuration time.Duration) (bool, error) {
	ms := holdDuration.Milliseconds()
	if ms <= 0 {
		ms = 200
	}
	resp := l.client.Do(ctx,
		l.client.B().Set().Key(l.prefixed(key)).Value("1").Nx().PxMilliseconds(ms).Build(),
	)
	err := resp.Error()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			// NX not satisfied → another replica holds the lock.
			return false, nil
		}
		return false, fmt.Errorf("distsf trylock %s: %w", key, err)
	}
	// SET returned OK → we won.
	return true, nil
}

// Unlock deletes the lock key. Best-effort: if it fails, the PX TTL
// ensures automatic release.
func (l *SFLocker) Unlock(ctx context.Context, key string) error {
	err := l.client.Do(ctx, l.client.B().Del().Key(l.prefixed(key)).Build()).Error()
	if err != nil {
		return fmt.Errorf("distsf unlock %s: %w", key, err)
	}
	return nil
}
