// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cachevalkey

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	pkgcache "github.com/mikeappsec/lightweightauth/pkg/cache"
	"github.com/mikeappsec/lightweightauth/pkg/upstream"
)

// This file makes the Valkey *Backend a first-class pkg/cache backend. The
// struct already satisfies pkgcache.Cache (Get/Set/Delete share the public
// signatures); here we add the optional capability interfaces — Locker,
// TagInvalidator, Atomic — so a pkg/cache pool configured with
// `backend: valkey` exposes distributed locks (E4 singleflight), tag
// invalidation, and atomic SetNX/Incr (cross-replica replay & rate limits).
//
// pkg/cache stays stdlib-only and never imports this package; instead this
// backend registers itself into pkg/cache's registry on import, exactly like
// the in-tree "memory" backend registers itself.

func init() {
	pkgcache.RegisterBackend("valkey", pkgFactory)
}

// pkgFactory builds a Valkey-backed pkgcache.Cache from a pool's BackendSpec.
func pkgFactory(spec pkgcache.BackendSpec, _ *pkgcache.Stats) (pkgcache.Cache, error) {
	if spec.Addr == "" {
		return nil, errors.New("valkey: addr is required")
	}
	return dial(spec.Addr, spec.Username, spec.Password, spec.TLS, spec.KeyPrefix, spec.Extra)
}

// incrScript atomically increments KEYS[1] and, only when the counter is
// freshly created (value == 1), applies the supplied PTTL. This mirrors the
// memory backend's "ttl on first creation" semantics for fixed-window rate
// limits while keeping the increment + expire a single round trip.
const incrScript = `local v = redis.call('incr', KEYS[1])
if v == 1 and tonumber(ARGV[1]) > 0 then
  redis.call('pexpire', KEYS[1], ARGV[1])
end
return v`

// --- Locker (remote-only distributed lock) ---------------------------------

// TryLock attempts to acquire key for ttl using SET key <token> NX PX. On
// success it returns a random token the caller must present to Unlock; on
// contention it returns acquired=false with no error.
func (b *Backend) TryLock(ctx context.Context, key string, ttl time.Duration) (string, bool, error) {
	ms := ttl.Milliseconds()
	if ms <= 0 {
		ms = 200
	}
	token := randomToken()
	pkey := b.prefixed(key)
	var acquired bool
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		resp := b.client.Do(ctx, b.client.B().Set().Key(pkey).Value(token).Nx().PxMilliseconds(ms).Build())
		if e := resp.Error(); e != nil {
			if valkey.IsValkeyNil(e) {
				acquired = false // NX not satisfied: another holder.
				return nil
			}
			return fmt.Errorf("valkey trylock %s: %w", key, e)
		}
		acquired = true
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return "", false, fmt.Errorf("valkey trylock %s: circuit open", key)
		}
		return "", false, err
	}
	if !acquired {
		return "", false, nil
	}
	return token, true, nil
}

// Unlock releases key only if its stored value still matches token, so a
// replica never deletes a lock that expired and was re-acquired elsewhere.
func (b *Backend) Unlock(ctx context.Context, key, token string) error {
	if token == "" {
		return nil
	}
	pkey := b.prefixed(key)
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		resp := b.client.Do(ctx, b.client.B().Eval().Script(unlockScript).Numkeys(1).Key(pkey).Arg(token).Build())
		if e := resp.Error(); e != nil {
			return fmt.Errorf("valkey unlock %s: %w", key, e)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return fmt.Errorf("valkey unlock %s: circuit open", key)
		}
		return err
	}
	return nil
}

// --- Atomic (SetNX / Incr) -------------------------------------------------

// SetNX stores value under key only if the key does not already exist,
// returning true when the value was stored. Used by the replay guard for
// cross-replica single-use enforcement.
func (b *Backend) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	cmd := b.client.B().Set().Key(b.prefixed(key)).Value(valkey.BinaryString(value)).Nx()
	var built valkey.Completed
	if ttl > 0 {
		built = cmd.PxMilliseconds(ttl.Milliseconds()).Build()
	} else {
		built = cmd.Build()
	}
	var stored bool
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		resp := b.client.Do(ctx, built)
		if e := resp.Error(); e != nil {
			if valkey.IsValkeyNil(e) {
				stored = false // NX not satisfied: key already present.
				return nil
			}
			return fmt.Errorf("valkey setnx %s: %w", key, e)
		}
		stored = true
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return false, fmt.Errorf("valkey setnx %s: circuit open", key)
		}
		return false, err
	}
	return stored, nil
}

// Incr atomically increments the integer at key, applying ttl only when the
// counter is created, and returns the new value. A non-integer stored value
// yields an error, matching the memory backend and Valkey's INCR.
func (b *Backend) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	ms := ttl.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	var out int64
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		resp := b.client.Do(ctx,
			b.client.B().Eval().Script(incrScript).Numkeys(1).Key(b.prefixed(key)).Arg(strconv.FormatInt(ms, 10)).Build())
		n, e := resp.AsInt64()
		if e != nil {
			return fmt.Errorf("valkey incr %s: %w", key, e)
		}
		out = n
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return 0, fmt.Errorf("valkey incr %s: circuit open", key)
		}
		return 0, err
	}
	return out, nil
}

// --- TagInvalidator --------------------------------------------------------

// tagSetKey is the Valkey set that records the physical keys carrying a tag.
func (b *Backend) tagSetKey(tag string) string { return b.prefixed("tag:" + tag) }

// Tag records that key carries the given tags by adding the physical key to
// each tag's membership set (SADD). Tagging is additive and idempotent.
func (b *Backend) Tag(ctx context.Context, key string, tags ...string) error {
	if len(tags) == 0 {
		return nil
	}
	member := b.prefixed(key)
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		for _, t := range tags {
			if e := b.client.Do(ctx, b.client.B().Sadd().Key(b.tagSetKey(t)).Member(member).Build()).Error(); e != nil {
				return fmt.Errorf("valkey tag %s: %w", t, e)
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return fmt.Errorf("valkey tag: circuit open")
		}
		return err
	}
	return nil
}

// InvalidateTag deletes every key recorded under tag, then clears the tag's
// membership set, returning the number of member keys removed.
func (b *Backend) InvalidateTag(ctx context.Context, tag string) (int, error) {
	setKey := b.tagSetKey(tag)
	var count int
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		members, e := b.client.Do(ctx, b.client.B().Smembers().Key(setKey).Build()).AsStrSlice()
		if e != nil {
			return fmt.Errorf("valkey invalidatetag %s: %w", tag, e)
		}
		// Delete member keys one at a time: the members may hash to distinct
		// cluster slots, which a single multi-key DEL would reject.
		for _, m := range members {
			if e := b.client.Do(ctx, b.client.B().Del().Key(m).Build()).Error(); e != nil {
				return fmt.Errorf("valkey invalidatetag del %s: %w", tag, e)
			}
		}
		count = len(members)
		if e := b.client.Do(ctx, b.client.B().Del().Key(setKey).Build()).Error(); e != nil {
			return fmt.Errorf("valkey invalidatetag clear %s: %w", tag, e)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return 0, fmt.Errorf("valkey invalidatetag %s: circuit open", tag)
		}
		return 0, err
	}
	return count, nil
}

// Compile-time proof that the Valkey backend offers the full pkg/cache
// capability set, so pools backed by it expose locks, tags, and atomics.
var (
	_ pkgcache.Cache          = (*Backend)(nil)
	_ pkgcache.Locker         = (*Backend)(nil)
	_ pkgcache.TagInvalidator = (*Backend)(nil)
	_ pkgcache.Atomic         = (*Backend)(nil)
)
