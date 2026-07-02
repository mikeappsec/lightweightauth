// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"sync"
)

// Group coalesces concurrent computations for the same key so that only one
// in-flight call runs at a time; the rest wait and share its result. It is
// the local (single-replica) half of the cache's stampede protection. For
// cross-replica coalescing, pair it with a [Locker].
//
// The zero value is ready to use.
type Group[T any] struct {
	mu    sync.Mutex
	calls map[string]*call[T]
}

type call[T any] struct {
	wg  sync.WaitGroup
	val T
	err error
}

// Do executes fn for key, ensuring only one execution is in flight for a
// given key at a time. Duplicate callers wait for the original to complete
// and receive the same result. The context governs only the caller's wait;
// fn receives ctx as well.
func (g *Group[T]) Do(ctx context.Context, key string, fn func(context.Context) (T, error)) (T, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*call[T])
	}
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := new(call[T])
	c.wg.Add(1)
	g.calls[key] = c
	g.mu.Unlock()

	c.val, c.err = fn(ctx)
	c.wg.Done()

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()

	return c.val, c.err
}
