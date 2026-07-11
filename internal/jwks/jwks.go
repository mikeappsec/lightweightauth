// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package jwks provides a process-shared, lifecycle-bound JWKS keyset cache
// shared by every identifier that verifies JWS against a remote JWKS (jwt,
// idjag, …). It keeps jwx as the refresh engine but ensures exactly one
// background poller per JWKS URL per process, bound to the engine-lifecycle
// context so the poller is torn down on hot-reload instead of leaking on
// context.Background().
//
// This is the §12 "Option A" decision from the cache layer redesign:
//
//   - dedup: identifiers and hot-reloaded engines targeting the same JWKS URL
//     share one poller instead of each spawning their own.
//   - lifecycle: binding the poller to the engine context fixes the goroutine
//     leak where jwx pollers were created with context.Background().
package jwks

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// ErrRegister indicates the JWKS URL could not be registered with jwx. It is
// a configuration-class failure; callers typically wrap it with their module
// ErrConfig sentinel.
var ErrRegister = errors.New("jwks: register failed")

// ErrFetch indicates the initial JWKS fetch failed (network / blackholed IdP /
// timeout). It is an upstream-class failure; callers typically wrap it with
// their module ErrUpstream sentinel.
var ErrFetch = errors.New("jwks: fetch failed")

// initialFetchTimeout bounds the first JWKS GET so a blackholed or very slow
// IdP cannot stall startup indefinitely.
const initialFetchTimeout = 30 * time.Second

// sharedEntry is one process-shared jwx-backed keyset. Its poller is bound to
// a dedicated context (cancelled when the last referencing engine closes), and
// refs counts how many live identifiers depend on it.
type sharedEntry struct {
	keyset jwk.Set
	cancel context.CancelFunc
	refs   int
}

var (
	mu       sync.Mutex
	registry = map[string]*sharedEntry{}
)

// build constructs a dedicated jwx cache + keyset bound to ctx and performs
// the bounded initial fetch. The returned keyset is read-only and safe for
// concurrent use.
func build(ctx context.Context, url string, minRefresh time.Duration) (jwk.Set, error) {
	c := jwk.NewCache(ctx)
	if err := c.Register(url, jwk.WithMinRefreshInterval(minRefresh)); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrRegister, url, err)
	}
	refreshCtx, cancel := context.WithTimeout(ctx, initialFetchTimeout)
	_, err := c.Refresh(refreshCtx, url)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrFetch, url, err)
	}
	return jwk.NewCachedSet(c, url), nil
}

// Standalone returns a one-off keyset bound to ctx. It does not participate in
// the shared registry and is used by direct callers and tests where no engine
// lifecycle context is available.
func Standalone(ctx context.Context, url string, minRefresh time.Duration) (jwk.Set, error) {
	return build(ctx, url, minRefresh)
}

// AcquireShared returns a process-shared cached keyset for url. The underlying
// jwx poller is created once per URL and bound to a dedicated context that is
// cancelled only when the last engine referencing it closes (lifeCtx is the
// engine-lifecycle context from module.Deps.Ctx). lifeCtx MUST be non-nil.
func AcquireShared(lifeCtx context.Context, url string, minRefresh time.Duration) (jwk.Set, error) {
	mu.Lock()
	if e, ok := registry[url]; ok {
		e.refs++
		mu.Unlock()
		go releaseOnDone(lifeCtx, url)
		return e.keyset, nil
	}
	mu.Unlock()

	// Build outside the registry lock so a slow IdP cannot stall acquisitions
	// for unrelated URLs.
	entryCtx, cancel := context.WithCancel(context.Background())
	keyset, err := build(entryCtx, url, minRefresh)
	if err != nil {
		cancel()
		return nil, err
	}

	mu.Lock()
	if e, ok := registry[url]; ok {
		// Lost a creation race with a concurrent acquirer; discard ours and
		// share the winner so there is still exactly one poller per URL.
		e.refs++
		mu.Unlock()
		cancel()
		go releaseOnDone(lifeCtx, url)
		return e.keyset, nil
	}
	registry[url] = &sharedEntry{keyset: keyset, cancel: cancel, refs: 1}
	mu.Unlock()
	go releaseOnDone(lifeCtx, url)
	return keyset, nil
}

// releaseOnDone blocks until lifeCtx is cancelled, then drops one reference to
// the shared entry for url, tearing the poller down when the last reference
// goes away.
func releaseOnDone(lifeCtx context.Context, url string) {
	<-lifeCtx.Done()
	mu.Lock()
	defer mu.Unlock()
	e, ok := registry[url]
	if !ok {
		return
	}
	e.refs--
	if e.refs <= 0 {
		e.cancel()
		delete(registry, url)
	}
}

// refCount returns the live reference count for url, or -1 when no entry
// exists. Exposed for tests within the package.
func refCount(url string) int {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := registry[url]; ok {
		return e.refs
	}
	return -1
}
