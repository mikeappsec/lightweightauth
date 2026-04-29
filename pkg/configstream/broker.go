// Package configstream is the controller→pod fan-out primitive that
// replaces SIGHUP+ConfigMap as the way compiled AuthConfigs reach a
// running lwauth process. It is transport-agnostic: a Broker simply
// produces a stream of snapshots, and a server (gRPC, in-process,
// whatever) wraps it.
//
// Why a broker, not a channel?
//
//   - Multiple lwauth replicas subscribe at different lifecycle points
//     (start-up, post-restart, mid-flight reconnect). Every late
//     subscriber must immediately receive the *latest* snapshot, not
//     the historical sequence. We do this by remembering "current" and
//     replaying it on Subscribe.
//   - A stalled subscriber (slow network, paused Go scheduler) must
//     never block the controller's Publish loop. We fold older pending
//     snapshots into the newest one — config is conflatable; only the
//     latest matters. This is the same trick xDS itself uses.
//
// Versioning. Every snapshot carries a monotonically increasing
// uint64. Subscribers de-duplicate using it; a server may surface it
// as the xDS "version_info" string.
package configstream

import (
	"context"
	"sync"

	"github.com/mikeappsec/lightweightauth/internal/config"
)

// Snapshot is one published AuthConfig. The Spec is shared by
// reference; subscribers must not mutate it. The controller publishes
// fresh values after each successful reconcile, so aliasing across
// snapshots is safe.
type Snapshot struct {
	Version uint64
	Spec    *config.AuthConfig
}

// Broker fans Snapshots out to many subscribers with conflation.
// The zero value is not usable; call NewBroker.
type Broker struct {
	mu      sync.Mutex
	version uint64
	current *Snapshot
	subs    map[*subscription]struct{}
}

// NewBroker constructs a fresh broker with no current snapshot.
func NewBroker() *Broker {
	return &Broker{subs: make(map[*subscription]struct{})}
}

// Publish atomically installs spec as the current snapshot and
// notifies every subscriber. Slow subscribers receive only the latest
// value (older queued values are dropped). Publish never blocks on a
// subscriber.
//
// Publish is safe to call from many goroutines concurrently. Version
// assignment is serialized inside the broker so every snapshot gets a
// unique, monotonically increasing version. Delivery to subscribers
// happens outside the broker mutex, so two concurrent publishers may
// hand a subscriber their snapshots in either order; subscriptions
// reject any snapshot whose version is not strictly greater than the
// highest one already queued or delivered (see [subscription.deliver]),
// so a slow subscriber's pending slot only ever moves forwards.
//
// Multi-writer fan-in (per-tenant publishers, federated control
// planes) is therefore part of the contract. M12-BROKER-MW (v1.1).
func (b *Broker) Publish(spec *config.AuthConfig) Snapshot {
	b.mu.Lock()
	b.version++
	snap := Snapshot{Version: b.version, Spec: spec}
	b.current = &snap
	subs := make([]*subscription, 0, len(b.subs))
	for s := range b.subs {
		subs = append(subs, s)
	}
	b.mu.Unlock()
	for _, s := range subs {
		s.deliver(snap)
	}
	return snap
}

// Latest returns the most recent snapshot, or (zero, false) if none
// has been published. Useful for new gRPC streams that want to send
// an initial value before blocking on updates.
func (b *Broker) Latest() (Snapshot, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current == nil {
		return Snapshot{}, false
	}
	return *b.current, true
}

// Subscribe returns a channel of conflated snapshots. The returned
// channel is closed when ctx is canceled (or the broker is dropped).
// If a snapshot has already been published, it is delivered before
// any subsequent updates. Buffer is depth 1 because the broker
// guarantees latest-wins.
func (b *Broker) Subscribe(ctx context.Context) <-chan Snapshot {
	s := &subscription{
		ch:   make(chan Snapshot, 1),
		cond: make(chan struct{}, 1),
	}

	b.mu.Lock()
	b.subs[s] = struct{}{}
	if b.current != nil {
		// Prime with the current snapshot so a late subscriber
		// doesn't have to wait for the next reconcile. Seed
		// highWater too so a concurrent Publish that delivers an
		// already-superseded snapshot to this brand-new subscription
		// (possible under multi-writer Publish, M12-BROKER-MW)
		// doesn't accidentally regress us below b.current.
		s.pending = b.current
		s.highWater = b.current.Version
	}
	b.mu.Unlock()

	out := make(chan Snapshot)
	go s.pump(ctx, out, func() {
		b.mu.Lock()
		delete(b.subs, s)
		b.mu.Unlock()
	})
	return out
}

// subscription owns one pending slot. deliver is called by Publish
// under no locks (the broker copies the subscriber list first).
//
// highWater is the highest snapshot version this subscription has ever
// observed — either currently queued in pending, or already delivered
// through the channel. deliver compares against it so a delayed
// concurrent Publish from a second writer cannot regress the slot to
// an older snapshot. See [Broker.Publish] for the multi-writer
// rationale.
type subscription struct {
	mu        sync.Mutex
	cond      chan struct{} // signaled when pending becomes non-nil
	pending   *Snapshot
	highWater uint64
	ch        chan Snapshot // unused — pump reads through `pending`
}

// deliver hands snap to the subscription's pending slot, but only if
// snap is newer than anything we've already observed. The
// version-compare here is what makes [Broker.Publish] safe to call
// from many goroutines concurrently.
func (s *subscription) deliver(snap Snapshot) {
	s.mu.Lock()
	if snap.Version <= s.highWater {
		s.mu.Unlock()
		return
	}
	s.highWater = snap.Version
	s.pending = &snap
	s.mu.Unlock()
	// Best-effort wake; pump uses a select with default.
	select {
	case s.cond <- struct{}{}:
	default:
	}
}

// pump reads s.pending and writes to out. If the consumer is slow,
// repeated deliver() calls overwrite pending — the consumer therefore
// always sees the latest. pump exits (and unsubscribes) on ctx.Done.
func (s *subscription) pump(ctx context.Context, out chan<- Snapshot, unsub func()) {
	defer close(out)
	defer unsub()

	// Replay an already-stored "current" snapshot if Subscribe seeded
	// it before pump started.
	s.mu.Lock()
	primed := s.pending
	s.mu.Unlock()
	if primed != nil {
		select {
		case out <- *primed:
			s.mu.Lock()
			if s.pending == primed {
				s.pending = nil
			}
			s.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}

	for {
		s.mu.Lock()
		next := s.pending
		s.pending = nil
		s.mu.Unlock()

		if next != nil {
			select {
			case out <- *next:
			case <-ctx.Done():
				return
			}
			continue
		}
		select {
		case <-s.cond:
		case <-ctx.Done():
			return
		}
	}
}
