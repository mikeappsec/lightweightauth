// Package ratelimitvalkey implements the K-DOS-1 distributed rate-limit
// aggregator backed by Valkey (or Redis 7.x). It registers under the
// type name "valkey" via [pkg/ratelimit.RegisterBackend], so an
// AuthConfig containing
//
//	rateLimit:
//	  perTenant: { rps: 200, burst: 400 }
//	  distributed:
//	    type: valkey
//	    addr: valkey-master.cache.svc:6379
//	    keyPrefix: lwauth-rl/
//	    window: 1s
//
// caps every tenant at 400 requests per rolling second across all
// lwauth replicas in the deployment.
//
// The aggregator uses a sorted-set sliding-window log: each request
// adds a (timestamp, unique-member) pair via ZADD; older entries are
// trimmed via ZREMRANGEBYSCORE; the verdict is `ZCARD < limit`. All
// three commands run inside one EVAL so the read-modify-write is
// indivisible. Per-key memory is bounded by `limit` because we only
// admit up to that many in-window entries.
//
// On any operational error (network, auth, circuit-open) the
// implementation returns the error to the caller; the Limiter then
// falls back to the local per-replica bucket per its `failOpen`
// setting. This keeps the gateway available during a Valkey blip.
package ratelimitvalkey

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/mikeappsec/lightweightauth/pkg/ratelimit"
	"github.com/mikeappsec/lightweightauth/pkg/upstream"
)

// Backend is the ratelimit.DistributedBackend implementation.
type Backend struct {
	client    valkey.Client
	keyPrefix string
	guard     *upstream.Guard

	// memberSeed + seq make the per-request unique sorted-set member.
	// We avoid hashing the request payload (we don't have one here)
	// or the score (collision under burst) by combining a process
	// random seed with a monotonic counter — uniqueness is per-
	// process and that is enough because ZADD with a duplicate member
	// would simply update the score, which is exactly the wrong
	// behaviour for a sliding-window counter.
	memberSeed string
	seq        atomic.Uint64
}

// New constructs a Backend. Exposed for tests that want to inject a
// pre-built client (e.g. miniredis-backed). Production code goes
// through the registered factory.
func New(client valkey.Client, keyPrefix string) *Backend {
	seed := make([]byte, 8)
	_, _ = rand.Read(seed)
	return &Backend{
		client:     client,
		keyPrefix:  keyPrefix,
		guard:      upstream.NewGuard(upstream.GuardConfig{}),
		memberSeed: hex.EncodeToString(seed),
	}
}

// allowScript is the atomic sliding-window check.
//
//	KEYS[1]   = the per-tenant key
//	ARGV[1]   = now, milliseconds since epoch
//	ARGV[2]   = window length, milliseconds
//	ARGV[3]   = limit (max in-window entries)
//	ARGV[4]   = unique sorted-set member
//
// Returns 1 if the request is admitted and added, 0 if denied.
//
// The trailing PEXPIRE is set to the window so unused tenants don't
// accumulate keys forever; the TTL is refreshed every admission, so
// active tenants keep their bucket alive.
const allowScript = `
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
local count = redis.call('ZCARD', KEYS[1])
if count >= limit then
  return 0
end
redis.call('ZADD', KEYS[1], now, member)
redis.call('PEXPIRE', KEYS[1], window)
return 1
`

// Allow runs allowScript against the configured client.
func (b *Backend) Allow(ctx context.Context, key string, limit int, window time.Duration, now time.Time) (bool, error) {
	if limit <= 0 {
		// limit==0 means "no cluster cap" — explicitly admit. Should
		// not happen in practice (Limiter computes a positive limit
		// from RPS/burst before calling) but defend against it.
		return true, nil
	}
	if window <= 0 {
		return false, errors.New("ratelimit/valkey: window must be > 0")
	}

	full := b.keyPrefix + key
	nowMs := strconv.FormatInt(now.UnixMilli(), 10)
	winMs := strconv.FormatInt(window.Milliseconds(), 10)
	limStr := strconv.Itoa(limit)
	member := b.memberSeed + ":" + strconv.FormatUint(b.seq.Add(1), 10)

	var allowed bool
	err := b.guard.Do(ctx, func(ctx context.Context) error {
		cmd := b.client.B().Eval().Script(allowScript).Numkeys(1).Key(full).Arg(nowMs, winMs, limStr, member).Build()
		v, err := b.client.Do(ctx, cmd).AsInt64()
		if err != nil {
			return fmt.Errorf("ratelimit/valkey eval: %w", err)
		}
		allowed = v == 1
		return nil
	})
	if err != nil {
		if errors.Is(err, upstream.ErrCircuitOpen) {
			return false, fmt.Errorf("ratelimit/valkey: circuit open")
		}
		return false, err
	}
	return allowed, nil
}

// Close tears down the underlying client. Idempotent.
func (b *Backend) Close() {
	if b.client != nil {
		b.client.Close()
	}
}

// init registers the Valkey-backed ratelimit backend under the type
// name "valkey".
func init() {
	ratelimit.RegisterBackend("valkey", factory)
}

func factory(spec ratelimit.DistributedSpec) (ratelimit.DistributedBackend, error) {
	if spec.Addr == "" {
		return nil, errors.New("ratelimit/valkey: addr is required")
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
		return nil, fmt.Errorf("ratelimit/valkey: dial %s: %w", spec.Addr, err)
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Do(pingCtx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("ratelimit/valkey: ping %s: %w", spec.Addr, err)
	}
	return New(client, spec.KeyPrefix), nil
}
