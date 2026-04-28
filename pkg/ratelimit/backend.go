package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DistributedSpec selects an opt-in cluster-wide aggregator for the
// per-tenant bucket (K-DOS-1). When nil, the limiter stays per-replica
// — the v1.0 default. When non-nil, the named backend is consulted on
// every Allow call; the local token bucket continues to act as a
// per-replica safety floor (so a Valkey blip can't undo the local
// limit, just relax the cross-replica cap).
//
// Schema (under AuthConfig.rateLimit.distributed):
//
//	rateLimit:
//	  perTenant: { rps: 200, burst: 400 }
//	  distributed:
//	    type: valkey                       # registered backend
//	    addr: valkey-master.cache.svc:6379
//	    password: ${VALKEY_PASSWORD}       # optional
//	    keyPrefix: lwauth-rl/              # optional, default empty
//	    tls: false
//	    window: 1s                         # sliding window length
//	    timeout: 50ms                      # per-call deadline
//	    failOpen: false                    # what to do when the backend errors
//
// Semantics:
//
//   - The cluster-wide cap is `Spec.PerTenant.Burst` (or RPS*window/1s
//     when Burst is zero) requests in any rolling `window`. Burst on
//     top of RPS is a token-bucket idiom; the sliding-window backend
//     interprets it as "max requests per window", which is the strict
//     equivalent for short windows and the conservative choice for
//     longer ones.
//   - On backend success: the verdict is authoritative; we still
//     charge the local bucket so a single replica can't exceed its
//     local RPS even if Valkey says yes.
//   - On backend error / context timeout: fall back to local. Set
//     `failOpen: true` to skip even the local check on backend error
//     (NOT recommended; useful only when the operator's threat model
//     prefers availability over fairness).
type DistributedSpec struct {
	Type      string         `json:"type,omitempty" yaml:"type,omitempty"`
	Addr      string         `json:"addr,omitempty" yaml:"addr,omitempty"`
	Username  string         `json:"username,omitempty" yaml:"username,omitempty"`
	Password  string         `json:"password,omitempty" yaml:"password,omitempty"`
	KeyPrefix string         `json:"keyPrefix,omitempty" yaml:"keyPrefix,omitempty"`
	TLS       bool           `json:"tls,omitempty" yaml:"tls,omitempty"`
	Window    time.Duration  `json:"window,omitempty" yaml:"window,omitempty"`
	Timeout   time.Duration  `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	FailOpen  bool           `json:"failOpen,omitempty" yaml:"failOpen,omitempty"`
	Extra     map[string]any `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// DistributedBackend is the storage abstraction the cluster-wide
// aggregator talks to. Implementations live in subpackages
// (e.g. pkg/ratelimit/valkey) to keep pkg/ratelimit dependency-free.
//
// Allow MUST be atomic per (key, window): the implementation is
// responsible for making "increment if under limit" indivisible.
// Returning err != nil signals an *operational* failure (network /
// auth / circuit-open); a normal "denied" outcome is (false, nil).
type DistributedBackend interface {
	// Allow attempts to charge one request to key within a sliding
	// window of length `window` against `limit` total. now is supplied
	// by the limiter (production: time.Now; tests: a fake clock) so
	// the same backend behaves deterministically under test.
	Allow(ctx context.Context, key string, limit int, window time.Duration, now time.Time) (bool, error)

	// Close releases any resources. Idempotent.
	Close()
}

// DistributedFactory builds a DistributedBackend from a spec. Backends
// register themselves at init() time via [RegisterBackend], the same
// pattern the cache layer uses.
type DistributedFactory func(spec DistributedSpec) (DistributedBackend, error)

var (
	backendRegMu sync.RWMutex
	backendReg   = map[string]DistributedFactory{}
)

// RegisterBackend installs a factory under typeName. Panics on
// duplicate registration so init-time mistakes surface immediately.
func RegisterBackend(typeName string, f DistributedFactory) {
	backendRegMu.Lock()
	defer backendRegMu.Unlock()
	if _, dup := backendReg[typeName]; dup {
		panic(fmt.Sprintf("ratelimit: backend %q already registered", typeName))
	}
	backendReg[typeName] = f
}

// BuildBackend constructs a DistributedBackend from spec. Returns
// (nil, nil) when spec is nil or has an empty Type — meaning "stay
// per-replica".
func BuildBackend(spec *DistributedSpec) (DistributedBackend, error) {
	if spec == nil || spec.Type == "" {
		return nil, nil
	}
	backendRegMu.RLock()
	f, ok := backendReg[spec.Type]
	backendRegMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("ratelimit: unknown distributed backend %q (registered: %v)", spec.Type, registeredBackends())
	}
	return f(*spec)
}

func registeredBackends() []string {
	backendRegMu.RLock()
	defer backendRegMu.RUnlock()
	out := make([]string, 0, len(backendReg))
	for k := range backendReg {
		out = append(out, k)
	}
	return out
}
