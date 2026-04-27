package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/yourorg/lightweightauth/pkg/module"
)

// Decision is the opt-in cache that wraps the authorize step. It coalesces
// concurrent misses with singleflight, applies a positive TTL on allow and
// a negative TTL on deny, and is keyed by the (tenant, subject, request
// fields) tuple operators declare in their AuthConfig.cache.key (DESIGN.md
// §5).
//
// Upstream errors are NEVER cached: a transient outage of an external
// authorizer (OPA bundle, OpenFGA, introspection) must not freeze a deny
// in the cache.
type Decision struct {
	backend     Backend
	positiveTTL time.Duration
	negativeTTL time.Duration
	keyFields   []string
	stats       *Stats
	sf          singleflight.Group
}

// DecisionOptions parameterises a decision cache. A nil DecisionOptions or
// PositiveTTL == 0 means "disabled" — callers should branch on
// (*Decision)(nil).
type DecisionOptions struct {
	Size        int
	PositiveTTL time.Duration
	NegativeTTL time.Duration
	// KeyFields list which Request / Identity fields contribute to the
	// cache key. Recognised values:
	//   "sub", "tenant", "method", "host", "path",
	//   "header:<Name>", "claim:<Name>"
	// Unknown values are skipped so future fields don't break old configs.
	KeyFields []string
}

// NewDecision returns a Decision cache or nil if disabled.
func NewDecision(o DecisionOptions) (*Decision, error) {
	if o.PositiveTTL <= 0 {
		return nil, nil
	}
	if o.Size <= 0 {
		o.Size = 10_000
	}
	if o.NegativeTTL <= 0 {
		o.NegativeTTL = 5 * time.Second
	}
	stats := &Stats{}
	backend, err := NewLRU(o.Size, 0, stats)
	if err != nil {
		return nil, fmt.Errorf("decision cache: %w", err)
	}
	keys := append([]string(nil), o.KeyFields...)
	sort.Strings(keys) // deterministic key ordering
	return &Decision{
		backend:     backend,
		positiveTTL: o.PositiveTTL,
		negativeTTL: o.NegativeTTL,
		keyFields:   keys,
		stats:       stats,
	}, nil
}

// Stats returns the live counter struct (hits/misses/evictions). The
// Decision cache emits a singleflight coalesce as a hit.
func (d *Decision) Stats() *Stats { return d.stats }

// Key computes the cache key for this request+identity, returning ""
// when the cache should be skipped (e.g. no identity yet, or the configured
// fields produced an empty payload).
func (d *Decision) Key(r *module.Request, id *module.Identity) string {
	if d == nil || len(d.keyFields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(d.keyFields))
	for _, f := range d.keyFields {
		v := resolveField(f, r, id)
		if v == "" {
			continue
		}
		parts = append(parts, f+"="+v)
	}
	if len(parts) == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:16])
}

// Do returns a Decision either from the cache or by calling fn (singleflight
// coalesced). fn must return an error in the upstream/config taxonomy; the
// result is cached for positiveTTL on allow and negativeTTL on a clean deny.
// Errors are surfaced to the caller and never cached.
func (d *Decision) Do(ctx context.Context, key string, fn func() (*module.Decision, error)) (*module.Decision, bool, error) {
	if d == nil || key == "" {
		dec, err := fn()
		return dec, false, err
	}
	if raw, ok, _ := d.backend.Get(ctx, key); ok {
		var dec module.Decision
		if err := json.Unmarshal(raw, &dec); err == nil {
			return &dec, true, nil
		}
		// fall through on decode error
	}
	v, err, _ := d.sf.Do(key, func() (any, error) {
		dec, err := fn()
		if err != nil {
			return nil, err
		}
		// Never cache upstream/transient errors; we already returned them
		// above. Cache the decision the authorizer produced.
		raw, _ := json.Marshal(dec)
		ttl := d.positiveTTL
		if !dec.Allow {
			ttl = d.negativeTTL
		}
		_ = d.backend.Set(ctx, key, raw, ttl)
		return dec, nil
	})
	if err != nil {
		// Upstream errors propagate; do not negative-cache them.
		if errors.Is(err, module.ErrUpstream) {
			return nil, false, err
		}
		return nil, false, err
	}
	return v.(*module.Decision), false, nil
}

func resolveField(f string, r *module.Request, id *module.Identity) string {
	switch {
	case f == "sub":
		if id != nil {
			return id.Subject
		}
	case f == "tenant":
		return r.TenantID
	case f == "method":
		return r.Method
	case f == "host":
		return r.Host
	case f == "path":
		return r.Path
	case strings.HasPrefix(f, "header:"):
		return r.Header(strings.TrimPrefix(f, "header:"))
	case strings.HasPrefix(f, "claim:"):
		if id == nil || id.Claims == nil {
			return ""
		}
		v, ok := id.Claims[strings.TrimPrefix(f, "claim:")]
		if !ok {
			return ""
		}
		switch x := v.(type) {
		case string:
			return x
		case fmt.Stringer:
			return x.String()
		default:
			b, _ := json.Marshal(v)
			return string(b)
		}
	}
	return ""
}
