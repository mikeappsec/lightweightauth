package cache

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// TestNewDecision_RejectsUnknownKeyField is the fail-closed fence on
// cache.key validation. The previous implementation silently dropped any
// value resolveField did not recognise, which meant a typo like
// "pathTemplate" would degrade [sub, method, pathTemplate] to [sub,
// method] and let a single allow decision replay across every path the
// same subject hit with the same method.
func TestNewDecision_RejectsUnknownKeyField(t *testing.T) {
	t.Parallel()
	cases := []string{
		"pathTemplate", // the documented-but-unimplemented typo
		"PATH",         // case-sensitive: only lower-case "path" is valid
		"resource",
		"header:", // empty selector
		"claim:",  // empty selector
		"",
	}
	for _, f := range cases {
		f := f
		t.Run(f, func(t *testing.T) {
			t.Parallel()
			_, err := NewDecision(DecisionOptions{
				Size:        16,
				PositiveTTL: time.Minute,
				KeyFields:   []string{"sub", f},
			})
			if err == nil {
				t.Fatalf("expected error for key field %q, got nil", f)
			}
			if !errors.Is(err, module.ErrConfig) {
				t.Errorf("error not in ErrConfig taxonomy: %v", err)
			}
			if !strings.Contains(err.Error(), "cache.key") {
				t.Errorf("error message should mention cache.key: %v", err)
			}
		})
	}
}

func TestNewDecision_AcceptsAllRecognisedFields(t *testing.T) {
	t.Parallel()
	good := []string{
		"sub", "tenant", "method", "host", "path",
		"header:X-Forwarded-For",
		"claim:roles",
	}
	for _, f := range good {
		f := f
		t.Run(f, func(t *testing.T) {
			t.Parallel()
			d, err := NewDecision(DecisionOptions{
				Size:        16,
				PositiveTTL: time.Minute,
				KeyFields:   []string{f},
			})
			if err != nil {
				t.Fatalf("recognised field %q rejected: %v", f, err)
			}
			if d == nil {
				t.Fatalf("recognised field %q produced nil cache", f)
			}
		})
	}
}

// TestDecision_HMACRejectsTamperedValue verifies that a value injected
// directly into the backend (bypassing the Decision cache's sign path)
// is rejected on read — the HMAC verification fails and the cache
// treats it as a miss, forcing re-evaluation.
func TestDecision_HMACRejectsTamperedValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d, err := NewDecision(DecisionOptions{
		Size:        100,
		PositiveTTL: time.Minute,
		KeyFields:   []string{"sub", "method", "path"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate an attacker injecting a forged allow decision directly
	// into the backend (e.g. via Valkey write access).
	forged := module.Decision{Allow: true, Status: 200, Reason: "forged"}
	raw, _ := json.Marshal(forged)
	_ = d.backend.Set(ctx, "attacker-key", raw, time.Minute)

	// The cache should reject the unsigned value and call fn instead.
	callCount := 0
	dec, cacheHit, err := d.Do(ctx, "attacker-key", func() (*module.Decision, error) {
		callCount++
		return &module.Decision{Allow: false, Status: 403, Reason: "denied by policy"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cacheHit {
		t.Fatal("expected cache miss (tampered value), got hit")
	}
	if dec.Allow {
		t.Fatal("expected deny from authorizer, got allow (tampered value was served)")
	}
	if callCount != 1 {
		t.Fatalf("expected fn to be called once, got %d", callCount)
	}
}

// TestDecision_HMACAcceptsValidSignedValue verifies that legitimately
// cached values are served correctly on subsequent reads.
func TestDecision_HMACAcceptsValidSignedValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d, err := NewDecision(DecisionOptions{
		Size:        100,
		PositiveTTL: time.Minute,
		KeyFields:   []string{"sub"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// First call — populate cache with a signed value.
	_, _, err = d.Do(ctx, "valid-key", func() (*module.Decision, error) {
		return &module.Decision{Allow: true, Status: 200}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Second call — should be a cache hit (valid HMAC).
	dec, cacheHit, err := d.Do(ctx, "valid-key", func() (*module.Decision, error) {
		t.Fatal("fn should not be called on cache hit")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cacheHit {
		t.Fatal("expected cache hit for properly signed value")
	}
	if !dec.Allow {
		t.Fatal("expected allow from cache")
	}
}

// TestDecision_HMACRejectsTruncatedValue verifies that short/truncated
// data in the backend is treated as a miss (not a crash).
func TestDecision_HMACRejectsTruncatedValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	d, err := NewDecision(DecisionOptions{
		Size:        100,
		PositiveTTL: time.Minute,
		KeyFields:   []string{"sub"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Inject a value that's too short to contain payload + HMAC tag.
	_ = d.backend.Set(ctx, "short-key", []byte("short"), time.Minute)

	callCount := 0
	dec, cacheHit, err := d.Do(ctx, "short-key", func() (*module.Decision, error) {
		callCount++
		return &module.Decision{Allow: false, Status: 403}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cacheHit {
		t.Fatal("expected miss for truncated value")
	}
	if dec.Allow {
		t.Fatal("expected deny from authorizer")
	}
	if callCount != 1 {
		t.Fatalf("expected fn called once, got %d", callCount)
	}
}

// TestDecision_CrossInstanceHMACRejection verifies that a value signed
// by one Decision instance (different HMAC key) is rejected by another.
func TestDecision_CrossInstanceHMACRejection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Shared backend (simulates shared Valkey).
	backend, _ := NewLRU(100, 0, &Stats{})

	d1, err := NewDecision(DecisionOptions{
		Size:        100,
		PositiveTTL: time.Minute,
		KeyFields:   []string{"sub"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Cache a value via d1.
	_, _, err = d1.Do(ctx, "shared-key", func() (*module.Decision, error) {
		return &module.Decision{Allow: true, Status: 200}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read the raw signed value from d1's backend and inject into a
	// shared backend that d2 will use.
	raw, ok, _ := d1.backend.Get(ctx, "shared-key")
	if !ok {
		t.Fatal("d1 did not cache the value")
	}
	_ = backend.Set(ctx, "shared-key", raw, time.Minute)

	// Create d2 with a DIFFERENT hmac key (different instance).
	d2, err := NewDecision(DecisionOptions{
		Size:        100,
		PositiveTTL: time.Minute,
		KeyFields:   []string{"sub"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Replace d2's backend with the shared one containing d1's signed value.
	d2.backend = backend

	// d2 should reject d1's signed value (different HMAC key).
	dec, cacheHit, err := d2.Do(ctx, "shared-key", func() (*module.Decision, error) {
		return &module.Decision{Allow: false, Status: 403}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cacheHit {
		t.Fatal("expected miss — cross-instance HMAC should not validate")
	}
	if dec.Allow {
		t.Fatal("expected deny from authorizer (cross-instance value should be rejected)")
	}
}
