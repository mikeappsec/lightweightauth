// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"testing"
	"time"
)

func TestFromMap_Empty(t *testing.T) {
	got, err := FromMap(nil)
	if err != nil {
		t.Fatalf("FromMap(nil): %v", err)
	}
	if got.MaxRetries != 0 || got.BackoffBase != 0 {
		t.Fatalf("expected zero-retry default, got %+v", got)
	}

	got, err = FromMap(map[string]any{"unrelated": 42})
	if err != nil {
		t.Fatalf("FromMap with no resilience key: %v", err)
	}
	if got.MaxRetries != 0 {
		t.Fatalf("expected zero, got %+v", got)
	}
}

func TestFromMap_Full(t *testing.T) {
	raw := map[string]any{
		"resilience": map[string]any{
			"breaker": map[string]any{
				"failureThreshold":  3,
				"coolDown":          "5s",
				"halfOpenSuccesses": 2,
			},
			"retries": map[string]any{
				"max":                2,
				"backoffBase":        "100ms",
				"backoffMax":         "2s",
				"budgetCapacity":     20.0,
				"budgetRefillPerSec": 5.0,
			},
		},
	}
	got, err := FromMap(raw)
	if err != nil {
		t.Fatalf("FromMap: %v", err)
	}
	if got.Breaker.FailureThreshold != 3 || got.Breaker.CoolDown != 5*time.Second || got.Breaker.HalfOpenSuccesses != 2 {
		t.Fatalf("breaker = %+v", got.Breaker)
	}
	if got.MaxRetries != 2 || got.BackoffBase != 100*time.Millisecond || got.BackoffMax != 2*time.Second {
		t.Fatalf("retries = %+v", got)
	}
	if got.Budget.Capacity != 20 || got.Budget.RefillPerSec != 5 {
		t.Fatalf("budget = %+v", got.Budget)
	}
}

func TestFromMap_BadDuration(t *testing.T) {
	_, err := FromMap(map[string]any{
		"resilience": map[string]any{
			"breaker": map[string]any{"coolDown": "not-a-duration"},
		},
	})
	if err == nil {
		t.Fatal("expected error for bad coolDown")
	}
}

func TestFromMap_FloatIntsFromYAML(t *testing.T) {
	// sigs.k8s.io/yaml decodes JSON numbers as float64; ensure both paths work.
	raw := map[string]any{
		"resilience": map[string]any{
			"retries": map[string]any{
				"max":                float64(4),
				"budgetCapacity":     50,
				"budgetRefillPerSec": 2,
			},
		},
	}
	got, err := FromMap(raw)
	if err != nil {
		t.Fatalf("FromMap: %v", err)
	}
	if got.MaxRetries != 4 || got.Budget.Capacity != 50 || got.Budget.RefillPerSec != 2 {
		t.Fatalf("got = %+v", got)
	}
}
