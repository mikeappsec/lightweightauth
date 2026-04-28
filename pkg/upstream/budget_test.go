package upstream

import (
	"testing"
	"time"
)

func TestRetryBudget_StartsFull(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewRetryBudget(RetryBudgetConfig{Capacity: 3, RefillPerSec: 1, Now: fakeClock(&now)})
	for i := 0; i < 3; i++ {
		if !b.TryAcquire() {
			t.Fatalf("TryAcquire #%d returned false, expected true", i)
		}
	}
	if b.TryAcquire() {
		t.Fatal("TryAcquire on empty bucket returned true")
	}
}

func TestRetryBudget_Refill(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewRetryBudget(RetryBudgetConfig{Capacity: 2, RefillPerSec: 4, Now: fakeClock(&now)})
	// drain
	for i := 0; i < 2; i++ {
		if !b.TryAcquire() {
			t.Fatalf("drain #%d failed", i)
		}
	}
	if b.TryAcquire() {
		t.Fatal("expected empty after drain")
	}
	// 250ms at 4/s = 1 token.
	now = now.Add(250 * time.Millisecond)
	if !b.TryAcquire() {
		t.Fatal("expected one token after 250ms refill")
	}
	if b.TryAcquire() {
		t.Fatal("expected empty after consuming refilled token")
	}
}

func TestRetryBudget_RefillCapped(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewRetryBudget(RetryBudgetConfig{Capacity: 2, RefillPerSec: 100, Now: fakeClock(&now)})
	for i := 0; i < 2; i++ {
		_ = b.TryAcquire()
	}
	now = now.Add(time.Hour)
	if got := b.Tokens(); got > 2 || got < 1.999 {
		t.Fatalf("tokens after long refill = %f, want ~2 (capped)", got)
	}
}

func TestRetryBudget_Defaults(t *testing.T) {
	b := NewRetryBudget(RetryBudgetConfig{})
	if b.cfg.Capacity != 10 || b.cfg.RefillPerSec != 1 {
		t.Fatalf("defaults = %+v", b.cfg)
	}
}
