package keyrotation

import (
	"testing"
	"time"
)

func TestKeyMeta_State(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		meta KeyMeta
		want KeyState
	}{
		{
			name: "no bounds → active",
			meta: KeyMeta{KID: "k1"},
			want: KeyStateActive,
		},
		{
			name: "before notBefore → pending",
			meta: KeyMeta{KID: "k2", NotBefore: now.Add(time.Hour)},
			want: KeyStatePending,
		},
		{
			name: "after notAfter within grace → retiring",
			meta: KeyMeta{KID: "k3", NotAfter: now.Add(-time.Minute)},
			want: KeyStateRetiring,
		},
		{
			name: "after notAfter + grace → retired",
			meta: KeyMeta{KID: "k4", NotAfter: now.Add(-10 * time.Minute), GracePeriod: 5 * time.Minute},
			want: KeyStateRetired,
		},
		{
			name: "within window → active",
			meta: KeyMeta{KID: "k5", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
			want: KeyStateActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.meta.State(now); got != tt.want {
				t.Fatalf("State() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKeyMeta_IsValid(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	if !(KeyMeta{KID: "a"}).IsValid(now) {
		t.Fatal("no-bounds key should be valid")
	}
	if !(KeyMeta{KID: "b", NotAfter: now.Add(-time.Minute)}).IsValid(now) {
		t.Fatal("retiring key should still be valid")
	}
	if (KeyMeta{KID: "c", NotAfter: now.Add(-10 * time.Minute), GracePeriod: 5 * time.Minute}).IsValid(now) {
		t.Fatal("retired key should not be valid")
	}
	if (KeyMeta{KID: "d", NotBefore: now.Add(time.Hour)}).IsValid(now) {
		t.Fatal("pending key should not be valid")
	}
}

func TestKeySet_PutGetPrune(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ks := NewKeySet[[]byte](func() time.Time { return now })

	// Add an active key.
	ks.Put(KeyMeta{KID: "hmac-1", NotBefore: now.Add(-time.Hour)}, []byte("secret1"))
	// Add a retired key.
	ks.Put(KeyMeta{KID: "hmac-old", NotAfter: now.Add(-10 * time.Minute), GracePeriod: 5 * time.Minute}, []byte("old"))

	// Get active key.
	v, ok := ks.Get("hmac-1")
	if !ok || string(v) != "secret1" {
		t.Fatal("should get active key")
	}

	// Get retired key should fail.
	_, ok = ks.Get("hmac-old")
	if ok {
		t.Fatal("should not get retired key")
	}

	// Prune should remove the retired key.
	pruned := ks.Prune()
	if len(pruned) != 1 || pruned[0] != "hmac-old" {
		t.Fatalf("expected [hmac-old], got %v", pruned)
	}
	if ks.Len() != 1 {
		t.Fatalf("expected 1 key remaining, got %d", ks.Len())
	}
}

func TestKeySet_ActiveAndRetiring(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ks := NewKeySet[string](func() time.Time { return now })

	ks.Put(KeyMeta{KID: "new"}, "new-secret")
	ks.Put(KeyMeta{KID: "old", NotAfter: now.Add(-time.Second)}, "old-secret")

	active := ks.ActiveKIDs()
	if len(active) != 1 || active[0] != "new" {
		t.Fatalf("active = %v, want [new]", active)
	}

	retiring := ks.RetiringKIDs()
	if len(retiring) != 1 || retiring[0] != "old" {
		t.Fatalf("retiring = %v, want [old]", retiring)
	}

	// Retiring key should still be fetchable.
	v, ok := ks.Get("old")
	if !ok || v != "old-secret" {
		t.Fatal("retiring key should still be Get-able")
	}
}
