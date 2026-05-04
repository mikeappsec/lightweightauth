// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package revocation_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/mikeappsec/lightweightauth/pkg/revocation"
)

// mockStore is an in-memory Store for testing.
type mockStore struct {
	data   map[string]bool
	calls  atomic.Int64
	errKey string // if set, return error for this key
}

func (m *mockStore) Add(_ context.Context, e revocation.Entry) error {
	m.data[e.Key] = true
	return nil
}

func (m *mockStore) Exists(_ context.Context, key string) (bool, error) {
	m.calls.Add(1)
	if m.errKey != "" && key == m.errKey {
		return false, errors.New("store error")
	}
	return m.data[key], nil
}

func (m *mockStore) Remove(_ context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockStore) List(_ context.Context, _ string, _ int, _ string) ([]revocation.Entry, string, error) {
	return nil, "", nil
}

func (m *mockStore) Close() error { return nil }

func TestParallelChecker_NoKeys(t *testing.T) {
	store := &mockStore{data: map[string]bool{}}
	pc := revocation.NewParallelChecker(store)
	revoked, err := pc.ExistsAny(context.Background(), nil)
	if err != nil || revoked {
		t.Fatalf("expected (false, nil), got (%v, %v)", revoked, err)
	}
}

func TestParallelChecker_SingleKey_NotRevoked(t *testing.T) {
	store := &mockStore{data: map[string]bool{}}
	pc := revocation.NewParallelChecker(store)
	revoked, err := pc.ExistsAny(context.Background(), []string{"jti:123"})
	if err != nil || revoked {
		t.Fatalf("expected (false, nil), got (%v, %v)", revoked, err)
	}
	if got := store.calls.Load(); got != 1 {
		t.Fatalf("expected 1 call, got %d", got)
	}
}

func TestParallelChecker_SingleKey_Revoked(t *testing.T) {
	store := &mockStore{data: map[string]bool{"jti:abc": true}}
	pc := revocation.NewParallelChecker(store)
	revoked, err := pc.ExistsAny(context.Background(), []string{"jti:abc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked {
		t.Fatal("expected revoked=true")
	}
}

func TestParallelChecker_MultipleKeys_OneRevoked(t *testing.T) {
	store := &mockStore{data: map[string]bool{"sub:alice": true}}
	pc := revocation.NewParallelChecker(store)
	keys := []string{"jti:123", "sub:alice"}
	revoked, err := pc.ExistsAny(context.Background(), keys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoked {
		t.Fatal("expected revoked=true")
	}
}

func TestParallelChecker_MultipleKeys_NoneRevoked(t *testing.T) {
	store := &mockStore{data: map[string]bool{}}
	pc := revocation.NewParallelChecker(store)
	keys := []string{"jti:1", "sub:bob", "aud:svc"}
	revoked, err := pc.ExistsAny(context.Background(), keys)
	if err != nil || revoked {
		t.Fatalf("expected (false, nil), got (%v, %v)", revoked, err)
	}
	if got := store.calls.Load(); got != 3 {
		t.Fatalf("expected 3 calls, got %d", got)
	}
}

func TestParallelChecker_Error(t *testing.T) {
	store := &mockStore{data: map[string]bool{}, errKey: "bad-key"}
	pc := revocation.NewParallelChecker(store)
	keys := []string{"good-key", "bad-key"}
	_, err := pc.ExistsAny(context.Background(), keys)
	if err == nil {
		t.Fatal("expected error")
	}
}
