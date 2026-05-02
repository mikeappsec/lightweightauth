// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestMemoryStore_SaveLoadClear(t *testing.T) {
	t.Parallel()
	ms := NewMemoryStore(MemoryStoreConfig{MaxAge: time.Hour})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	if err := ms.Save(w, r, &Session{Subject: "alice"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if ms.Len() != 1 {
		t.Fatalf("len = %d, want 1", ms.Len())
	}

	// Replay cookie back as the next request.
	r2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		r2.AddCookie(c)
	}
	got, err := ms.Load(r2)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil || got.Subject != "alice" {
		t.Fatalf("Load = %+v", got)
	}

	// Clear removes server-side + sends expiring cookie.
	w2 := httptest.NewRecorder()
	if err := ms.Clear(w2, r2); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if ms.Len() != 0 {
		t.Errorf("len after clear = %d", ms.Len())
	}
}

func TestMemoryStore_SIDReuse(t *testing.T) {
	t.Parallel()
	ms := NewMemoryStore(MemoryStoreConfig{MaxAge: time.Hour})

	// First Save mints a SID.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/", nil)
	_ = ms.Save(w1, r1, &Session{Subject: "alice"})
	cookies := w1.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	sid1 := cookies[0].Value

	// Second Save with the cookie present should reuse the SID.
	r2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		r2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	_ = ms.Save(w2, r2, &Session{Subject: "alice", AccessToken: "rotated"})
	sid2 := w2.Result().Cookies()[0].Value
	if sid1 != sid2 {
		t.Errorf("SID rotated: %q -> %q (want stable for refresh continuity)", sid1, sid2)
	}
	if ms.Len() != 1 {
		t.Errorf("entries = %d, want 1 (reuse)", ms.Len())
	}
}

func TestMemoryStore_ExpiredOnLoad(t *testing.T) {
	t.Parallel()
	ms := NewMemoryStore(MemoryStoreConfig{MaxAge: time.Hour})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	_ = ms.Save(w, r, &Session{Subject: "alice", Expiry: time.Now().Add(-time.Minute)})

	r2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		r2.AddCookie(c)
	}
	got, _ := ms.Load(r2)
	if got != nil {
		t.Errorf("expired Load = %+v, want nil", got)
	}
	if ms.Len() != 0 {
		t.Errorf("expired not pruned, len=%d", ms.Len())
	}
}
