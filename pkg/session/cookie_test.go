package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *CookieStore {
	t.Helper()
	insecure := false
	s, err := NewCookieStore(CookieStoreConfig{
		Secret:   []byte("0123456789abcdef0123456789abcdef"),
		MaxAge:   time.Hour,
		Secure:   &insecure, // tests run over http
		SameSite: http.SameSiteLaxMode,
	})
	if err != nil {
		t.Fatalf("NewCookieStore: %v", err)
	}
	return s
}

func TestCookieStore_RoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	// Save.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	in := &Session{
		Subject: "alice",
		Email:   "alice@example.com",
		Claims:  map[string]any{"groups": []any{"admin"}},
		IDToken: "eyJ...",
	}
	if err := s.Save(w, r, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	resp := w.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	// Carry the Set-Cookie back as a Cookie on a new request.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, ck := range resp.Cookies() {
		r2.AddCookie(ck)
	}
	out, err := s.Load(r2)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out == nil {
		t.Fatal("Load returned nil session")
	}
	if out.Subject != "alice" || out.Email != "alice@example.com" {
		t.Errorf("session subject/email mismatch: %+v", out)
	}
	if out.IssuedAt.IsZero() || out.Expiry.IsZero() {
		t.Errorf("Save did not stamp issuedAt/expiry: %+v", out)
	}
}

func TestCookieStore_TamperRejected(t *testing.T) {
	t.Parallel()
	s := newStore(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := s.Save(w, r, &Session{Subject: "alice"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	ck := w.Result().Cookies()[0]
	// Flip a byte in the middle of the value.
	mid := len(ck.Value) / 2
	bad := ck.Value[:mid] + string(rune(ck.Value[mid])+1) + ck.Value[mid+1:]
	bad = strings.ReplaceAll(bad, "/", "_") // keep base64url-safe

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: s.Name(), Value: bad})
	out, err := s.Load(r2)
	if err == nil {
		t.Fatalf("expected error on tamper, got %+v", out)
	}
	if out != nil {
		t.Errorf("expected nil session on tamper, got %+v", out)
	}
}

func TestCookieStore_Absent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	out, err := s.Load(r)
	if err != nil || out != nil {
		t.Errorf("Load with no cookie = (%v, %v); want (nil, nil)", out, err)
	}
}

func TestCookieStore_Clear(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := s.Clear(w, r); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	cks := w.Result().Cookies()
	if len(cks) != 1 || cks[0].MaxAge >= 0 {
		t.Errorf("Clear did not emit deletion cookie: %+v", cks)
	}
}

func TestCookieStore_ExpiredSessionLoadsNil(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	expired := &Session{
		Subject:  "alice",
		IssuedAt: time.Now().Add(-2 * time.Hour),
		Expiry:   time.Now().Add(-time.Hour),
	}
	if err := s.Save(w, r, expired); err != nil {
		t.Fatalf("Save: %v", err)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, ck := range w.Result().Cookies() {
		r2.AddCookie(ck)
	}
	out, err := s.Load(r2)
	if err != nil || out != nil {
		t.Errorf("expired session should load as nil; got (%v, %v)", out, err)
	}
}

func TestCookieStore_RejectsShortSecret(t *testing.T) {
	t.Parallel()
	if _, err := NewCookieStore(CookieStoreConfig{Secret: []byte("short")}); err == nil {
		t.Fatal("expected error for short secret")
	}
}
