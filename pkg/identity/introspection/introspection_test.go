package introspection

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func mkServer(t *testing.T, hits *atomic.Int32, claims map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	}))
}

func mkIdentifier(t *testing.T, url string) *identifier {
	t.Helper()
	a, err := factory("introspect", map[string]any{
		"url":          url,
		"clientId":     "lwauth",
		"clientSecret": "s",
		"maxCacheTtl":  "5s",
		"negativeTtl":  "1s",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return a.(*identifier)
}

func req(token string) *module.Request {
	return &module.Request{Headers: map[string][]string{"Authorization": {"Bearer " + token}}}
}

func TestIntrospection_ActiveTokenIdentifies(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkServer(t, hits, map[string]any{
		"active": true, "sub": "alice", "exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	got, err := id.Identify(t.Context(), req("tok"))
	if err != nil || got == nil || got.Subject != "alice" {
		t.Fatalf("got (%+v, %v), want subject=alice", got, err)
	}
}

func TestIntrospection_PositiveCacheHits(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkServer(t, hits, map[string]any{
		"active": true, "sub": "alice", "exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	for i := 0; i < 5; i++ {
		if _, err := id.Identify(t.Context(), req("tok")); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("upstream hits = %d, want 1 (cache should absorb the rest)", h)
	}
}

func TestIntrospection_NegativeCacheRemembersInactive(t *testing.T) {
	t.Parallel()
	hits := &atomic.Int32{}
	srv := mkServer(t, hits, map[string]any{"active": false})
	defer srv.Close()
	id := mkIdentifier(t, srv.URL)

	for i := 0; i < 3; i++ {
		_, err := id.Identify(t.Context(), req("tok"))
		if !errors.Is(err, module.ErrInvalidCredential) {
			t.Fatalf("iter %d: err = %v, want ErrInvalidCredential", i, err)
		}
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("upstream hits = %d, want 1", h)
	}
}

func TestIntrospection_NoBearerNoMatch(t *testing.T) {
	t.Parallel()
	id := mkIdentifier(t, "http://unused")
	_, err := id.Identify(t.Context(), &module.Request{})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Errorf("err = %v, want ErrNoMatch", err)
	}
}
