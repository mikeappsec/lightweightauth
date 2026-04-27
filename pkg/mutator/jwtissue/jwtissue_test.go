package jwtissue

import (
	"context"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yourorg/lightweightauth/pkg/module"
)

func TestJWTIssue_HS256_Roundtrip(t *testing.T) {
	t.Parallel()
	m, err := factory("upstream", map[string]any{
		"issuer":     "lwauth",
		"audience":   "api.internal",
		"algorithm":  "HS256",
		"key":        "hex:" + strings.Repeat("ab", 32),
		"copyClaims": []any{"email", "roles"},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	d := &module.Decision{}
	id := &module.Identity{
		Subject: "alice",
		Claims: map[string]any{
			"email": "alice@example.com",
			"roles": []any{"admin"},
		},
	}
	if err := m.Mutate(context.Background(), &module.Request{}, id, d); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	auth := d.UpstreamHeaders["Authorization"]
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("Authorization = %q, want Bearer prefix", auth)
	}
	raw := strings.TrimPrefix(auth, "Bearer ")

	// Verify with the same key.
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = 0xab
	}
	verifyKey, _ := jwk.FromRaw(keyBytes)
	tok, err := jwtlib.ParseString(raw,
		jwtlib.WithKey(jwa.HS256, verifyKey),
		jwtlib.WithIssuer("lwauth"),
		jwtlib.WithAudience("api.internal"),
		jwtlib.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok.Subject() != "alice" {
		t.Errorf("sub = %q", tok.Subject())
	}
	cm, _ := tok.AsMap(context.Background())
	if cm["email"] != "alice@example.com" {
		t.Errorf("email claim = %v", cm["email"])
	}
}

func TestJWTIssue_NoIdentityNoOp(t *testing.T) {
	t.Parallel()
	m, _ := factory("u", map[string]any{
		"issuer":    "lwauth",
		"audience":  "x",
		"algorithm": "HS256",
		"key":       "secret-secret-secret",
	})
	d := &module.Decision{}
	if err := m.Mutate(context.Background(), &module.Request{}, nil, d); err != nil {
		t.Fatalf("Mutate: %v", err)
	}
	if len(d.UpstreamHeaders) != 0 {
		t.Errorf("headers = %v, want empty", d.UpstreamHeaders)
	}
}
