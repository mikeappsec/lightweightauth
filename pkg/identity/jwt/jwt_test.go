package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// fixture spins up an in-memory JWKS endpoint and returns a signer that
// mints tokens against it.
type fixture struct {
	srv     *httptest.Server
	signKey jwk.Key
	pubSet  jwk.Set
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	priv, err := jwk.FromRaw(rsaKey)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = priv.Set(jwk.KeyIDKey, "test-kid-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256)

	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	_ = pub.Set(jwk.KeyIDKey, "test-kid-1")
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)

	set := jwk.NewSet()
	_ = set.AddKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)

	return &fixture{srv: srv, signKey: priv, pubSet: set}
}

func (f *fixture) mint(t *testing.T, build func(*jwtlib.Builder) *jwtlib.Builder) string {
	t.Helper()
	b := jwtlib.NewBuilder().
		Issuer("https://idp.test").
		Subject("alice").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		Audience([]string{"api://my-svc"})
	if build != nil {
		b = build(b)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.RS256, f.signKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

func newID(t *testing.T, f *fixture, cfg Config) *identifier {
	t.Helper()
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = f.srv.URL
	}
	id, err := newIdentifier(context.Background(), "jwt-test", cfg)
	if err != nil {
		t.Fatalf("newIdentifier: %v", err)
	}
	return id
}

func req(token string) *module.Request {
	return &module.Request{
		Headers: map[string][]string{"Authorization": {"Bearer " + token}},
	}
}

func TestJWT_HappyPath(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := newID(t, f, Config{
		IssuerURL: "https://idp.test",
		Audiences: []string{"api://my-svc"},
	})

	got, err := id.Identify(context.Background(), req(f.mint(t, nil)))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", got.Subject)
	}
	if got.Source != "jwt-test" {
		t.Errorf("Source = %q, want jwt-test", got.Source)
	}
	if _, ok := got.Claims["iss"]; !ok {
		t.Error("Claims should contain iss")
	}
}

func TestJWT_NoMatchOnMissingHeader(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := newID(t, f, Config{})

	_, err := id.Identify(context.Background(), &module.Request{Headers: map[string][]string{}})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestJWT_NoMatchOnWrongScheme(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := newID(t, f, Config{})
	r := &module.Request{Headers: map[string][]string{"Authorization": {"Basic abc"}}}

	_, err := id.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestJWT_RejectsExpired(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := newID(t, f, Config{IssuerURL: "https://idp.test"})

	tok := f.mint(t, func(b *jwtlib.Builder) *jwtlib.Builder {
		return b.IssuedAt(time.Now().Add(-2 * time.Hour)).
			Expiration(time.Now().Add(-1 * time.Hour))
	})
	_, err := id.Identify(context.Background(), req(tok))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestJWT_RejectsWrongIssuer(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := newID(t, f, Config{IssuerURL: "https://idp.test"})

	tok := f.mint(t, func(b *jwtlib.Builder) *jwtlib.Builder {
		return b.Issuer("https://attacker.example")
	})
	_, err := id.Identify(context.Background(), req(tok))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestJWT_RejectsWrongAudience(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := newID(t, f, Config{
		IssuerURL: "https://idp.test",
		Audiences: []string{"api://my-svc"},
	})

	tok := f.mint(t, func(b *jwtlib.Builder) *jwtlib.Builder {
		return b.Audience([]string{"api://other"})
	})
	_, err := id.Identify(context.Background(), req(tok))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestJWT_RejectsBadSignature(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	id := newID(t, f, Config{})

	// Mint with a *different* key; the verifier won't have it in its set.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := jwk.FromRaw(otherKey)
	_ = other.Set(jwk.KeyIDKey, "rogue")
	_ = other.Set(jwk.AlgorithmKey, jwa.RS256)

	tok, _ := jwtlib.NewBuilder().
		Subject("alice").
		Expiration(time.Now().Add(time.Minute)).
		Build()
	signed, _ := jwtlib.Sign(tok, jwtlib.WithKey(jwa.RS256, other))

	_, err := id.Identify(context.Background(), req(string(signed)))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestJWT_FactoryRequiresJWKSURL(t *testing.T) {
	t.Parallel()
	_, err := factory("x", map[string]any{})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}
