// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package idjag

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

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/pkg/cache"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

const (
	testIssuer   = "https://idp.test/"
	testAudience = "https://lwauth.test/"
	testResource = "https://github-mcp.test/"
)

type fixture struct {
	srv     *httptest.Server
	signKey jwk.Key
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
	_ = priv.Set(jwk.KeyIDKey, "idjag-kid-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256)

	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	_ = pub.Set(jwk.KeyIDKey, "idjag-kid-1")
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)

	set := jwk.NewSet()
	_ = set.AddKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return &fixture{srv: srv, signKey: priv}
}

// assertion describes the claims/headers of an ID-JAG to mint.
type assertion struct {
	typ      string
	issuer   string
	audience string
	resource any
	clientID string
	subject  string
	jti      string
	exp      time.Time
	noExp    bool
}

func (f *fixture) mint(t *testing.T, a assertion) string {
	t.Helper()
	if a.typ == "" {
		a.typ = DefaultTokenType
	}
	if a.issuer == "" {
		a.issuer = testIssuer
	}
	if a.audience == "" {
		a.audience = testAudience
	}
	if a.resource == nil {
		a.resource = testResource
	}
	if a.subject == "" {
		a.subject = "alice@test"
	}
	if a.jti == "" {
		a.jti = uuid.NewString()
	}
	if a.exp.IsZero() {
		a.exp = time.Now().Add(2 * time.Minute)
	}

	b := jwtlib.NewBuilder().
		Issuer(a.issuer).
		Audience([]string{a.audience}).
		Subject(a.subject).
		IssuedAt(time.Now()).
		JwtID(a.jti).
		Claim("resource", a.resource)
	if a.clientID != "" {
		b = b.Claim("client_id", a.clientID)
	}
	if !a.noExp {
		b = b.Expiration(a.exp)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.TypeKey, a.typ)
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.RS256, f.signKey, jws.WithProtectedHeaders(hdrs)))
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
	if cfg.Issuer == "" {
		cfg.Issuer = testIssuer
	}
	if cfg.Audience == "" {
		cfg.Audience = testAudience
	}
	if cfg.ResourceIdentifier == "" {
		cfg.ResourceIdentifier = testResource
	}
	id, err := newIdentifier(context.Background(), "idjag-test", cfg)
	if err != nil {
		t.Fatalf("newIdentifier: %v", err)
	}
	return id
}

func req(token string) *module.Request {
	return &module.Request{
		Headers: map[string][]string{"authorization": {"Bearer " + token}},
	}
}

func TestIDJAG_HappyPath(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})

	got, err := id.Identify(context.Background(), req(f.mint(t, assertion{clientID: "agent-1"})))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.Subject != "alice@test" {
		t.Errorf("Subject = %q, want alice@test", got.Subject)
	}
	if got.Source != "idjag-test" {
		t.Errorf("Source = %q, want idjag-test", got.Source)
	}
	if got.Claims["client_id"] != "agent-1" {
		t.Errorf("client_id = %v, want agent-1", got.Claims["client_id"])
	}
}

func TestIDJAG_NoBearer(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	_, err := id.Identify(context.Background(), &module.Request{})
	if !errors.Is(err, module.ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestIDJAG_WrongTyp(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	_, err := id.Identify(context.Background(), req(f.mint(t, assertion{typ: "JWT"})))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestIDJAG_WrongResource(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	_, err := id.Identify(context.Background(), req(f.mint(t, assertion{resource: "https://other-mcp.test/"})))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestIDJAG_ResourceArrayMatch(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	tok := f.mint(t, assertion{resource: []any{"https://other.test/", testResource}})
	if _, err := id.Identify(context.Background(), req(tok)); err != nil {
		t.Fatalf("Identify: %v", err)
	}
}

func TestIDJAG_WrongIssuer(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	_, err := id.Identify(context.Background(), req(f.mint(t, assertion{issuer: "https://evil.test/"})))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestIDJAG_WrongAudience(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	_, err := id.Identify(context.Background(), req(f.mint(t, assertion{audience: "https://other-as.test/"})))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestIDJAG_Expired(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	tok := f.mint(t, assertion{exp: time.Now().Add(-1 * time.Minute)})
	_, err := id.Identify(context.Background(), req(tok))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestIDJAG_MissingExp(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	_, err := id.Identify(context.Background(), req(f.mint(t, assertion{noExp: true})))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestIDJAG_ClientAllowlist(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{AllowedClients: []string{"agent-1"}})

	if _, err := id.Identify(context.Background(), req(f.mint(t, assertion{clientID: "agent-1"}))); err != nil {
		t.Fatalf("allowed client rejected: %v", err)
	}
	_, err := id.Identify(context.Background(), req(f.mint(t, assertion{clientID: "agent-2"})))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestIDJAG_ReplayRejected(t *testing.T) {
	f := newFixture(t)
	id := newID(t, f, Config{})
	tok := f.mint(t, assertion{jti: "fixed-jti"})

	if _, err := id.Identify(context.Background(), req(tok)); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	_, err := id.Identify(context.Background(), req(tok))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("replay err = %v, want ErrInvalidCredential", err)
	}
}

// TestIDJAG_ReplayRejected_CacheBacked exercises the deps-wired path where jti
// single-use is enforced through the injected cache's Atomic SetNX rather than
// the in-process fallback.
func TestIDJAG_ReplayRejected_CacheBacked(t *testing.T) {
	f := newFixture(t)
	cfg := Config{
		JWKSURL:            f.srv.URL,
		Issuer:             testIssuer,
		Audience:           testAudience,
		ResourceIdentifier: testResource,
	}
	pools, err := cache.BuildPools(nil)
	if err != nil {
		t.Fatalf("BuildPools: %v", err)
	}
	deps := module.Deps{Caches: pools.For("i/idjag/idjag-test", cache.DefaultPool, nil)}
	id, err := newIdentifierWithDeps("idjag-test", cfg, deps)
	if err != nil {
		t.Fatalf("newIdentifierWithDeps: %v", err)
	}
	tok := f.mint(t, assertion{jti: "fixed-jti"})

	if _, err := id.Identify(context.Background(), req(tok)); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	if _, err := id.Identify(context.Background(), req(tok)); !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("replay err = %v, want ErrInvalidCredential", err)
	}
}

func TestIDJAG_Factory_UnknownKey(t *testing.T) {
	_, err := factory("x", map[string]any{"bogus": "1"}, module.Deps{})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestIDJAG_Factory_MissingRequired(t *testing.T) {
	_, err := factory("x", map[string]any{"jwksUrl": "https://idp/jwks"}, module.Deps{})
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestIDJAG_Registered(t *testing.T) {
	found := false
	for _, name := range module.RegisteredTypes(module.KindIdentifier) {
		if name == "idjag" {
			found = true
		}
	}
	if !found {
		t.Fatal("idjag not registered as an identifier")
	}
}
