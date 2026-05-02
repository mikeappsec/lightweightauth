// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/internal/server"

	// Register the built-in modules so config.Compile can find them.
	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"
)

// startJWKS starts an in-memory JWKS endpoint and returns the URL plus a
// signing key for minting tokens.
func startJWKS(t *testing.T) (jwksURL string, signKey jwk.Key) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	priv, _ := jwk.FromRaw(rsaKey)
	_ = priv.Set(jwk.KeyIDKey, "kid-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256)
	pub, _ := jwk.PublicKeyOf(priv)
	_ = pub.Set(jwk.KeyIDKey, "kid-1")
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, priv
}

// mintToken mints an RS256 JWT signed with k.
func mintToken(t *testing.T, k jwk.Key, mut func(*jwtlib.Builder) *jwtlib.Builder) string {
	t.Helper()
	b := jwtlib.NewBuilder().
		Issuer("https://idp.test").
		Subject("alice").
		Audience([]string{"api://my-svc"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		Claim("roles", []string{"admin"})
	if mut != nil {
		b = mut(b)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.RS256, k))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// bootServer compiles a JWT+RBAC AuthConfig pointing at jwksURL and
// returns an httptest.Server fronting the lwauth HTTP handler.
func bootServer(t *testing.T, jwksURL string) *httptest.Server {
	t.Helper()
	ac := &config.AuthConfig{
		Identifier: config.IdentifierFirstMatch,
		Identifiers: []config.ModuleSpec{{
			Name: "corp-jwt",
			Type: "jwt",
			Config: map[string]any{
				"jwksUrl":   jwksURL,
				"issuerUrl": "https://idp.test",
				"audiences": []any{"api://my-svc"},
			},
		}},
		Authorizers: []config.ModuleSpec{{
			Name: "rbac",
			Type: "rbac",
			Config: map[string]any{
				"rolesFrom": "claim:roles",
				"allow":     []any{"admin", "editor"},
			},
		}},
	}
	eng, err := config.Compile(ac)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	holder := server.NewEngineHolder(eng)
	httpSrv := httptest.NewServer(server.NewHTTPHandler(holder))
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func authorize(t *testing.T, base, token string) (status int, body map[string]any) {
	t.Helper()
	body = map[string]any{}
	in := map[string]any{
		"method":  "GET",
		"path":    "/things",
		"headers": map[string][]string{},
	}
	if token != "" {
		in["headers"] = map[string][]string{"Authorization": {"Bearer " + token}}
	}
	buf, _ := json.Marshal(in)
	resp, err := http.Post(base+"/v1/authorize", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestHTTP_JWT_AllowsAdmin(t *testing.T) {
	t.Parallel()
	jwksURL, key := startJWKS(t)
	srv := bootServer(t, jwksURL)

	tok := mintToken(t, key, nil)
	status, body := authorize(t, srv.URL, tok)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", status, body)
	}
	data, _ := body["data"].(map[string]any)
	if data == nil || data["allow"] != true {
		t.Errorf("body = %v, want allow=true", body)
	}
}

func TestHTTP_JWT_DeniesViewer(t *testing.T) {
	t.Parallel()
	jwksURL, key := startJWKS(t)
	srv := bootServer(t, jwksURL)

	tok := mintToken(t, key, func(b *jwtlib.Builder) *jwtlib.Builder {
		return b.Claim("roles", []string{"viewer"})
	})
	status, body := authorize(t, srv.URL, tok)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", status, body)
	}
	data, _ := body["data"].(map[string]any)
	if data == nil || data["allow"] != false {
		t.Errorf("allow = %v, want false", body)
	}
}

func TestHTTP_JWT_RejectsExpired(t *testing.T) {
	t.Parallel()
	jwksURL, key := startJWKS(t)
	srv := bootServer(t, jwksURL)

	tok := mintToken(t, key, func(b *jwtlib.Builder) *jwtlib.Builder {
		return b.IssuedAt(time.Now().Add(-2 * time.Hour)).
			Expiration(time.Now().Add(-time.Hour))
	})
	status, _ := authorize(t, srv.URL, tok)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestHTTP_JWT_RejectsMissingHeader(t *testing.T) {
	t.Parallel()
	jwksURL, _ := startJWKS(t)
	srv := bootServer(t, jwksURL)

	status, _ := authorize(t, srv.URL, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

// silence unused import warnings from build tags / linters
var _ = context.Background
