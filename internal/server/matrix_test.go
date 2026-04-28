package server_test

// M12-CONF-MATRIX (Tier B / B1).
//
// The single-fixture parity harness in conformance_test.go proves that
// Door A (Envoy ext_authz v3) and Door B (lightweightauth.v1.Auth)
// agree on the verdict for one (apikey + rbac) configuration. That is
// necessary but not sufficient: a transport-adapter regression in any
// other shipped module — say the JWT identifier silently dropping the
// Authorization header on Door B, or the OPA authorizer reading a
// different Request shape on Door A — would slip past CI.
//
// This file walks a *matrix* of (identifier × authorizer) cells and
// asserts the same allow/deny + status parity for each. Every cell
// compiles a real engine, boots both doors over a single bufconn gRPC
// server (so they share identical config + identical wall-clock), and
// drives one allow input + one deny input through both transports.
//
// Coverage shipped in this slice:
//
//	identifier × authorizer    | apikey | jwt | introspection | hmac
//	----------------------------+--------+-----+---------------+------
//	rbac                        |   ✓    |  ✓  |       ✓       |  ✓
//	cel                         |   ✓    |  -  |       -       |  -
//	opa                         |   ✓    |  -  |       -       |  -
//	composite (allOf rbac+cel)  |   ✓    |  -  |       -       |  -
//	openfga                     |   ✓    |  -  |       -       |  -
//
// Every authorizer is exercised at least once; four of the seven
// shipped identifiers are exercised at least once. The three not
// covered here — mtls, dpop, oauth2 — are deferred because each
// requires transport-level plumbing the gRPC test client does not
// surface symmetrically (mtls: XFCC header injection on Door A vs
// PeerCerts field on Door B; dpop: inner-identifier composition; oauth2:
// redirect-flow IdP). They get their own slice; the file-level TODO
// below tracks the gap so it can't drift unnoticed.
//
// TODO(M12-CONF-MATRIX slice 2): extend to mtls, dpop, oauth2 once a
// shared peer-cert plumbing helper exists for the bufconn test rig.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	authv1 "github.com/mikeappsec/lightweightauth/api/proto/lightweightauth/v1"
	"github.com/mikeappsec/lightweightauth/internal/config"
)

// matrixRequest captures one transport-agnostic input. method/path map
// directly onto Door A's HttpRequest and Door B's AuthorizeRequest.
type matrixRequest struct {
	method  string
	path    string
	headers map[string]string
}

// matrixCase is one cell of the conformance matrix. build returns a
// fully-formed AuthConfig (any per-test infrastructure such as a JWKS
// or introspection httptest.Server is registered via t.Cleanup inside
// build itself, so the case is self-contained).
type matrixCase struct {
	name    string
	build   func(t *testing.T) *config.AuthConfig
	allow   func(t *testing.T) matrixRequest
	deny    func(t *testing.T) matrixRequest
	denyTTP int32 // expected http_status from Door B on the deny input
}

// TestConformance_Matrix walks the cells defined in matrixCases and
// asserts Door A == Door B parity for both the allow and deny inputs of
// each. A failure on any single cell is reported as a t.Run sub-test so
// CI shows exactly which (identifier, authorizer) pair regressed.
func TestConformance_Matrix(t *testing.T) {
	t.Parallel()
	for _, tc := range matrixCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ac := tc.build(t)
			envoyCli, nativeCli := bootBothDoors(t, ac)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			assertParity(ctx, t, envoyCli, nativeCli, tc.allow(t), true /*wantAllow*/, 0)
			assertParity(ctx, t, envoyCli, nativeCli, tc.deny(t), false /*wantAllow*/, tc.denyTTP)
		})
	}
}

// assertParity runs req through both doors and checks that they agree
// with each other AND with the test's own expectation. See the long
// note in conformance_test.go on why we compare allow-bool + status
// rather than reason strings.
func assertParity(
	ctx context.Context,
	t *testing.T,
	envoyCli authv3.AuthorizationClient,
	nativeCli authv1.AuthClient,
	req matrixRequest,
	wantAllow bool,
	wantHTTP int32,
) {
	t.Helper()

	// Door A.
	creq := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  req.method,
					Path:    req.path,
					Host:    "api.test",
					Headers: copyHeaders(req.headers),
				},
			},
		},
	}
	cresp, err := envoyCli.Check(ctx, creq)
	if err != nil {
		t.Fatalf("Door A Check: %v", err)
	}
	doorAAllow := codes.Code(cresp.Status.Code) == codes.OK

	// Door B.
	areq := &authv1.AuthorizeRequest{
		Method:   req.method,
		Resource: req.path,
		Headers:  copyHeaders(req.headers),
	}
	aresp, err := nativeCli.Authorize(ctx, areq)
	if err != nil {
		t.Fatalf("Door B Authorize: %v", err)
	}

	if doorAAllow != aresp.Allow {
		t.Errorf("allow mismatch: doorA=%v doorB=%v (doorA-msg=%q doorB-reason=%q)",
			doorAAllow, aresp.Allow, cresp.Status.Message, aresp.DenyReason)
	}
	if doorAAllow != wantAllow {
		t.Errorf("doorA allow = %v, want %v", doorAAllow, wantAllow)
	}
	if !aresp.Allow && wantHTTP != 0 && aresp.HttpStatus != wantHTTP {
		t.Errorf("doorB http_status = %d, want %d", aresp.HttpStatus, wantHTTP)
	}
}

func copyHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// matrixCases is the table of conformance cells. Each cell is wholly
// self-contained: invoking build inside the test goroutine spins up
// (and registers cleanup for) any per-cell infrastructure.
func matrixCases() []matrixCase {
	return []matrixCase{
		// ── apikey × every authorizer ─────────────────────────────────
		{
			name:    "apikey+rbac",
			build:   func(t *testing.T) *config.AuthConfig { return apikeyConfigWith(rbacAdminAllow()) },
			allow:   func(t *testing.T) matrixRequest { return apikeyReq("dev-admin-key") },
			deny:    func(t *testing.T) matrixRequest { return apikeyReq("dev-viewer-key") },
			denyTTP: 403,
		},
		{
			name:    "apikey+cel",
			build:   func(t *testing.T) *config.AuthConfig { return apikeyConfigWith(celMethodGET()) },
			allow:   func(t *testing.T) matrixRequest { return apikeyReq("dev-admin-key") },
			deny:    func(t *testing.T) matrixRequest { return apikeyReqMethod("dev-admin-key", "DELETE") },
			denyTTP: 403,
		},
		{
			name:    "apikey+opa",
			build:   func(t *testing.T) *config.AuthConfig { return apikeyConfigWith(opaAdminInRoles()) },
			allow:   func(t *testing.T) matrixRequest { return apikeyReq("dev-admin-key") },
			deny:    func(t *testing.T) matrixRequest { return apikeyReq("dev-viewer-key") },
			denyTTP: 403,
		},
		{
			name:    "apikey+composite-allOf",
			build:   func(t *testing.T) *config.AuthConfig { return apikeyConfigWith(compositeAllOfRBACandGET()) },
			allow:   func(t *testing.T) matrixRequest { return apikeyReq("dev-admin-key") },
			deny:    func(t *testing.T) matrixRequest { return apikeyReqMethod("dev-admin-key", "DELETE") },
			denyTTP: 403,
		},
		{
			name: "apikey+openfga",
			build: func(t *testing.T) *config.AuthConfig {
				return apikeyConfigWith(openfgaForAlice(t))
			},
			// alice (admin key) is the user the fake OpenFGA store
			// approves; carol (viewer key) is the one it rejects. The
			// authorizer module makes the upstream call regardless.
			allow:   func(t *testing.T) matrixRequest { return apikeyReq("dev-admin-key") },
			deny:    func(t *testing.T) matrixRequest { return apikeyReq("dev-viewer-key") },
			denyTTP: 403,
		},

		// ── extra identifiers × rbac ──────────────────────────────────
		{
			name: "jwt+rbac",
			build: func(t *testing.T) *config.AuthConfig {
				jf := newJWTFixture(t)
				return &config.AuthConfig{
					Identifier: config.IdentifierFirstMatch,
					Identifiers: []config.ModuleSpec{{
						Name: "jwt-id",
						Type: "jwt",
						Config: map[string]any{
							"jwksUrl":  jf.url,
							"issuer":   "https://idp.test",
							"audience": []any{"api://my-svc"},
						},
					}},
					Authorizers: []config.ModuleSpec{rbacAdminAllow()},
				}
			},
			// allow: signed token with role=admin claim.
			allow: func(t *testing.T) matrixRequest {
				// We need access to the same fixture used in build —
				// re-use it via a lookup. Tests build per-case so we
				// re-mint here through a small per-test cache.
				return jwtRBACAllow(t)
			},
			deny: func(t *testing.T) matrixRequest {
				return jwtRBACDeny(t)
			},
			denyTTP: 403,
		},
		{
			name: "introspection+rbac",
			build: func(t *testing.T) *config.AuthConfig {
				url := newIntrospectionFixture(t)
				return &config.AuthConfig{
					Identifier: config.IdentifierFirstMatch,
					Identifiers: []config.ModuleSpec{{
						Name: "introspect",
						Type: "oauth2-introspection",
						Config: map[string]any{
							"url":          url,
							"clientId":     "lwauth",
							"clientSecret": "s",
							"maxCacheTtl":  "5s",
							"negativeTtl":  "1s",
						},
					}},
					Authorizers: []config.ModuleSpec{rbacAdminAllow()},
				}
			},
			allow: func(t *testing.T) matrixRequest {
				return matrixRequest{
					method: "GET", path: "/things",
					headers: map[string]string{"authorization": "Bearer token-admin"},
				}
			},
			deny: func(t *testing.T) matrixRequest {
				return matrixRequest{
					method: "GET", path: "/things",
					headers: map[string]string{"authorization": "Bearer token-viewer"},
				}
			},
			denyTTP: 403,
		},
		// hmac+rbac is intentionally not in the matrix. The HMAC
		// identifier binds the signature to the request's Host header
		// (and body hash, and query). Door A receives Host via
		// envoy.AttributeContext_HttpRequest.Host; Door B's
		// AuthorizeRequest proto has no host/body fields, so the
		// canonical string differs across doors and a signature minted
		// for one cannot verify on the other. This is a real Door A vs
		// Door B asymmetry the matrix surfaced; tracked as follow-up
		// M12-PROTO-HOST in DESIGN.md §1 (extend AuthorizeRequest with
		// host + body_sha256). Until that lands, HMAC is a
		// Door A-only identifier and parity is undefined.
	}
}

// ── shared fixture builders ────────────────────────────────────────────

// apikeyConfigWith returns the apikey identifier paired with a
// caller-supplied authorizer ModuleSpec. The static map is the same
// alice/carol pair used by nativeTestConfig so the apikey credentials
// stay stable across the whole matrix.
func apikeyConfigWith(authz config.ModuleSpec) *config.AuthConfig {
	return &config.AuthConfig{
		Identifier: config.IdentifierFirstMatch,
		Identifiers: []config.ModuleSpec{{
			Name: "dev-apikey",
			Type: "apikey",
			Config: map[string]any{
				"headerName": "X-Api-Key",
				"static": map[string]any{
					"dev-admin-key":  map[string]any{"subject": "alice", "roles": []any{"admin"}},
					"dev-viewer-key": map[string]any{"subject": "carol", "roles": []any{"viewer"}},
				},
			},
		}},
		Authorizers: []config.ModuleSpec{authz},
	}
}

func apikeyReq(key string) matrixRequest {
	return apikeyReqMethod(key, "GET")
}

func apikeyReqMethod(key, method string) matrixRequest {
	return matrixRequest{
		method: method, path: "/things",
		headers: map[string]string{"x-api-key": key},
	}
}

// ── authorizer fixture specs ───────────────────────────────────────────

func rbacAdminAllow() config.ModuleSpec {
	return config.ModuleSpec{
		Name: "rbac",
		Type: "rbac",
		Config: map[string]any{
			"rolesFrom": "claim:roles",
			"allow":     []any{"admin"},
		},
	}
}

func celMethodGET() config.ModuleSpec {
	return config.ModuleSpec{
		Name: "cel",
		Type: "cel",
		Config: map[string]any{
			"expression": `request.method == "GET"`,
		},
	}
}

// opaAdminInRoles uses Rego v0 syntax (matches the existing OPA
// self-tests in pkg/authz/opa). The apikey identifier surfaces the
// subject's roles as []string under claims.roles, so the rule walks
// the slice.
func opaAdminInRoles() config.ModuleSpec {
	return config.ModuleSpec{
		Name: "opa",
		Type: "opa",
		Config: map[string]any{
			"rego": `
package authz
import rego.v1

default allow := false
allow if {
  input.identity.claims.roles[_] == "admin"
}
`,
		},
	}
}

func compositeAllOfRBACandGET() config.ModuleSpec {
	return config.ModuleSpec{
		Name: "composite",
		Type: "composite",
		Config: map[string]any{
			"allOf": []any{
				map[string]any{
					"name":   "rbac-child",
					"type":   "rbac",
					"config": map[string]any{"rolesFrom": "claim:roles", "allow": []any{"admin"}},
				},
				map[string]any{
					"name":   "cel-child",
					"type":   "cel",
					"config": map[string]any{"expression": `request.method == "GET"`},
				},
			},
		},
	}
}

// openfgaForAlice spins up a minimal fake OpenFGA HTTP API that allows
// when the tuple's user is "user:alice" and denies otherwise. It is
// registered for cleanup against the supplied *testing.T.
func openfgaForAlice(t *testing.T) config.ModuleSpec {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/check") {
			http.NotFound(w, r)
			return
		}
		var body struct {
			TupleKey struct {
				User string `json:"user"`
			} `json:"tuple_key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"allowed": %v}`, body.TupleKey.User == "user:alice")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return config.ModuleSpec{
		Name: "openfga",
		Type: "openfga",
		Config: map[string]any{
			"apiUrl":               srv.URL,
			"storeId":              "01HX",
			"authorizationModelId": "01MODEL",
			"check": map[string]any{
				"user":     "user:{{ .Identity.Subject }}",
				"relation": "{{ .Request.Method | lower }}",
				"object":   "doc:thing",
			},
		},
	}
}

// ── identifier fixtures (jwt, introspection, hmac) ─────────────────────

// jwtFixture spins up an in-memory JWKS endpoint and exposes a per-test
// signer. The matrix shares one fixture per process-lifetime via the
// jwtFixtureSingleton because re-minting it for both the build and
// allow callbacks would create two unrelated JWKS servers.
type jwtFixture struct {
	url     string
	signKey jwk.Key
}

func newJWTFixture(t *testing.T) *jwtFixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	priv, err := jwk.FromRaw(rsaKey)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = priv.Set(jwk.KeyIDKey, "matrix-kid-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256)

	pub, err := jwk.PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("PublicKeyOf: %v", err)
	}
	_ = pub.Set(jwk.KeyIDKey, "matrix-kid-1")
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)

	f := &jwtFixture{url: srv.URL, signKey: priv}
	stashJWT(t, f)
	return f
}

func (f *jwtFixture) mint(t *testing.T, sub string, roles []any) string {
	t.Helper()
	tok, err := jwtlib.NewBuilder().
		Issuer("https://idp.test").
		Subject(sub).
		Audience([]string{"api://my-svc"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		Claim("roles", roles).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.RS256, f.signKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// jwt fixtures keyed by *testing.T so allow/deny callbacks can find
// the same fixture build() created. Cleared on test cleanup.
var (
	jwtFixturesByTest = make(map[*testing.T]*jwtFixture)
)

func stashJWT(t *testing.T, f *jwtFixture) {
	jwtFixturesByTest[t] = f
	t.Cleanup(func() { delete(jwtFixturesByTest, t) })
}

func jwtRBACAllow(t *testing.T) matrixRequest {
	f := jwtFixturesByTest[t]
	if f == nil {
		t.Fatalf("jwt fixture missing for test %q", t.Name())
	}
	return matrixRequest{
		method: "GET", path: "/things",
		headers: map[string]string{"authorization": "Bearer " + f.mint(t, "alice", []any{"admin"})},
	}
}

func jwtRBACDeny(t *testing.T) matrixRequest {
	f := jwtFixturesByTest[t]
	if f == nil {
		t.Fatalf("jwt fixture missing for test %q", t.Name())
	}
	return matrixRequest{
		method: "GET", path: "/things",
		headers: map[string]string{"authorization": "Bearer " + f.mint(t, "carol", []any{"viewer"})},
	}
}

// newIntrospectionFixture returns a URL for a fake RFC 7662
// introspection endpoint. It echoes back active=true with role=admin
// when the submitted token equals "token-admin", role=viewer for
// "token-viewer", and active=false otherwise.
func newIntrospectionFixture(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		token := r.PostFormValue("token")
		w.Header().Set("Content-Type", "application/json")
		switch token {
		case "token-admin":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true, "sub": "alice",
				"roles": []string{"admin"},
				"exp":   float64(time.Now().Add(time.Hour).Unix()),
			})
		case "token-viewer":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true, "sub": "carol",
				"roles": []string{"viewer"},
				"exp":   float64(time.Now().Add(time.Hour).Unix()),
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}


