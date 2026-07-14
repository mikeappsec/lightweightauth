// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/internal/replay"
	"github.com/mikeappsec/lightweightauth/pkg/keyrotation"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

var registerTestStub sync.Once

// stubIdentifier is a plain inner identifier for tests. It returns a
// fixed identity whose claims are configurable per test (so we can
// inject `cnf.jkt` to exercise the binding path).
type stubIdentifier struct {
	name   string
	claims map[string]any
	err    error
}

func (s *stubIdentifier) Name() string { return s.name }
func (s *stubIdentifier) Identify(_ context.Context, _ *module.Request) (*module.Identity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &module.Identity{Subject: "alice", Claims: s.claims, Source: s.name}, nil
}

// dpopFixture pairs an ES256 keypair (used for the proof) with a
// preconfigured *identifier whose inner is the supplied stub.
type dpopFixture struct {
	priv     jwk.Key
	pub      jwk.Key
	thumb    string
	identity *identifier
}

func newFixture(t *testing.T, inner module.Identifier, skew time.Duration) *dpopFixture {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	priv, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = priv.Set(jwk.AlgorithmKey, jwa.ES256)
	pub, _ := jwk.PublicKeyOf(priv)
	thumb, err := jwkThumbprintB64(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	id := &identifier{
		name: "dpop-test",
		cfg: Config{
			Required:     true,
			Skew:         skew,
			ProofHeader:  defaultProofHeader,
			BearerHeader: defaultBearerHeader,
		},
		inner:  inner,
		replay: replay.New(nil),
		now:    time.Now,
	}
	return &dpopFixture{priv: priv, pub: pub, thumb: thumb, identity: id}
}

// signProof builds a DPoP proof JWT with the given claim overrides.
func (f *dpopFixture) signProof(t *testing.T, htm, htu, jti string, iat time.Time, ath string) string {
	t.Helper()
	tok, err := jwtlib.NewBuilder().
		Claim("htm", htm).
		Claim("htu", htu).
		Claim("jti", jti).
		IssuedAt(iat).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if ath != "" {
		_ = tok.Set("ath", ath)
	}
	hdr := jws.NewHeaders()
	_ = hdr.Set("typ", dpopJWTType)
	_ = hdr.Set("jwk", f.pub)
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.ES256, f.priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

func req(method, host, path, proof, bearer string) *module.Request {
	headers := map[string][]string{}
	if proof != "" {
		headers["DPoP"] = []string{proof}
	}
	if bearer != "" {
		headers["Authorization"] = []string{"Bearer " + bearer}
	}
	return &module.Request{Method: method, Host: host, Path: path, Headers: headers}
}

// TestDPoP_HappyPath: proof verifies, inner returns identity, no
// confirmation claim or access token → identity is returned.
func TestDPoP_HappyPath(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{}}, 30*time.Second)
	proof := f.signProof(t, "POST", "https://api.example/things", "jti-1", time.Now(), "")
	id, err := f.identity.Identify(context.Background(), req("POST", "api.example", "/things", proof, ""))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "alice" {
		t.Fatalf("subject = %q, want alice", id.Subject)
	}
}

// TestDPoP_MissingHeader_Required: required=true, no DPoP header →
// ErrInvalidCredential.
func TestDPoP_MissingHeader_Required(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner"}, 30*time.Second)
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", "", ""))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// TestDPoP_MissingHeader_NotRequired: required=false falls through to
// inner so the identifier composes with plain bearer setups.
func TestDPoP_MissingHeader_NotRequired(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{}}, 30*time.Second)
	f.identity.cfg.Required = false
	id, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", "", ""))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "alice" {
		t.Fatalf("subject = %q, want alice", id.Subject)
	}
}

// TestDPoP_HTMMismatch: proof signed for POST against a GET request.
func TestDPoP_HTMMismatch(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner"}, 30*time.Second)
	proof := f.signProof(t, "POST", "https://api.example/x", "jti-2", time.Now(), "")
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, ""))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// TestDPoP_HTUMismatch: proof signed for /a, request hits /b.
func TestDPoP_HTUMismatch(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner"}, 30*time.Second)
	proof := f.signProof(t, "GET", "https://api.example/a", "jti-3", time.Now(), "")
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/b", proof, ""))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// TestDPoP_HTUIgnoresQuery: proof's htu omits the query, request URL
// has one. They should still match.
func TestDPoP_HTUIgnoresQuery(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{}}, 30*time.Second)
	proof := f.signProof(t, "GET", "https://api.example/x?a=1", "jti-q", time.Now(), "")
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, ""))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
}

// TestDPoP_IATSkew: an iat far outside the skew window is rejected.
func TestDPoP_IATSkew(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner"}, 5*time.Second)
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-skew", time.Now().Add(-1*time.Minute), "")
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, ""))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// TestDPoP_JTIReplay: re-using the same jti within the cache window
// is rejected.
func TestDPoP_JTIReplay(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{}}, 30*time.Second)
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-replay", time.Now(), "")
	if _, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, "")); err != nil {
		t.Fatalf("first Identify: %v", err)
	}
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, ""))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("replay err = %v, want ErrInvalidCredential", err)
	}
}

// TestDPoP_CnfJktBinding: when inner identity carries cnf.jkt, the
// proof's JWK thumbprint MUST match.
func TestDPoP_CnfJktBinding_Match(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner"}, 30*time.Second)
	f.identity.inner = &stubIdentifier{
		name:   "inner",
		claims: map[string]any{"cnf": map[string]any{"jkt": f.thumb}},
	}
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-cnf-ok", time.Now(), "")
	if _, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, "")); err != nil {
		t.Fatalf("Identify: %v", err)
	}
}

func TestDPoP_CnfJktBinding_Mismatch(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner"}, 30*time.Second)
	f.identity.inner = &stubIdentifier{
		name:   "inner",
		claims: map[string]any{"cnf": map[string]any{"jkt": "not-the-real-thumbprint"}},
	}
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-cnf-bad", time.Now(), "")
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, ""))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// TestDPoP_AthBinding: when a bearer is on the request, the proof's
// `ath` must equal base64url(sha256(token)).
func TestDPoP_AthBinding_Match(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner"}, 30*time.Second)
	// Inner must carry cnf.jkt when bearer is present (DPOP-VULN-01 fix).
	f.identity.inner = &stubIdentifier{
		name:   "inner",
		claims: map[string]any{"cnf": map[string]any{"jkt": f.thumb}},
	}
	at := "deadbeef-access-token"
	sum := sha256.Sum256([]byte(at))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-ath", time.Now(), ath)
	if _, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, at)); err != nil {
		t.Fatalf("Identify: %v", err)
	}
}

func TestDPoP_AthBinding_Mismatch(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner"}, 30*time.Second)
	f.identity.inner = &stubIdentifier{
		name:   "inner",
		claims: map[string]any{"cnf": map[string]any{"jkt": f.thumb}},
	}
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-ath-bad", time.Now(), "wrong-ath")
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, "the-token"))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

// reqDPoP builds a request with Authorization: DPoP <token> (the actual
// RFC 9449 wire format) instead of Bearer.
func reqDPoP(method, host, path, proof, accessToken string) *module.Request {
	headers := map[string][]string{}
	if proof != "" {
		headers["dpop"] = []string{proof}
	}
	if accessToken != "" {
		headers["authorization"] = []string{"DPoP " + accessToken}
	}
	return &module.Request{Method: method, Host: host, Path: path, Headers: headers}
}

// capturingIdentifier records the request it receives so tests can
// assert the Authorization header was rewritten from DPoP to Bearer.
type capturingIdentifier struct {
	name        string
	claims      map[string]any
	lastAuthHdr string
}

func (c *capturingIdentifier) Name() string { return c.name }
func (c *capturingIdentifier) Identify(_ context.Context, r *module.Request) (*module.Identity, error) {
	c.lastAuthHdr = r.Header("Authorization")
	return &module.Identity{Subject: "bob", Claims: c.claims, Source: c.name}, nil
}

// TestDPoP_RFC9449_FullFlow exercises the complete production path per
// RFC 9449 §4.3:
//
//  1. Client sends: Authorization: DPoP <access_token>, DPoP: <proof>
//  2. Resource server (lwauth) validates the DPoP proof JWT
//  3. Resource server calls introspection (inner) to validate token
//  4. Introspection responds with cnf.jkt (JWK thumbprint of DPoP key)
//  5. Resource server verifies:
//     - DPoP proof key matches cnf.jkt from introspection
//     - ath claim in proof = sha256(access_token)
//     - Token is active (inner returned identity)
func TestDPoP_RFC9449_FullFlow(t *testing.T) {
	accessToken := "opaque-token-from-idp-12345"

	// The inner identifier simulates introspection returning cnf.jkt.
	inner := &capturingIdentifier{name: "introspect"}

	f := newFixture(t, inner, 30*time.Second)

	// Set the inner's claims to include cnf.jkt matching our DPoP key's
	// thumbprint — this simulates the introspection response.
	inner.claims = map[string]any{
		"cnf": map[string]any{"jkt": f.thumb},
	}

	// Build DPoP proof with ath = sha256(access_token), per §4.3 step 11.
	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/resource", "jti-rfc9449", time.Now(), ath)

	// Send request with "Authorization: DPoP <token>" (NOT Bearer).
	r := reqDPoP("GET", "api.example", "/resource", proof, accessToken)
	id, err := f.identity.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "bob" {
		t.Fatalf("subject = %q, want bob", id.Subject)
	}

	// Verify the inner identifier received "Bearer <token>" (rewritten
	// from "DPoP <token>") so oauth2-introspection can extract it.
	wantAuth := "Bearer " + accessToken
	if inner.lastAuthHdr != wantAuth {
		t.Fatalf("inner saw Authorization = %q, want %q", inner.lastAuthHdr, wantAuth)
	}
}

// TestDPoP_RFC9449_CnfMismatch_DPoPScheme verifies that when the
// introspection response's cnf.jkt doesn't match the proof key, the
// request is rejected — even with a valid proof and valid ath.
func TestDPoP_RFC9449_CnfMismatch_DPoPScheme(t *testing.T) {
	accessToken := "token-for-cnf-mismatch"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{"cnf": map[string]any{"jkt": "wrong-thumbprint-from-different-key"}},
	}
	f := newFixture(t, inner, 30*time.Second)

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-cnf-dpop", time.Now(), ath)

	_, err := f.identity.Identify(context.Background(), reqDPoP("GET", "api.example", "/x", proof, accessToken))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (cnf.jkt mismatch)", err)
	}
}

// TestDPoP_RFC9449_AthMismatch_DPoPScheme verifies that a valid proof
// with wrong ath (token hash) is rejected when using DPoP scheme.
func TestDPoP_RFC9449_AthMismatch_DPoPScheme(t *testing.T) {
	accessToken := "the-real-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f := newFixture(t, inner, 30*time.Second)

	// ath computed over a DIFFERENT token than what's on the wire.
	wrongAth := base64.RawURLEncoding.EncodeToString(sha256sum("different-token"))
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-ath-dpop", time.Now(), wrongAth)

	_, err := f.identity.Identify(context.Background(), reqDPoP("GET", "api.example", "/x", proof, accessToken))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (ath mismatch)", err)
	}
}

// ---------------------------------------------------------------------------
// Grant-type-specific DPoP tests
//
// RFC 9449 DPoP is grant-type agnostic — the resource server validates
// proof + cnf.jkt + ath regardless of how the token was obtained. These
// tests verify DPoP works correctly with introspection responses typical
// of each grant type.
// ---------------------------------------------------------------------------

// TestDPoP_GrantType_AuthorizationCode exercises the most common flow:
// a user-facing app obtains a token via Authorization Code grant. The
// introspection response includes subject, scope, and cnf.jkt.
func TestDPoP_GrantType_AuthorizationCode(t *testing.T) {
	accessToken := "authz-code-token-abc123"
	inner := &capturingIdentifier{
		name: "introspect",
		claims: map[string]any{
			"grant_type": "authorization_code",
			"scope":      "openid profile email",
			"client_id":  "web-app-client",
			"cnf":        map[string]any{},
		},
	}
	f := newFixture(t, inner, 30*time.Second)
	// Inject the correct jkt after fixture creation (need the key thumbprint).
	inner.claims["cnf"] = map[string]any{"jkt": f.thumb}

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "POST", "https://api.example/userinfo", "jti-authz-code", time.Now(), ath)

	r := reqDPoP("POST", "api.example", "/userinfo", proof, accessToken)
	id, err := f.identity.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "bob" {
		t.Fatalf("subject = %q, want bob", id.Subject)
	}
	// Verify inner received Bearer (rewritten from DPoP).
	if got := inner.lastAuthHdr; got != "Bearer "+accessToken {
		t.Fatalf("inner auth = %q, want Bearer prefix", got)
	}
}

// TestDPoP_GrantType_AuthorizationCodePKCE exercises the PKCE variant
// used by SPAs and mobile apps. The introspection response may include
// code_challenge_method to indicate PKCE was used. DPoP validation is
// identical — the resource server doesn't care about PKCE details.
func TestDPoP_GrantType_AuthorizationCodePKCE(t *testing.T) {
	accessToken := "pkce-spa-token-xyz789"
	inner := &capturingIdentifier{
		name: "introspect",
		claims: map[string]any{
			"grant_type":            "authorization_code",
			"scope":                 "openid offline_access",
			"client_id":             "spa-public-client",
			"code_challenge_method": "S256", // indicates PKCE was used
			"cnf":                   map[string]any{},
		},
	}
	f := newFixture(t, inner, 30*time.Second)
	inner.claims["cnf"] = map[string]any{"jkt": f.thumb}

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/data", "jti-pkce", time.Now(), ath)

	r := reqDPoP("GET", "api.example", "/data", proof, accessToken)
	id, err := f.identity.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "bob" {
		t.Fatalf("subject = %q, want bob", id.Subject)
	}
	if got := inner.lastAuthHdr; got != "Bearer "+accessToken {
		t.Fatalf("inner auth = %q, want Bearer prefix", got)
	}
}

// TestDPoP_GrantType_ClientCredentials exercises machine-to-machine
// tokens obtained via Client Credentials grant. These tokens typically
// have no "sub" (or sub = client_id), no refresh token, and narrower
// scopes. DPoP validation is unchanged.
func TestDPoP_GrantType_ClientCredentials(t *testing.T) {
	accessToken := "m2m-service-token-000"
	inner := &capturingIdentifier{
		name: "introspect",
		claims: map[string]any{
			"grant_type": "client_credentials",
			"scope":      "api:read api:write",
			"client_id":  "backend-service-a",
			// No "sub" claim — common for client_credentials tokens.
			"cnf": map[string]any{},
		},
	}
	f := newFixture(t, inner, 30*time.Second)
	inner.claims["cnf"] = map[string]any{"jkt": f.thumb}

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "PUT", "https://api.example/internal/sync", "jti-m2m", time.Now(), ath)

	r := reqDPoP("PUT", "api.example", "/internal/sync", proof, accessToken)
	id, err := f.identity.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "bob" {
		t.Fatalf("subject = %q, want bob", id.Subject)
	}
	if got := inner.lastAuthHdr; got != "Bearer "+accessToken {
		t.Fatalf("inner auth = %q, want Bearer prefix", got)
	}
}

// TestDPoP_GrantType_ClientCredentials_CnfMismatch verifies that even
// for M2M tokens, a cnf.jkt mismatch rejects the request. A
// compromised service cannot replay another service's DPoP-bound token
// without possessing the private key.
func TestDPoP_GrantType_ClientCredentials_CnfMismatch(t *testing.T) {
	accessToken := "m2m-stolen-token"
	inner := &capturingIdentifier{
		name: "introspect",
		claims: map[string]any{
			"grant_type": "client_credentials",
			"client_id":  "backend-service-b",
			"cnf":        map[string]any{"jkt": "attacker-has-different-key-thumbprint"},
		},
	}
	f := newFixture(t, inner, 30*time.Second)

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "DELETE", "https://api.example/internal/resource", "jti-m2m-stolen", time.Now(), ath)

	_, err := f.identity.Identify(context.Background(), reqDPoP("DELETE", "api.example", "/internal/resource", proof, accessToken))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (M2M cnf.jkt mismatch)", err)
	}
}

// TestDPoP_GrantType_AuthorizationCode_ProofReplay verifies JTI replay
// detection across grant types — a valid proof cannot be replayed even
// if everything else (ath, cnf) is correct.
func TestDPoP_GrantType_AuthorizationCode_ProofReplay(t *testing.T) {
	accessToken := "authcode-replay-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f := newFixture(t, inner, 30*time.Second)
	inner.claims = map[string]any{"cnf": map[string]any{"jkt": f.thumb}}

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/me", "jti-replay-grant", time.Now(), ath)

	r := reqDPoP("GET", "api.example", "/me", proof, accessToken)
	// First request succeeds.
	if _, err := f.identity.Identify(context.Background(), r); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Same proof replayed — must be rejected.
	_, err := f.identity.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("replay: err = %v, want ErrInvalidCredential", err)
	}
}

// TestDPoP_RejectsHMAC: a proof signed with an HMAC alg must be
// rejected even if the embedded "jwk" is something the verifier could
// otherwise consume — the alg check happens before the signature check.
func TestDPoP_RejectsHMAC(t *testing.T) {
	// Build the proof manually with HS256.
	hkRaw := []byte("0123456789abcdef0123456789abcdef")
	hk, _ := jwk.FromRaw(hkRaw)
	pub := hk // symmetric, but we'll embed it just to drive the path
	tok, _ := jwtlib.NewBuilder().
		Claim("htm", "GET").Claim("htu", "https://api.example/x").Claim("jti", "jti-hmac").
		IssuedAt(time.Now()).Build()
	hdr := jws.NewHeaders()
	_ = hdr.Set("typ", dpopJWTType)
	_ = hdr.Set("jwk", pub)
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(jwa.HS256, hkRaw, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("sign hs256: %v", err)
	}

	f := newFixture(t, &stubIdentifier{name: "inner"}, 30*time.Second)
	_, err = f.identity.Identify(context.Background(), req("GET", "api.example", "/x", string(signed), ""))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (HMAC rejected)", err)
	}
}

func TestDPoP_RejectsUnknownConfigKey(t *testing.T) {
	t.Parallel()
	_, err := factory("d", map[string]any{
		"inner":   map[string]any{"type": "jwt", "config": map[string]any{"jwksUrl": "http://localhost/jwks"}},
		"enforce": true,
	}, module.Deps{})
	if err == nil {
		t.Fatal("expected error for unknown config key, got nil")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Errorf("error = %v, want ErrConfig wrapper", err)
	}
}

// TestDPoP_RejectsTokenWithoutCnfJkt verifies DPOP-VULN-01: when
// required=true and a bearer token is present, the inner identity MUST
// carry cnf.jkt. Without it, proof-of-possession is not enforced and a
// stolen token can be replayed with any attacker-generated key.
func TestDPoP_RejectsTokenWithoutCnfJkt(t *testing.T) {
	// Inner returns identity WITHOUT cnf.jkt — simulates an IdP that
	// didn't bind the token to the client's DPoP key.
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{
		"scope": "read write",
	}}, 30*time.Second)

	at := "stolen-access-token"
	sum := sha256.Sum256([]byte(at))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/resource", "jti-no-cnf", time.Now(), ath)

	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/resource", proof, at))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (token without cnf.jkt must be rejected when DPoP required)", err)
	}
}

// TestDPoP_AllowsMissingCnfJktWhenNotRequired verifies that
// required=false does NOT enforce cnf.jkt — this allows gradual DPoP
// rollout where some tokens may not yet be DPoP-bound.
func TestDPoP_AllowsMissingCnfJktWhenNotRequired(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{}}, 30*time.Second)
	f.identity.cfg.Required = false

	at := "unbound-token"
	sum := sha256.Sum256([]byte(at))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-not-req", time.Now(), ath)

	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, at))
	if err != nil {
		t.Fatalf("Identify: %v (required=false should allow missing cnf.jkt)", err)
	}
}

// TestDPoP_HTUMatchesWithQueryInPath verifies DPOP-VULN-02: when
// r.Path includes query strings (as in ext_authz deployments), the
// htu comparison must still succeed by stripping the query from r.Path
// per RFC 9449 §4.3 step 9.
func TestDPoP_HTUMatchesWithQueryInPath(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{}}, 30*time.Second)
	// Proof htu omits query (RFC-compliant).
	proof := f.signProof(t, "GET", "https://api.example/resource", "jti-query", time.Now(), "")
	// Request path includes query (as ext_authz provides).
	r := &module.Request{
		Method:  "GET",
		Host:    "api.example",
		Path:    "/resource?id=42&page=1",
		Headers: map[string][]string{"dpop": {proof}},
	}
	_, err := f.identity.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v (htu should match after stripping query from r.Path)", err)
	}
}

// ---------------------------------------------------------------------------
// Pinned Key Rotation Tests
// ---------------------------------------------------------------------------

// newRotatableFixture creates a rotatableIdentifier with pinned keys
// and a controllable clock for lifecycle testing.
func newRotatableFixture(t *testing.T, inner module.Identifier, skew time.Duration) (*dpopFixture, *rotatableIdentifier, *fakeClock) {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	priv, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = priv.Set(jwk.AlgorithmKey, jwa.ES256)
	pub, _ := jwk.PublicKeyOf(priv)
	thumb, err := jwkThumbprintB64(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	clk := &fakeClock{now: time.Now()}
	id := &identifier{
		name: "dpop-pinned-test",
		cfg: Config{
			Required:     true,
			Skew:         skew,
			ProofHeader:  defaultProofHeader,
			BearerHeader: defaultBearerHeader,
		},
		inner:  inner,
		replay: replay.New(nil),
		now:    clk.Now,
	}

	ks := keyrotation.NewKeySet[string](clk.Now)
	ri := &rotatableIdentifier{identifier: *id, pinned: ks}

	return &dpopFixture{priv: priv, pub: pub, thumb: thumb, identity: id}, ri, clk
}

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// TestPinnedKey_ActiveKey_Accepted: a proof signed by an active pinned
// key is accepted.
func TestPinnedKey_ActiveKey_Accepted(t *testing.T) {
	accessToken := "pinned-active-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f, ri, clk := newRotatableFixture(t, inner, 30*time.Second)
	inner.claims = map[string]any{"cnf": map[string]any{"jkt": f.thumb}}

	// Register the key as active (no bounds).
	ri.pinned.Put(keyrotation.KeyMeta{KID: "key-v1"}, f.thumb)

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/data", "jti-pinned-active", clk.Now(), ath)

	r := reqDPoP("GET", "api.example", "/data", proof, accessToken)
	id, err := ri.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "bob" {
		t.Fatalf("subject = %q, want bob", id.Subject)
	}
}

// TestPinnedKey_RejectsTokenWithoutCnfJkt verifies the pinned-key
// (rotatableIdentifier) path enforces the same cnf.jkt binding as the base
// identifier (see TestDPoP_RejectsTokenWithoutCnfJkt). Regression test for
// the bug where rotatableIdentifier.Identify's cnf.jkt check had no `else`
// branch, silently accepting a valid proof from a pinned key paired with a
// bearer token that carried no cnf.jkt at all — defeating proof-of-possession
// specifically in the mode meant to be more secure.
func TestPinnedKey_RejectsTokenWithoutCnfJkt(t *testing.T) {
	accessToken := "pinned-no-cnf-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{}, // no cnf.jkt
	}
	f, ri, clk := newRotatableFixture(t, inner, 30*time.Second)

	// Register the key as active (no bounds) — the proof itself is
	// legitimately signed by a pinned key, only the inner identity lacks
	// cnf.jkt.
	ri.pinned.Put(keyrotation.KeyMeta{KID: "key-v1"}, f.thumb)

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/data", "jti-pinned-no-cnf", clk.Now(), ath)

	r := reqDPoP("GET", "api.example", "/data", proof, accessToken)
	_, err := ri.Identify(context.Background(), r)
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (token without cnf.jkt must be rejected via the pinned-key path too)", err)
	}
}

// TestPinnedKey_PendingKey_Rejected: a proof signed by a key whose
// notBefore is in the future is rejected.
func TestPinnedKey_PendingKey_Rejected(t *testing.T) {
	accessToken := "pinned-pending-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f, ri, clk := newRotatableFixture(t, inner, 30*time.Second)
	inner.claims = map[string]any{"cnf": map[string]any{"jkt": f.thumb}}

	// Register key with notBefore 1 hour in the future → pending.
	ri.pinned.Put(keyrotation.KeyMeta{
		KID:       "key-v2",
		NotBefore: clk.Now().Add(1 * time.Hour),
	}, f.thumb)

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/data", "jti-pinned-pending", clk.Now(), ath)

	_, err := ri.Identify(context.Background(), reqDPoP("GET", "api.example", "/data", proof, accessToken))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (pending key)", err)
	}
}

// TestPinnedKey_RetiringKey_Accepted: a key past notAfter but within
// gracePeriod is still accepted (allows in-flight requests to drain).
func TestPinnedKey_RetiringKey_Accepted(t *testing.T) {
	accessToken := "pinned-retiring-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f, ri, clk := newRotatableFixture(t, inner, 30*time.Second)
	inner.claims = map[string]any{"cnf": map[string]any{"jkt": f.thumb}}

	// Key was active until 1 minute ago, grace period is 10 minutes.
	ri.pinned.Put(keyrotation.KeyMeta{
		KID:         "key-v1",
		NotAfter:    clk.Now().Add(-1 * time.Minute),
		GracePeriod: 10 * time.Minute,
	}, f.thumb)

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/data", "jti-pinned-retiring", clk.Now(), ath)

	r := reqDPoP("GET", "api.example", "/data", proof, accessToken)
	id, err := ri.Identify(context.Background(), r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "bob" {
		t.Fatalf("subject = %q, want bob", id.Subject)
	}
}

// TestPinnedKey_RetiredKey_Rejected: a key past notAfter + gracePeriod
// is rejected.
func TestPinnedKey_RetiredKey_Rejected(t *testing.T) {
	accessToken := "pinned-retired-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f, ri, clk := newRotatableFixture(t, inner, 30*time.Second)
	inner.claims = map[string]any{"cnf": map[string]any{"jkt": f.thumb}}

	// Key retired: notAfter was 20 minutes ago, grace is 5 minutes.
	ri.pinned.Put(keyrotation.KeyMeta{
		KID:         "key-v1",
		NotAfter:    clk.Now().Add(-20 * time.Minute),
		GracePeriod: 5 * time.Minute,
	}, f.thumb)

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/data", "jti-pinned-retired", clk.Now(), ath)

	_, err := ri.Identify(context.Background(), reqDPoP("GET", "api.example", "/data", proof, accessToken))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (retired key)", err)
	}
}

// TestPinnedKey_UnknownKey_Rejected: a proof signed by a key not in
// the pinned set is rejected.
func TestPinnedKey_UnknownKey_Rejected(t *testing.T) {
	accessToken := "pinned-unknown-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f, ri, _ := newRotatableFixture(t, inner, 30*time.Second)
	inner.claims = map[string]any{"cnf": map[string]any{"jkt": f.thumb}}

	// Register a DIFFERENT thumbprint as the only pinned key.
	ri.pinned.Put(keyrotation.KeyMeta{KID: "key-other"}, "some-other-thumbprint-not-ours")

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/data", "jti-pinned-unknown", time.Now(), ath)

	_, err := ri.Identify(context.Background(), reqDPoP("GET", "api.example", "/data", proof, accessToken))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential (unknown key)", err)
	}
}

// TestPinnedKey_OverlapWindow: two keys are active simultaneously
// during rotation. Both should be accepted.
func TestPinnedKey_OverlapWindow(t *testing.T) {
	accessToken := "pinned-overlap-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f, ri, clk := newRotatableFixture(t, inner, 30*time.Second)
	inner.claims = map[string]any{"cnf": map[string]any{"jkt": f.thumb}}

	// Two pinned keys: our key (v1) and another (v2). Both active.
	ri.pinned.Put(keyrotation.KeyMeta{KID: "key-v1"}, f.thumb)
	ri.pinned.Put(keyrotation.KeyMeta{KID: "key-v2"}, "another-key-thumbprint")

	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/data", "jti-overlap", clk.Now(), ath)

	// Our key (v1) is in the set → accepted.
	id, err := ri.Identify(context.Background(), reqDPoP("GET", "api.example", "/data", proof, accessToken))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.Subject != "bob" {
		t.Fatalf("subject = %q, want bob", id.Subject)
	}
}

// TestPinnedKey_TransitionFromActiveToRetired: simulate full rotation
// lifecycle using clock advancement.
func TestPinnedKey_TransitionFromActiveToRetired(t *testing.T) {
	accessToken := "pinned-transition-token"
	inner := &capturingIdentifier{
		name:   "introspect",
		claims: map[string]any{},
	}
	f, ri, clk := newRotatableFixture(t, inner, 30*time.Second)
	inner.claims = map[string]any{"cnf": map[string]any{"jkt": f.thumb}}

	baseTime := clk.Now()
	// Key v1 expires in 10 minutes with 5 minute grace.
	ri.pinned.Put(keyrotation.KeyMeta{
		KID:         "key-v1",
		NotAfter:    baseTime.Add(10 * time.Minute),
		GracePeriod: 5 * time.Minute,
	}, f.thumb)

	// Phase 1: Key is active (now is before notAfter).
	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof1 := f.signProof(t, "GET", "https://api.example/x", "jti-trans-1", clk.Now(), ath)
	if _, err := ri.Identify(context.Background(), reqDPoP("GET", "api.example", "/x", proof1, accessToken)); err != nil {
		t.Fatalf("Phase 1 (active): %v", err)
	}

	// Phase 2: Advance past notAfter but within grace → retiring.
	clk.Advance(12 * time.Minute) // 2 min past notAfter
	proof2 := f.signProof(t, "GET", "https://api.example/x", "jti-trans-2", clk.Now(), ath)
	if _, err := ri.Identify(context.Background(), reqDPoP("GET", "api.example", "/x", proof2, accessToken)); err != nil {
		t.Fatalf("Phase 2 (retiring): %v", err)
	}

	// Phase 3: Advance past grace period → retired.
	clk.Advance(5 * time.Minute) // now 17 min from start = past notAfter+grace
	proof3 := f.signProof(t, "GET", "https://api.example/x", "jti-trans-3", clk.Now(), ath)
	_, err := ri.Identify(context.Background(), reqDPoP("GET", "api.example", "/x", proof3, accessToken))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("Phase 3 (retired): err = %v, want ErrInvalidCredential", err)
	}

	// Verify key states.
	states := ri.KeyStates()
	found := false
	for _, s := range states {
		if s.KID == "key-v1" {
			found = true
			if s.State != "retired" {
				t.Fatalf("key-v1 state = %q, want retired", s.State)
			}
		}
	}
	if !found {
		t.Fatal("key-v1 not in KeyStates()")
	}
}

// TestPinnedKey_FactoryParsing: verify factory creates rotatableIdentifier
// when pinnedKeys is provided. Uses a stub inner to avoid dependency on
// registered identifier types.
func TestPinnedKey_FactoryParsing(t *testing.T) {
	// Register a temporary "stub" identifier type for this test.
	registerTestStub.Do(func() {
		module.RegisterIdentifier("test-stub-pinned", func(name string, raw map[string]any) (module.Identifier, error) {
			return &stubIdentifier{name: name}, nil
		})
	})

	id, err := factory("pinned-dpop", map[string]any{
		"required": true,
		"skew":     "30s",
		"inner": map[string]any{
			"type":   "test-stub-pinned",
			"config": map[string]any{},
		},
		"pinnedKeys": []any{map[string]any{
			"kid":        "v1",
			"thumbprint": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
			map[string]any{
				"kid":         "v2",
				"thumbprint":  "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
				"notBefore":   "2026-05-01T00:00:00Z",
				"notAfter":    "2026-06-01T00:00:00Z",
				"gracePeriod": "10m",
			},
		},
	}, module.Deps{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ri, ok := id.(*rotatableIdentifier)
	if !ok {
		t.Fatalf("got %T, want *rotatableIdentifier", id)
	}
	if ri.pinned.Len() != 2 {
		t.Fatalf("pinned keys = %d, want 2", ri.pinned.Len())
	}
	states := ri.KeyStates()
	if len(states) != 2 {
		t.Fatalf("KeyStates len = %d, want 2", len(states))
	}
}

// TestPinnedKey_FactoryMissingThumbprint: pinnedKeys entry without
// thumbprint must fail.
func TestPinnedKey_FactoryMissingThumbprint(t *testing.T) {
	t.Parallel()
	_, err := factory("bad", map[string]any{
		"inner": map[string]any{
			"type":   "jwt",
			"config": map[string]any{"jwksUrl": "http://localhost/jwks"},
		},
		"pinnedKeys": []any{
			map[string]any{"kid": "v1"}, // missing thumbprint
		},
	}, module.Deps{})
	if err == nil {
		t.Fatal("expected error for missing thumbprint")
	}
	if !errors.Is(err, module.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}
