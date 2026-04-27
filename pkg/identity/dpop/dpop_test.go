package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/mikeappsec/lightweightauth/internal/cache"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

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

	replay, err := cache.NewLRU(64, 2*skew, nil)
	if err != nil {
		t.Fatalf("replay cache: %v", err)
	}
	id := &identifier{
		name: "dpop-test",
		cfg: Config{
			Required:        true,
			Skew:            skew,
			ReplayCacheSize: 64,
			ProofHeader:     defaultProofHeader,
			BearerHeader:    defaultBearerHeader,
		},
		inner:  inner,
		replay: replay,
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
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{}}, 30*time.Second)
	at := "deadbeef-access-token"
	sum := sha256.Sum256([]byte(at))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-ath", time.Now(), ath)
	if _, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, at)); err != nil {
		t.Fatalf("Identify: %v", err)
	}
}

func TestDPoP_AthBinding_Mismatch(t *testing.T) {
	f := newFixture(t, &stubIdentifier{name: "inner", claims: map[string]any{}}, 30*time.Second)
	proof := f.signProof(t, "GET", "https://api.example/x", "jti-ath-bad", time.Now(), "wrong-ath")
	_, err := f.identity.Identify(context.Background(), req("GET", "api.example", "/x", proof, "the-token"))
	if !errors.Is(err, module.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
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
