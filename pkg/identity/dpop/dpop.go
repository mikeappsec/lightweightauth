// Package dpop implements RFC 9449 — OAuth 2.0 Demonstrating Proof of
// Possession (DPoP). It is a wrapper-style identifier: it does not
// produce identities itself, but binds an inner bearer-token identifier
// (typically `jwt` or `oauth2-introspection`) to a client-held key so
// that a leaked access token cannot be replayed by a third party.
//
// Configuration:
//
//	identifiers:
//	  - name: corp-jwt-dpop
//	    type: dpop
//	    config:
//	      required: true              # default true; when false a
//	                                   # missing DPoP header passes through
//	                                   # to the inner identifier as a plain bearer.
//	      skew: 30s                   # default 30s on iat
//	      replayCacheSize: 10000      # default 10000
//	      proofHeader: DPoP           # default DPoP
//	      bearerHeader: Authorization # default Authorization, used to
//	                                   # compute `ath` and to detect
//	                                   # whether the inner identifier
//	                                   # received a token
//	      inner:
//	        type: jwt
//	        config:
//	          jwksUrl: https://idp.example/.well-known/jwks.json
//	          audiences: [api.example]
//
// Verification (per RFC 9449 §4.3):
//   1. The `DPoP` header carries exactly one compact JWS.
//   2. Its protected header contains `typ=dpop+jwt`, an asymmetric `alg`
//      (HMAC and `none` are rejected outright per §4.2 step 4), and a
//      single embedded `jwk` that is a public key.
//   3. Signature verifies under that JWK.
//   4. Payload claims:
//        htm = request method (case-insensitive),
//        htu = request URL ignoring query/fragment (§4.3 step 9),
//        iat is within ±skew,
//        jti is unique within a replay window (jti+skew*2 retained).
//   5. When the inner identifier surfaces `cnf.jkt` (RFC 7800), the
//      RFC-7638 thumbprint of the embedded JWK MUST equal it.
//   6. When an access token is present on the request, the proof's
//      `ath` claim MUST equal base64url(sha256(access_token)).
package dpop

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yourorg/lightweightauth/internal/cache"
	"github.com/yourorg/lightweightauth/pkg/module"
)

const (
	defaultSkew         = 30 * time.Second
	defaultReplayEntries = 10_000
	defaultProofHeader  = "DPoP"
	defaultBearerHeader = "Authorization"
	dpopJWTType          = "dpop+jwt"
)

// Config is the YAML/CRD shape understood by the dpop identifier.
type Config struct {
	Required        bool
	Skew            time.Duration
	ReplayCacheSize int
	ProofHeader     string
	BearerHeader    string
	Inner           InnerSpec
}

// InnerSpec names the wrapped identifier. The dpop identifier resolves
// it lazily through module.BuildIdentifier so any registered identifier
// type can be wrapped without import cycles.
type InnerSpec struct {
	Type   string
	Name   string
	Config map[string]any
}

type identifier struct {
	name    string
	cfg     Config
	inner   module.Identifier
	replay  *cache.LRU
	now     func() time.Time
}

func (i *identifier) Name() string { return i.name }

// Identify is the wrapper entrypoint. The flow:
//
//   1. If no DPoP header is present:
//        - required=true  → ErrInvalidCredential.
//        - required=false → fall through to inner.Identify so this
//                            identifier behaves transparently when DPoP
//                            is opt-in per route.
//   2. Otherwise verify the proof and only then defer to inner.Identify.
//      Failures from inner are returned as-is (ErrNoMatch lets the next
//      configured identifier try, ErrInvalidCredential is fatal for
//      this identifier).
//   3. After inner returns identity, optionally check `cnf.jkt` and
//      `ath` to enforce the proof-of-possession binding.
func (i *identifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
	proof := r.Header(i.cfg.ProofHeader)
	if proof == "" {
		if i.cfg.Required {
			return nil, fmt.Errorf("%w: dpop: missing %s header", module.ErrInvalidCredential, i.cfg.ProofHeader)
		}
		return i.inner.Identify(ctx, r)
	}

	jwkProof, claims, err := i.verifyProof(ctx, proof, r)
	if err != nil {
		return nil, err
	}

	id, err := i.inner.Identify(ctx, r)
	if err != nil {
		return nil, err
	}

	// Confirmation-claim binding (RFC 9449 §6.1 / RFC 7800 cnf.jkt).
	if jkt, ok := extractCnfJkt(id); ok {
		thumb, terr := jwkThumbprintB64(jwkProof)
		if terr != nil {
			return nil, fmt.Errorf("%w: dpop: thumbprint: %v", module.ErrInvalidCredential, terr)
		}
		if thumb != jkt {
			return nil, fmt.Errorf("%w: dpop: cnf.jkt mismatch", module.ErrInvalidCredential)
		}
	}

	// ath binding (RFC 9449 §4.3 step 11). Computed against whatever
	// bearer token sat on the request — that is the only thing the
	// inner identifier was allowed to validate.
	if at := bearerToken(r, i.cfg.BearerHeader); at != "" {
		gotAth, _ := claims["ath"].(string)
		wantAth := base64.RawURLEncoding.EncodeToString(sha256sum(at))
		if gotAth == "" || gotAth != wantAth {
			return nil, fmt.Errorf("%w: dpop: ath mismatch", module.ErrInvalidCredential)
		}
	}
	return id, nil
}

// verifyProof handles steps 1-10 of RFC 9449 §4.3.
func (i *identifier) verifyProof(ctx context.Context, proof string, r *module.Request) (jwk.Key, map[string]any, error) {
	// We use jwt.WithKeyProvider so we get header inspection + signature
	// verification + claim parsing in a single jwt.ParseString call.
	var hdrJWK jwk.Key
	tok, err := jwtlib.ParseString(
		proof,
		jwtlib.WithKeyProvider(jws.KeyProviderFunc(func(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
			hdr := sig.ProtectedHeaders()
			if typ := hdr.Type(); typ != dpopJWTType {
				return fmt.Errorf("typ=%q, want %q", typ, dpopJWTType)
			}
			alg := hdr.Algorithm()
			if !isAsymmetricAlg(alg) {
				return fmt.Errorf("alg %q not allowed for dpop proof", alg)
			}
			k := hdr.JWK()
			if k == nil {
				return errors.New("missing embedded jwk")
			}
			// Reject keys carrying private parameters — DPoP §4.2
			// requires a public JWK. jwx exposes Thumbprint on Key
			// which works on either a private or public key, so the
			// safest check is to round-trip via PublicKeyOf and use
			// only the resulting public.
			pub, perr := jwk.PublicKeyOf(k)
			if perr != nil {
				return fmt.Errorf("jwk: %v", perr)
			}
			hdrJWK = pub
			sink.Key(alg, pub)
			return nil
		})),
		jwtlib.WithValidate(false), // we enforce iat ourselves to apply skew
	)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: dpop proof verify: %v", module.ErrInvalidCredential, err)
	}

	claims, _ := tok.AsMap(ctx)

	// htm, htu, iat, jti per §4.3.
	gotMethod, _ := claims["htm"].(string)
	if !strings.EqualFold(gotMethod, r.Method) {
		return nil, nil, fmt.Errorf("%w: dpop: htm mismatch (got %q, want %q)", module.ErrInvalidCredential, gotMethod, r.Method)
	}
	gotURL, _ := claims["htu"].(string)
	if err := matchHTU(gotURL, r); err != nil {
		return nil, nil, fmt.Errorf("%w: dpop: htu: %v", module.ErrInvalidCredential, err)
	}

	iat := tok.IssuedAt()
	if iat.IsZero() {
		return nil, nil, fmt.Errorf("%w: dpop: missing iat", module.ErrInvalidCredential)
	}
	now := i.now()
	if delta := now.Sub(iat); delta > i.cfg.Skew || delta < -i.cfg.Skew {
		return nil, nil, fmt.Errorf("%w: dpop: iat outside skew (delta=%s)", module.ErrInvalidCredential, delta)
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, nil, fmt.Errorf("%w: dpop: missing jti", module.ErrInvalidCredential)
	}
	if _, hit, _ := i.replay.Get(ctx, jti); hit {
		return nil, nil, fmt.Errorf("%w: dpop: jti replay", module.ErrInvalidCredential)
	}
	// TTL = iat + 2*skew, bounded so a far-future iat can't keep an
	// entry alive forever.
	ttl := time.Until(iat.Add(2 * i.cfg.Skew))
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 2 * i.cfg.Skew
	}
	_ = i.replay.Set(ctx, jti, []byte{1}, ttl)

	return hdrJWK, claims, nil
}

// matchHTU compares the proof's htu to the request URL ignoring query
// and fragment per §4.3 step 9. We compose the request URL from the
// request's Host + Path; scheme is taken from X-Forwarded-Proto if
// present, else the htu's own scheme is accepted (we cannot know
// whether the connection terminated as TLS at lwauth or upstream of
// it, and §4.3 only requires the URLs to match — not that we mint our
// own canonical form).
func matchHTU(got string, r *module.Request) error {
	if got == "" {
		return errors.New("missing htu")
	}
	u, err := url.Parse(got)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("htu must be absolute, got %q", got)
	}
	// Drop query + fragment for comparison.
	u.RawQuery = ""
	u.Fragment = ""

	if !strings.EqualFold(u.Host, r.Host) {
		return fmt.Errorf("host mismatch (got %q, want %q)", u.Host, r.Host)
	}
	wantPath := r.Path
	if wantPath == "" {
		wantPath = "/"
	}
	gotPath := u.Path
	if gotPath == "" {
		gotPath = "/"
	}
	if gotPath != wantPath {
		return fmt.Errorf("path mismatch (got %q, want %q)", gotPath, wantPath)
	}
	if xfp := r.Header("X-Forwarded-Proto"); xfp != "" {
		if !strings.EqualFold(u.Scheme, xfp) {
			return fmt.Errorf("scheme mismatch (got %q, want %q)", u.Scheme, xfp)
		}
	}
	return nil
}

// isAsymmetricAlg reports whether alg is suitable for DPoP signatures.
// DPoP §4.2 step 4 rejects HMAC algorithms (the verifier must hold the
// private key, defeating proof-of-possession) and the unsigned `none`
// alg.
func isAsymmetricAlg(alg jwa.SignatureAlgorithm) bool {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512,
		jwa.PS256, jwa.PS384, jwa.PS512,
		jwa.ES256, jwa.ES384, jwa.ES512, jwa.ES256K,
		jwa.EdDSA:
		return true
	default:
		return false
	}
}

// jwkThumbprintB64 returns the RFC 7638 SHA-256 thumbprint of k as
// base64url-no-pad (the form used by `cnf.jkt`).
func jwkThumbprintB64(k jwk.Key) (string, error) {
	t, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(t), nil
}

// extractCnfJkt pulls cnf.jkt out of an Identity's claims. Tolerates
// either a nested map or a flattened "cnf.jkt" string (some IdPs
// flatten claims for convenience).
func extractCnfJkt(id *module.Identity) (string, bool) {
	if id == nil || id.Claims == nil {
		return "", false
	}
	if v, ok := id.Claims["cnf"].(map[string]any); ok {
		if s, ok := v["jkt"].(string); ok && s != "" {
			return s, true
		}
	}
	if s, ok := id.Claims["cnf.jkt"].(string); ok && s != "" {
		return s, true
	}
	return "", false
}

func bearerToken(r *module.Request, header string) string {
	v := r.Header(header)
	if v == "" {
		return ""
	}
	const bearer = "bearer "
	if len(v) > len(bearer) && strings.EqualFold(v[:len(bearer)], bearer) {
		return strings.TrimSpace(v[len(bearer):])
	}
	// DPoP also defines a `DPoP` token-type for the Authorization
	// header (§7); accept it the same way.
	const dpop = "dpop "
	if len(v) > len(dpop) && strings.EqualFold(v[:len(dpop)], dpop) {
		return strings.TrimSpace(v[len(dpop):])
	}
	return ""
}

func sha256sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	cfg := Config{
		Required:        true,
		Skew:            defaultSkew,
		ReplayCacheSize: defaultReplayEntries,
		ProofHeader:     defaultProofHeader,
		BearerHeader:    defaultBearerHeader,
	}
	if v, ok := raw["required"].(bool); ok {
		cfg.Required = v
	}
	if d, ok := durationFrom(raw, "skew"); ok {
		cfg.Skew = d
	}
	if v, ok := raw["replayCacheSize"].(int); ok && v > 0 {
		cfg.ReplayCacheSize = v
	}
	if v, ok := raw["proofHeader"].(string); ok && v != "" {
		cfg.ProofHeader = v
	}
	if v, ok := raw["bearerHeader"].(string); ok && v != "" {
		cfg.BearerHeader = v
	}

	innerRaw, ok := raw["inner"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: dpop %q: inner identifier is required", module.ErrConfig, name)
	}
	cfg.Inner.Type, _ = innerRaw["type"].(string)
	if cfg.Inner.Type == "" {
		return nil, fmt.Errorf("%w: dpop %q: inner.type is required", module.ErrConfig, name)
	}
	cfg.Inner.Name, _ = innerRaw["name"].(string)
	if cfg.Inner.Name == "" {
		cfg.Inner.Name = name + "-inner"
	}
	cfg.Inner.Config, _ = innerRaw["config"].(map[string]any)
	if cfg.Inner.Config == nil {
		cfg.Inner.Config = map[string]any{}
	}

	inner, err := module.BuildIdentifier(cfg.Inner.Type, cfg.Inner.Name, cfg.Inner.Config)
	if err != nil {
		return nil, fmt.Errorf("%w: dpop %q inner %q: %v", module.ErrConfig, name, cfg.Inner.Type, err)
	}

	replay, err := cache.NewLRU(cfg.ReplayCacheSize, 2*cfg.Skew, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: dpop %q replay cache: %v", module.ErrConfig, name, err)
	}

	return &identifier{
		name:   name,
		cfg:    cfg,
		inner:  inner,
		replay: replay,
		now:    time.Now,
	}, nil
}

func durationFrom(raw map[string]any, key string) (time.Duration, bool) {
	if v, ok := raw[key].(string); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d, true
		}
	}
	return 0, false
}

func init() { module.RegisterIdentifier("dpop", factory) }
