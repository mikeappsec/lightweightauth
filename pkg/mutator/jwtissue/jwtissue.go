// Package jwtissue is the response mutator that mints an internal JWT
// for the upstream service (DESIGN.md §4 / M6).
//
// Common use case: lwauth fronts a Go service that wants a uniformly
// signed token regardless of how the user authenticated (api-key, mTLS,
// OAuth2, ...). On allow, this mutator issues a short-lived JWT signed
// with a key it owns and adds it as `Authorization: Bearer ...` (or any
// configured header) to the upstream-bound headers.
//
// Config shape:
//
//	response:
//	  - name: upstream-jwt
//	    type: jwt-issue
//	    config:
//	      issuer:    lwauth                  # required
//	      audience:  api.internal             # required
//	      ttl:       60s                      # default
//	      algorithm: HS256                    # HS256 (default) | RS256
//	      key:       hex:<32+ bytes>          # for HS256
//	      # OR
//	      privateKeyFile: /etc/lwauth/jwt.key # for RS256 (PKCS#1 / PKCS#8 PEM)
//	      header:    Authorization            # default
//	      scheme:    Bearer                   # default
//	      copyClaims: [email, roles]          # optional, copied from Identity.Claims
package jwtissue

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yourorg/lightweightauth/pkg/module"
)

type mutator struct {
	name       string
	issuer     string
	audience   string
	ttl        time.Duration
	alg        jwa.SignatureAlgorithm
	signKey    jwk.Key
	header     string
	scheme     string
	copyClaims []string
}

func (m *mutator) Name() string { return m.name }

func (m *mutator) Mutate(_ context.Context, _ *module.Request, id *module.Identity, d *module.Decision) error {
	if id == nil || id.Subject == "" {
		return nil
	}
	now := time.Now()
	tok, err := jwtlib.NewBuilder().
		Issuer(m.issuer).
		Audience([]string{m.audience}).
		Subject(id.Subject).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(m.ttl)).
		Build()
	if err != nil {
		return fmt.Errorf("jwt-issue: build: %w", err)
	}
	for _, k := range m.copyClaims {
		if v, ok := id.Claims[k]; ok {
			_ = tok.Set(k, v)
		}
	}
	signed, err := jwtlib.Sign(tok, jwtlib.WithKey(m.alg, m.signKey))
	if err != nil {
		return fmt.Errorf("jwt-issue: sign: %w", err)
	}
	if d.UpstreamHeaders == nil {
		d.UpstreamHeaders = map[string]string{}
	}
	val := string(signed)
	if m.scheme != "" {
		val = m.scheme + " " + val
	}
	d.UpstreamHeaders[m.header] = val
	return nil
}

func factory(name string, raw map[string]any) (module.ResponseMutator, error) {
	issuer, _ := raw["issuer"].(string)
	audience, _ := raw["audience"].(string)
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("%w: jwt-issue %q: issuer and audience are required", module.ErrConfig, name)
	}
	ttl := 60 * time.Second
	if v, ok := raw["ttl"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%w: jwt-issue.ttl: %v", module.ErrConfig, err)
		}
		ttl = d
	}
	algName, _ := raw["algorithm"].(string)
	if algName == "" {
		algName = "HS256"
	}
	alg, err := parseAlg(algName)
	if err != nil {
		return nil, fmt.Errorf("%w: jwt-issue %q: %v", module.ErrConfig, name, err)
	}
	key, err := loadKey(name, alg, raw)
	if err != nil {
		return nil, err
	}
	hdr := "Authorization"
	if v, ok := raw["header"].(string); ok && v != "" {
		hdr = v
	}
	scheme := "Bearer"
	if v, ok := raw["scheme"].(string); ok {
		scheme = v
	}
	var copyClaims []string
	if v, ok := raw["copyClaims"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok {
				copyClaims = append(copyClaims, s)
			}
		}
	}
	return &mutator{
		name: name, issuer: issuer, audience: audience, ttl: ttl,
		alg: alg, signKey: key, header: hdr, scheme: scheme,
		copyClaims: copyClaims,
	}, nil
}

func parseAlg(name string) (jwa.SignatureAlgorithm, error) {
	switch strings.ToUpper(name) {
	case "HS256":
		return jwa.HS256, nil
	case "HS384":
		return jwa.HS384, nil
	case "HS512":
		return jwa.HS512, nil
	case "RS256":
		return jwa.RS256, nil
	case "RS384":
		return jwa.RS384, nil
	case "RS512":
		return jwa.RS512, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %q", name)
	}
}

func loadKey(name string, alg jwa.SignatureAlgorithm, raw map[string]any) (jwk.Key, error) {
	switch alg {
	case jwa.HS256, jwa.HS384, jwa.HS512:
		secret, _ := raw["key"].(string)
		if secret == "" {
			return nil, fmt.Errorf("%w: jwt-issue %q: HS* requires `key`", module.ErrConfig, name)
		}
		bytes, err := decodeSecret(secret)
		if err != nil {
			return nil, fmt.Errorf("%w: jwt-issue %q: key: %v", module.ErrConfig, name, err)
		}
		k, err := jwk.FromRaw(bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: jwt-issue %q: jwk: %v", module.ErrConfig, name, err)
		}
		return k, nil
	case jwa.RS256, jwa.RS384, jwa.RS512:
		path, _ := raw["privateKeyFile"].(string)
		if path == "" {
			return nil, fmt.Errorf("%w: jwt-issue %q: RS* requires `privateKeyFile`", module.ErrConfig, name)
		}
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: jwt-issue %q: read key: %v", module.ErrConfig, name, err)
		}
		priv, err := parseRSAPrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: jwt-issue %q: parse key: %v", module.ErrConfig, name, err)
		}
		k, err := jwk.FromRaw(priv)
		if err != nil {
			return nil, fmt.Errorf("%w: jwt-issue %q: jwk: %v", module.ErrConfig, name, err)
		}
		return k, nil
	}
	return nil, fmt.Errorf("unsupported algorithm")
}

func decodeSecret(s string) ([]byte, error) {
	if strings.HasPrefix(s, "hex:") {
		return hex.DecodeString(strings.TrimPrefix(s, "hex:"))
	}
	return []byte(s), nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not PEM-encoded")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := k.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("PKCS#8 key is not RSA")
	}
	return nil, errors.New("unrecognised PEM (need PKCS#1 or PKCS#8 RSA)")
}

func init() { module.RegisterMutator("jwt-issue", factory) }
