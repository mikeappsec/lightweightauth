// Package mtls is the mTLS identifier. It supports two ingestion paths
// (DESIGN.md §4):
//
//  1. In-process TLS termination — the server layer populates
//     Request.PeerCerts with the leaf certificate's DER bytes.
//  2. Upstream termination via Envoy — Envoy forwards the verified peer
//     cert chain in the `x-forwarded-client-cert` (XFCC) header.
//
// The module accepts whichever is available, with PeerCerts winning when
// both are present.
//
// SPIFFE / URI SAN handling: when the certificate carries a `spiffe://`
// URI SAN, that SPIFFE ID is set as the Identity.Subject. Otherwise the
// certificate's CN is used.
package mtls

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/yourorg/lightweightauth/pkg/module"
)

// Config is the YAML/CRD shape.
//
//	type: mtls
//	header:        X-Forwarded-Client-Cert       # default; only consulted if PeerCerts is empty
//	trustedIssuers: ["CN=Corp Root CA"]          # optional, exact-match Subject DN allow-list
type Config struct {
	Header         string   `yaml:"header" json:"header"`
	TrustedIssuers []string `yaml:"trustedIssuers" json:"trustedIssuers"`
}

type identifier struct {
	name           string
	header         string
	trustedIssuers map[string]struct{}
}

func (i *identifier) Name() string { return i.name }

func (i *identifier) Identify(_ context.Context, r *module.Request) (*module.Identity, error) {
	cert, err := i.extractCert(r)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, module.ErrNoMatch
	}
	if len(i.trustedIssuers) > 0 {
		if _, ok := i.trustedIssuers[cert.Issuer.String()]; !ok {
			return nil, fmt.Errorf("%w: mtls: issuer %q not trusted", module.ErrInvalidCredential, cert.Issuer.String())
		}
	}

	subj, spiffeID := subjectFromCert(cert)
	claims := map[string]any{
		"sub":          subj,
		"cn":           cert.Subject.CommonName,
		"issuer":       cert.Issuer.String(),
		"serialNumber": cert.SerialNumber.String(),
		"notBefore":    cert.NotBefore,
		"notAfter":     cert.NotAfter,
	}
	if spiffeID != "" {
		claims["spiffe"] = spiffeID
	}
	if len(cert.DNSNames) > 0 {
		claims["dnsNames"] = anySliceOfStrings(cert.DNSNames)
	}
	return &module.Identity{Subject: subj, Claims: claims, Source: i.name}, nil
}

// extractCert returns the verified peer leaf certificate. It prefers
// Request.PeerCerts (set when lwauth itself terminated TLS) and falls
// back to parsing Envoy's XFCC header.
func (i *identifier) extractCert(r *module.Request) (*x509.Certificate, error) {
	if len(r.PeerCerts) > 0 {
		cert, err := x509.ParseCertificate(r.PeerCerts)
		if err != nil {
			return nil, fmt.Errorf("%w: mtls: parse PeerCerts: %v", module.ErrInvalidCredential, err)
		}
		return cert, nil
	}
	xfcc := r.Header(i.header)
	if xfcc == "" {
		return nil, nil
	}
	return parseXFCC(xfcc)
}

// parseXFCC understands a (very) common subset of Envoy's XFCC header:
//
//	By=...;Hash=...;Cert="<URL-encoded PEM>";Subject="..."
//
// Multiple certs are concatenated with commas; we take the first.
// Reference: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
func parseXFCC(xfcc string) (*x509.Certificate, error) {
	first := xfcc
	if comma := strings.Index(xfcc, ","); comma >= 0 {
		first = xfcc[:comma]
	}
	for _, part := range strings.Split(first, ";") {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		val := strings.TrimSpace(part[eq+1:])
		val = strings.Trim(val, `"`)
		switch key {
		case "cert":
			pemStr, err := url.QueryUnescape(val)
			if err != nil {
				return nil, fmt.Errorf("%w: mtls: xfcc Cert decode: %v", module.ErrInvalidCredential, err)
			}
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				return nil, fmt.Errorf("%w: mtls: xfcc Cert is not PEM", module.ErrInvalidCredential)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%w: mtls: xfcc parse: %v", module.ErrInvalidCredential, err)
			}
			return cert, nil
		}
	}
	return nil, nil
}

func subjectFromCert(c *x509.Certificate) (subject, spiffe string) {
	for _, u := range c.URIs {
		if u.Scheme == "spiffe" {
			s := u.String()
			return s, s
		}
	}
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName, ""
	}
	return c.Subject.String(), ""
}

func anySliceOfStrings(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	hdr := "X-Forwarded-Client-Cert"
	if v, ok := raw["header"].(string); ok && v != "" {
		hdr = v
	}
	trusted := map[string]struct{}{}
	if v, ok := raw["trustedIssuers"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				trusted[s] = struct{}{}
			}
		}
	}
	return &identifier{name: name, header: hdr, trustedIssuers: trusted}, nil
}

func init() { module.RegisterIdentifier("mtls", factory) }
