// Package mtls is the mTLS identifier. It supports two ingestion paths
// (DESIGN.md §4):
//
//  1. In-process TLS termination — the server layer populates
//     Request.PeerCerts with the leaf certificate's DER bytes. Trust
//     here flows from the TLS stack itself; the cert is already
//     verified by the time it reaches us.
//  2. Upstream termination via Envoy / Istio — Envoy forwards the
//     verified peer cert chain in the `x-forwarded-client-cert` (XFCC)
//     header. **Trust on this path is opt-in** (`trustForwardedClientCert`)
//     because anything that can reach the auth surface can otherwise
//     forge identity by setting the header itself.
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
	"os"
	"strings"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// Config is the YAML/CRD shape.
//
//	type: mtls
//	header:        X-Forwarded-Client-Cert       # default; only consulted when trustForwardedClientCert: true
//	trustForwardedClientCert: false              # default; MUST set true to read XFCC
//	trustedCAFiles: ["/etc/lwauth/ca.pem"]       # PEM bundle(s); enables x509 chain verification of XFCC leaves
//	trustedCAs:    "-----BEGIN CERTIFICATE-----..."  # alternative inline PEM bundle
//	trustedIssuers: ["CN=Corp Root CA"]          # optional, secondary Subject-DN allow-list (not a trust check on its own)
type Config struct {
	Header                   string   `yaml:"header" json:"header"`
	TrustForwardedClientCert bool     `yaml:"trustForwardedClientCert" json:"trustForwardedClientCert"`
	TrustedCAFiles           []string `yaml:"trustedCAFiles" json:"trustedCAFiles"`
	TrustedCAs               string   `yaml:"trustedCAs" json:"trustedCAs"`
	TrustedIssuers           []string `yaml:"trustedIssuers" json:"trustedIssuers"`
}

type identifier struct {
	name           string
	header         string
	trustXFCC      bool
	trustedRoots   *x509.CertPool // non-nil ⇒ chain-verify XFCC leaves
	trustedIssuers map[string]struct{}
}

func (i *identifier) Name() string { return i.name }

func (i *identifier) Identify(_ context.Context, r *module.Request) (*module.Identity, error) {
	cert, fromXFCC, err := i.extractCert(r)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, module.ErrNoMatch
	}

	// XFCC leaves are not trusted by the TLS stack — they're whatever
	// bytes the upstream proxy forwarded. When the operator has given
	// us a CA bundle, verify the chain. Without a CA bundle we fall
	// back to the (legacy) Subject-DN allow-list, but that is a weak
	// check by itself — see docs/modules/mtls.md.
	if fromXFCC && i.trustedRoots != nil {
		opts := x509.VerifyOptions{
			Roots:     i.trustedRoots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(opts); err != nil {
			return nil, fmt.Errorf("%w: mtls: xfcc chain verify: %v", module.ErrInvalidCredential, err)
		}
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
// back to parsing Envoy's XFCC header — but only when the operator has
// explicitly opted in via trustForwardedClientCert: true.
//
// fromXFCC is true when the cert came from the header (so the caller
// knows to apply additional verification); false when it came from the
// TLS stack and is already trusted.
func (i *identifier) extractCert(r *module.Request) (cert *x509.Certificate, fromXFCC bool, err error) {
	if len(r.PeerCerts) > 0 {
		c, err := x509.ParseCertificate(r.PeerCerts)
		if err != nil {
			return nil, false, fmt.Errorf("%w: mtls: parse PeerCerts: %v", module.ErrInvalidCredential, err)
		}
		return c, false, nil
	}
	if !i.trustXFCC {
		// Default-deny: do not even look at the header. An attacker who
		// can reach the auth surface cannot forge identity by setting
		// XFCC themselves; operators who front lwauth with a verified
		// proxy hop must opt in (and ideally pin trustedCAFiles).
		return nil, false, nil
	}
	xfcc := r.Header(i.header)
	if xfcc == "" {
		return nil, false, nil
	}
	c, err := parseXFCC(xfcc)
	if err != nil {
		return nil, true, err
	}
	return c, true, nil
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

// loadCAPool builds an x509.CertPool from the optional file list and
// inline PEM bundle. Returns (nil, nil) when the operator supplied
// neither — chain verification is then skipped (the legacy DN
// allow-list path).
func loadCAPool(files []string, inline string) (*x509.CertPool, error) {
	if len(files) == 0 && inline == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("mtls: read trustedCAFiles[%q]: %w", f, err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("mtls: trustedCAFiles[%q] contained no PEM certificates", f)
		}
	}
	if inline != "" {
		if !pool.AppendCertsFromPEM([]byte(inline)) {
			return nil, fmt.Errorf("mtls: trustedCAs inline PEM contained no certificates")
		}
	}
	return pool, nil
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	hdr := "X-Forwarded-Client-Cert"
	if v, ok := raw["header"].(string); ok && v != "" {
		hdr = v
	}
	trustXFCC := false
	if v, ok := raw["trustForwardedClientCert"].(bool); ok {
		trustXFCC = v
	}
	var caFiles []string
	if v, ok := raw["trustedCAFiles"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				caFiles = append(caFiles, s)
			}
		}
	}
	inlinePEM := ""
	if v, ok := raw["trustedCAs"].(string); ok {
		inlinePEM = v
	}
	pool, err := loadCAPool(caFiles, inlinePEM)
	if err != nil {
		return nil, err
	}
	if pool != nil && !trustXFCC {
		// A CA bundle without trustForwardedClientCert is a
		// configuration mistake — the operator clearly meant to enable
		// the XFCC path. Fail closed at compile time so the mistake
		// surfaces during AuthConfig validation, not at request time.
		return nil, fmt.Errorf("mtls: trustedCAFiles/trustedCAs requires trustForwardedClientCert: true")
	}
	trusted := map[string]struct{}{}
	if v, ok := raw["trustedIssuers"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				trusted[s] = struct{}{}
			}
		}
	}
	// Symmetric to the gate above: trustForwardedClientCert: true
	// without ANY anchor (no CA bundle, no issuer allow-list) silently
	// re-enables the original blind-XFCC behavior — anyone able to
	// reach the listener could spoof any subject. Fail closed at
	// compile time so the operator has to make the trust boundary
	// explicit. (SEC-MTLS-1.)
	if trustXFCC && pool == nil && len(trusted) == 0 {
		return nil, fmt.Errorf("mtls: trustForwardedClientCert: true requires at least one anchor (trustedCAFiles, trustedCAs, or trustedIssuers)")
	}
	return &identifier{
		name:           name,
		header:         hdr,
		trustXFCC:      trustXFCC,
		trustedRoots:   pool,
		trustedIssuers: trusted,
	}, nil
}

// RevocationKeys implements module.RevocationChecker for the mTLS identifier.
// It derives keys from the certificate serial number and the identity's subject.
func (i *identifier) RevocationKeys(id *module.Identity, tenantID string) []string {
	if id == nil {
		return nil
	}
	var keys []string

	// Key by certificate serial number — revokes a specific cert.
	if serial, ok := id.Claims["serialNumber"].(string); ok && serial != "" {
		keys = append(keys, "serial:"+serial)
	}

	// Key by subject — revokes ALL certificates for this identity.
	if id.Subject != "" {
		prefix := "sub:"
		if tenantID != "" {
			prefix += tenantID + ":"
		}
		keys = append(keys, prefix+id.Subject)
	}

	return keys
}

func init() { module.RegisterIdentifier("mtls", factory) }
