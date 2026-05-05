// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// testCertPEM generates a self-signed certificate PEM for testing.
func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// validSAMLResponse returns a minimal valid SAML response XML.
func validSAMLResponse(issuer, audience, subject string, notBefore, notAfter time.Time) string {
	return `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` + issuer + `</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer>` + issuer + `</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		`<SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
		`<Reference URI="#assertion"><DigestValue>abc123</DigestValue></Reference></SignedInfo>` +
		`<SignatureValue>fakesig</SignatureValue></Signature>` +
		`<Subject><NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">` + subject + `</NameID></Subject>` +
		`<Conditions NotBefore="` + notBefore.Format(time.RFC3339) + `" NotOnOrAfter="` + notAfter.Format(time.RFC3339) + `">` +
		`<AudienceRestriction><Audience>` + audience + `</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`<AuthnStatement SessionIndex="session-123"/>` +
		`<AttributeStatement>` +
		`<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">` +
		`<AttributeValue>alice@example.com</AttributeValue></Attribute>` +
		`<Attribute Name="http://schemas.xmlsoap.org/claims/Group">` +
		`<AttributeValue>admins</AttributeValue><AttributeValue>users</AttributeValue></Attribute>` +
		`</AttributeStatement>` +
		`</Assertion></Response>`
}

func TestFactory_Valid(t *testing.T) {
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"issuer":              "https://idp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"maxClockSkew":        "1m",
		"attributeMapping": map[string]any{
			"email":  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			"groups": "http://schemas.xmlsoap.org/claims/Group",
		},
	}
	id, err := factory("test-saml", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if id.Name() != "test-saml" {
		t.Errorf("Name = %q, want test-saml", id.Name())
	}
}

func TestFactory_UnknownKey(t *testing.T) {
	raw := map[string]any{
		"idpCertPEM": testCertPEM(t),
		"bogusKey":   "x",
	}
	_, err := factory("x", raw)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestFactory_BadCert(t *testing.T) {
	raw := map[string]any{
		"idpCertPEM": "not-a-pem",
	}
	_, err := factory("x", raw)
	if err == nil {
		t.Fatal("expected error for bad cert PEM")
	}
}

func TestFactory_BadClockSkew(t *testing.T) {
	raw := map[string]any{
		"maxClockSkew": "not-a-duration",
	}
	_, err := factory("x", raw)
	if err == nil {
		t.Fatal("expected error for bad duration")
	}
}

func TestIdentify_NoHeader(t *testing.T) {
	id, _ := factory("test", map[string]any{})
	r := &module.Request{Headers: map[string][]string{}}
	_, err := id.Identify(nil, r)
	if err != module.ErrNoMatch {
		t.Fatalf("expected ErrNoMatch, got %v", err)
	}
}

func TestIdentify_BadBase64(t *testing.T) {
	id, _ := factory("test", map[string]any{})
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {"!!!not-base64!!!"},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestIdentify_InvalidXML(t *testing.T) {
	id, _ := factory("test", map[string]any{})
	encoded := base64.StdEncoding.EncodeToString([]byte("<not-valid-saml>"))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
}

func TestIdentify_IssuerMismatch(t *testing.T) {
	raw := map[string]any{
		"issuer": "https://trusted-idp.com",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse("https://evil-idp.com", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
}

func TestIdentify_Expired(t *testing.T) {
	raw := map[string]any{
		"maxClockSkew": "0s",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse("https://idp.com", "https://sp.com", "alice",
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for expired assertion")
	}
}

func TestIdentify_NotYetValid(t *testing.T) {
	raw := map[string]any{
		"maxClockSkew": "0s",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse("https://idp.com", "https://sp.com", "alice",
		time.Now().Add(2*time.Hour), time.Now().Add(3*time.Hour))
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for not-yet-valid assertion")
	}
}

func TestIdentify_AudienceMismatch(t *testing.T) {
	raw := map[string]any{
		"audienceRestriction": "https://my-sp.com",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse("https://idp.com", "https://other-sp.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
}

func TestIdentify_Valid(t *testing.T) {
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"issuer":              "https://idp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"maxClockSkew":        "5m",
		"attributeMapping": map[string]any{
			"email":  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			"groups": "http://schemas.xmlsoap.org/claims/Group",
		},
	}
	id, err := factory("corp-saml", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	xml := validSAMLResponse("https://idp.example.com", "https://sp.example.com", "alice@corp.com",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "alice@corp.com" {
		t.Errorf("Subject = %q, want alice@corp.com", identity.Subject)
	}
	if identity.Source != "corp-saml" {
		t.Errorf("Source = %q, want corp-saml", identity.Source)
	}
	if identity.Claims["email"] != "alice@example.com" {
		t.Errorf("email claim = %v, want alice@example.com", identity.Claims["email"])
	}
	if identity.Claims["sessionIndex"] != "session-123" {
		t.Errorf("sessionIndex = %v, want session-123", identity.Claims["sessionIndex"])
	}
	groups, ok := identity.Claims["groups"].([]string)
	if !ok || len(groups) != 2 {
		t.Errorf("groups = %v, want [admins users]", identity.Claims["groups"])
	}
}

func TestIdentify_StatusFailure(t *testing.T) {
	id, _ := factory("test", map[string]any{})
	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Subject><NameID>x</NameID></Subject></Assertion></Response>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for non-success status")
	}
}

func TestIdentify_ExpiredCert(t *testing.T) {
	// Generate an expired certificate.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired-idp"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	raw := map[string]any{
		"idpCertPEM": certPEM,
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	xml := validSAMLResponse("https://idp.com", "https://sp.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for expired IdP certificate")
	}
}

func TestIdentify_CustomHeader(t *testing.T) {
	raw := map[string]any{
		"header": "X-Custom-SAML",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse("https://idp.com", "", "bob",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	r := &module.Request{Headers: map[string][]string{
		"X-Custom-Saml": {encoded},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify with custom header: %v", err)
	}
	if identity.Subject != "bob" {
		t.Errorf("Subject = %q, want bob", identity.Subject)
	}
}

func TestIdentify_NoSignatureNoCert(t *testing.T) {
	// Without a configured cert, signature verification is skipped (dev mode).
	id, _ := factory("test", map[string]any{})
	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Subject><NameID>alice</NameID></Subject>` +
		`<Conditions NotBefore="` + time.Now().Add(-time.Minute).Format(time.RFC3339) + `" NotOnOrAfter="` + time.Now().Add(time.Hour).Format(time.RFC3339) + `"/>` +
		`</Assertion></Response>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", identity.Subject)
	}
}

func TestIdentify_BadAlgorithm(t *testing.T) {
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM": certPEM,
	}
	id, _ := factory("test", raw)
	// Response with a bad signature algorithm.
	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		`<SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>` +
		`<Reference URI="#x"><DigestValue>abc</DigestValue></Reference></SignedInfo>` +
		`<SignatureValue>fakesig</SignatureValue></Signature>` +
		`<Subject><NameID>alice</NameID></Subject>` +
		`<Conditions NotBefore="` + time.Now().Add(-time.Minute).Format(time.RFC3339) + `" NotOnOrAfter="` + time.Now().Add(time.Hour).Format(time.RFC3339) + `"/>` +
		`</Assertion></Response>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for bad signature algorithm")
	}
}
