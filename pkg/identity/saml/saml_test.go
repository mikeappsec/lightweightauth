// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// testKeyPair generates a self-signed certificate PEM and its private key for testing.
func testKeyPair(t *testing.T) (certPEM string, key *ecdsa.PrivateKey) {
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
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return certPEM, key
}

// testCertPEM generates a self-signed certificate PEM for testing (no key returned).
func testCertPEM(t *testing.T) string {
	t.Helper()
	certPEM, _ := testKeyPair(t)
	return certPEM
}

// signSignedInfo signs the SignedInfo XML bytes with the given ECDSA key using SHA-256.
func signSignedInfo(t *testing.T, key *ecdsa.PrivateKey, signedInfoXML string) string {
	t.Helper()
	h := sha256.Sum256([]byte(signedInfoXML))
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// buildSignedInfo constructs a <SignedInfo> element referencing the given
// assertion ID with the real SHA-256 digest of the assertion content.
func buildSignedInfo(refURI string, digestB64 string) string {
	return `<SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>` +
		`<Reference URI="` + refURI + `"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<DigestValue>` + digestB64 + `</DigestValue></Reference></SignedInfo>`
}

// validSAMLResponse returns a minimal valid SAML response XML with a real
// cryptographic signature. If key is nil, uses "fakesig" (for tests that
// expect signature verification failure).
func validSAMLResponse(t *testing.T, issuer, audience, subject string, notBefore, notAfter time.Time, key *ecdsa.PrivateKey) string {
	return validSAMLResponseWithID(t, "_assert-"+t.Name(), issuer, audience, subject, notBefore, notAfter, key)
}

func validSAMLResponseWithID(t *testing.T, assertionID, issuer, audience, subject string, notBefore, notAfter time.Time, key *ecdsa.PrivateKey) string {
	t.Helper()

	notOnOrAfterAttr := ""
	if !notAfter.IsZero() {
		notOnOrAfterAttr = ` NotOnOrAfter="` + notAfter.Format(time.RFC3339) + `"`
	}
	notBeforeAttr := ""
	if !notBefore.IsZero() {
		notBeforeAttr = ` NotBefore="` + notBefore.Format(time.RFC3339) + `"`
	}
	idAttr := ""
	if assertionID != "" {
		idAttr = ` ID="` + assertionID + `"`
	}

	// Build assertion content WITHOUT the Signature element (this is
	// what gets digested per the enveloped-signature transform).
	scNotOnOrAfter := notAfter.Format(time.RFC3339)
	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"` + idAttr + `>` +
		`<Issuer>` + issuer + `</Issuer>` +
		`<Subject><NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">` + subject + `</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData Recipient="` + audience + `" NotOnOrAfter="` + scNotOnOrAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions` + notBeforeAttr + notOnOrAfterAttr + `>` +
		`<AudienceRestriction><Audience>` + audience + `</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`<AuthnStatement SessionIndex="session-123"/>` +
		`<AttributeStatement>` +
		`<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">` +
		`<AttributeValue>alice@example.com</AttributeValue></Attribute>` +
		`<Attribute Name="http://schemas.xmlsoap.org/claims/Group">` +
		`<AttributeValue>admins</AttributeValue><AttributeValue>users</AttributeValue></Attribute>` +
		`</AttributeStatement>` +
		`</Assertion>`

	// Compute the digest of the assertion content (enveloped-sig transform
	// means we hash the assertion without the Signature element).
	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Build the Reference URI.
	refURI := ""
	if assertionID != "" {
		refURI = "#" + assertionID
	}

	// Build SignedInfo with the real digest.
	signedInfoXML := buildSignedInfo(refURI, digestB64)

	// Sign the SignedInfo or use a fake signature for negative tests.
	sigValue := "fakesig"
	if key != nil {
		sigValue = signSignedInfo(t, key, signedInfoXML)
	}

	// Destination attribute matches the audience (entityId) for POST binding.
	destAttr := ""
	if audience != "" {
		destAttr = ` Destination="` + audience + `"`
	}

	// Build the full assertion WITH the embedded Signature.
	return `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"` + destAttr + ` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` + issuer + `</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"` + idAttr + `>` +
		`<Issuer>` + issuer + `</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject><NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">` + subject + `</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData Recipient="` + audience + `" NotOnOrAfter="` + scNotOnOrAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions` + notBeforeAttr + notOnOrAfterAttr + `>` +
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
		"audienceRestriction": "https://sp.example.com",
		"issuer":              "https://idp.example.com",
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
		"idpCertPEM":   testCertPEM(t),
		"maxClockSkew": "not-a-duration",
	}
	_, err := factory("x", raw)
	if err == nil {
		t.Fatal("expected error for bad duration")
	}
}

func TestFactory_MissingCert(t *testing.T) {
	raw := map[string]any{}
	_, err := factory("x", raw)
	if err == nil {
		t.Fatal("expected error when idpCertPEM is missing")
	}
}

func TestIdentify_NoHeader(t *testing.T) {
	id, _ := factory("test", map[string]any{"idpCertPEM": testCertPEM(t), "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"})
	r := &module.Request{Headers: map[string][]string{}}
	_, err := id.Identify(nil, r)
	if err != module.ErrNoMatch {
		t.Fatalf("expected ErrNoMatch, got %v", err)
	}
}

func TestIdentify_BadBase64(t *testing.T) {
	id, _ := factory("test", map[string]any{"idpCertPEM": testCertPEM(t), "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"})
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {"!!!not-base64!!!"},
	}}
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestIdentify_InvalidXML(t *testing.T) {
	id, _ := factory("test", map[string]any{"idpCertPEM": testCertPEM(t), "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"})
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
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"issuer":              "https://trusted-idp.com",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse(t, "https://evil-idp.com", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
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
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"maxClockSkew":        "0s",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse(t, "https://idp.com", "https://sp.com", "alice",
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil)
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
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"maxClockSkew":        "0s",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse(t, "https://idp.com", "https://sp.com", "alice",
		time.Now().Add(2*time.Hour), time.Now().Add(3*time.Hour), nil)
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
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://my-sp.com",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse(t, "https://idp.com", "https://other-sp.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
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
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"issuer":              "https://idp.example.com",
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
	xml := validSAMLResponse(t, "https://idp.example.com", "https://sp.example.com", "alice@corp.com",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), key)
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

func TestIdentify_ForgedSignatureRejected(t *testing.T) {
	// PoC for G9-01: a forged signature must be rejected.
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	// Use nil key - produces "fakesig" which is not a valid cryptographic signature.
	xml := validSAMLResponse(t, "https://idp.com", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
	encoded := base64.StdEncoding.EncodeToString([]byte(xml))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error: forged signature must be rejected")
	}
}

func TestIdentify_StatusFailure(t *testing.T) {
	id, _ := factory("test", map[string]any{"idpCertPEM": testCertPEM(t), "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"})
	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
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
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	xml := validSAMLResponse(t, "https://idp.com", "https://sp.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), key)
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
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"header":              "X-Custom-SAML",
	}
	id, _ := factory("test", raw)
	xml := validSAMLResponse(t, "https://idp.com", "https://sp.example.com", "bob",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), key)
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

func TestIdentify_NoSignaturePresent(t *testing.T) {
	// With cert configured, missing signature must be rejected.
	certPEM := testCertPEM(t)
	id, _ := factory("test", map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"})
	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
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
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error: assertions without signature must be rejected")
	}
}

func TestIdentify_BadAlgorithm(t *testing.T) {
	certPEM := testCertPEM(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, _ := factory("test", raw)
	// Response with a bad signature algorithm.
	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
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

func TestIdentify_XSWSignatureWrapping(t *testing.T) {
	// G9-04 regression: Ensure extractSignedInfo only extracts from the
	// correct <Signature> block (the one containing the verified
	// SignatureValue), not an attacker-injected one elsewhere in the doc.
	//
	// Attack scenario: attacker injects a second <SignedInfo> with different
	// digest references into the document OUTSIDE the legitimate Signature.
	// Old code (bytes.Index on full doc) would pick up the injected one.
	// Fixed code searches only within the Signature block matching the
	// SignatureValue being verified.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute).Format(time.RFC3339)
	notAfter := time.Now().Add(time.Hour).Format(time.RFC3339)

	// Build assertion content (without Signature) to compute real digest.
	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xsw-test">` +
		`<Issuer>idp</Issuer>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion>`
	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	signedInfoXML := buildSignedInfo("#_xsw-test", digestB64)
	legitimateSig := signSignedInfo(t, key, signedInfoXML)

	// The response has NO response-level signature, but the assertion has one.
	// We also inject a bare <SignedInfo> element BEFORE the assertion to
	// simulate an XSW injection. Old code would grab this injected one.
	injectedSignedInfo := `<SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>` +
		`<Reference URI="#evil"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<DigestValue>INJECTED_EVIL</DigestValue></Reference></SignedInfo>`

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		// Inject a bare SignedInfo (not inside a Signature) to confuse first-match search:
		`<!-- injected -->` + injectedSignedInfo +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xsw-test">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + legitimateSig + `</SignatureValue></Signature>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore +
		`" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}

	// The fix ensures extractSignedInfo searches within the <Signature>
	// block containing our SignatureValue, ignoring the injected bare
	// <SignedInfo>. This should succeed because the real signature is valid.
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("XSW regression: should verify using correct SignedInfo from the matching Signature block: %v", err)
	}
	if identity.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", identity.Subject)
	}
}

func TestIdentify_MalformedTimestampRejected(t *testing.T) {
	// G9-05 regression: Malformed timestamps must cause rejection,
	// not silent bypass.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// Use a dummy SignedInfo -this test fails before sig verification
	// due to malformed timestamps, so the digest value doesn't matter.
	dummySignedInfo := `<SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>` +
		`<Reference URI="#_malformed-ts"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<DigestValue>dW51c2Vk</DigestValue></Reference></SignedInfo>`
	sigValue := signSignedInfo(t, key, dummySignedInfo)

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_malformed-ts">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		dummySignedInfo +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject><NameID>alice</NameID></Subject>` +
		`<Conditions NotBefore="not-a-date" NotOnOrAfter="also-not-a-date"/>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for malformed timestamp")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error = %v, want mention of 'malformed'", err)
	}
}

func TestIdentify_MissingNotOnOrAfterRejected(t *testing.T) {
	// G9-05 regression: Missing NotOnOrAfter must be rejected because
	// without it, assertions never expire and replay becomes trivial.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponseWithID(t, "_no-expiry", "idp", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Time{}, key) // zero notAfter -no NotOnOrAfter attr

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for missing NotOnOrAfter")
	}
	if !strings.Contains(err.Error(), "NotOnOrAfter") {
		t.Errorf("error = %v, want mention of NotOnOrAfter", err)
	}
}

func TestIdentify_ReplayRejected(t *testing.T) {
	// G9-06 regression: Same assertion ID consumed twice must be rejected.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponse(t, "idp", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}

	// First call should succeed.
	_, err = id.Identify(nil, r)
	if err != nil {
		t.Fatalf("first Identify should succeed: %v", err)
	}

	// Second call with same assertion should be rejected as replay.
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected replay rejection on second Identify")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Errorf("error = %v, want mention of 'replay'", err)
	}
}

func TestIdentify_MissingAssertionIDRejected(t *testing.T) {
	// G9-06/G9-07 regression: Assertion without ID attribute must be rejected.
	// With digest verification (G9-07), if the Reference URI is empty it
	// resolves to the full document which won't match the assertion digest,
	// so the rejection may come from digest verification or from the ID check.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponseWithID(t, "", "idp", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for missing assertion ID")
	}
	// Accepted errors: digest mismatch (G9-07 catches it first) or no ID attribute (G9-06).
	errMsg := err.Error()
	if !strings.Contains(errMsg, "no ID attribute") && !strings.Contains(errMsg, "digest mismatch") && !strings.Contains(errMsg, "tampered") {
		t.Errorf("error = %v, want mention of ID or digest issue", err)
	}
}

func TestIdentify_TamperedAssertionContentRejected(t *testing.T) {
	// G9-07 regression: Modifying assertion content (e.g., changing the
	// subject) after signing MUST be detected via digest verification.
	// The attacker has a valid signature over the original SignedInfo, but
	// the Assertion content was changed so the digest no longer matches.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(5 * time.Minute)

	// Build a legitimate response for "alice".
	legitimateXML := validSAMLResponse(t, "idp", "https://sp.example.com", "alice", notBefore, notAfter, key)

	// Tamper: replace alice with admin in the assertion.
	tamperedXML := strings.Replace(legitimateXML, ">alice<", ">admin<", 1)
	if tamperedXML == legitimateXML {
		t.Fatal("tampering failed -test is broken")
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(tamperedXML))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for tampered assertion content")
	}
	if !strings.Contains(err.Error(), "digest mismatch") && !strings.Contains(err.Error(), "tampered") {
		t.Errorf("error = %v, want mention of digest mismatch or tampering", err)
	}
}

func TestIdentify_XSWForgedFirstAssertion(t *testing.T) {
	// G9-VULN-01: An attacker injects a forged assertion as the first
	// <Assertion> child of <Response>, and hides the legitimately signed
	// assertion inside a wrapper. xml.Unmarshal picks the first Assertion,
	// but the signature covers the second one. The fix validates that
	// the Reference URI in the signature targets resp.Assertion.ID.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute).Format(time.RFC3339)
	notAfter := time.Now().Add(time.Hour).Format(time.RFC3339)

	// Build the REAL assertion that will be signed (hidden).
	realAssertionID := "_real-signed-assertion"
	realAssertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + realAssertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Subject><NameID>legitimate-user</NameID></Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion>`
	digest := sha256.Sum256([]byte(realAssertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])
	signedInfoXML := buildSignedInfo("#"+realAssertionID, digestB64)
	sigValue := signSignedInfo(t, key, signedInfoXML)

	// XSW attack: forged assertion is first child, signed assertion is hidden.
	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		// FORGED assertion (first child -this is what xml.Unmarshal picks)
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged-evil">` +
		`<Issuer>idp</Issuer>` +
		`<Subject><NameID>attacker@evil.com</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion>` +
		// Real signed assertion hidden in Extensions
		`<Extensions>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + realAssertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject><NameID>legitimate-user</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion>` +
		`</Extensions>` +
		`</Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection: signature does not cover the deserialized assertion")
	}
	// The attack is blocked -either because no signature is found in the
	// forged assertion, or because the signature reference doesn't match.
	// Both outcomes prevent impersonation.
	errStr := err.Error()
	if !strings.Contains(errStr, "XSW") &&
		!strings.Contains(errStr, "does not cover") &&
		!strings.Contains(errStr, "no signature") {
		t.Errorf("error = %v, want mention of XSW, 'does not cover', or 'no signature'", err)
	}
}

func TestIdentify_DestinationMismatch(t *testing.T) {
	// G9-VULN-03: Response Destination must match entityId.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://my-sp.example.com/saml",
		"audienceRestriction": "https://my-sp.example.com/saml",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	xmlData := validSAMLResponse(t, "idp", "https://my-sp.example.com/saml", "alice", notBefore, notAfter, key)

	// Inject a wrong Destination attribute into the Response.
	xmlData = strings.Replace(xmlData,
		`Destination="https://my-sp.example.com/saml"`,
		`Destination="https://other-sp.example.com/saml"`,
		1)

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for Destination mismatch")
	}
	if !strings.Contains(err.Error(), "Destination") {
		t.Errorf("error = %v, want mention of 'Destination'", err)
	}
}

func TestIdentify_DestinationCorrect(t *testing.T) {
	// G9-VULN-03 positive: matching Destination is accepted.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://my-sp.example.com/saml",
		"audienceRestriction": "https://my-sp.example.com/saml",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	xmlData := validSAMLResponse(t, "idp", "https://my-sp.example.com/saml", "alice", notBefore, notAfter, key)

	// Add correct Destination.
	xmlData = strings.Replace(xmlData,
		`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"`,
		`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://my-sp.example.com/saml"`,
		1)

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify with correct Destination: %v", err)
	}
	if identity.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", identity.Subject)
	}
}

func TestIdentify_SubjectConfirmationRecipientMismatch(t *testing.T) {
	// G9-VULN-02: SubjectConfirmationData@Recipient must match entityId.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://my-sp.example.com/saml",
		"audienceRestriction": "https://my-sp.example.com/saml",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)

	// Build a response with SubjectConfirmation pointing to wrong Recipient.
	assertionID := "_sc-test-" + t.Name()
	notBeforeStr := notBefore.Format(time.RFC3339)
	notAfterStr := notAfter.Format(time.RFC3339)

	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Subject>` +
		`<NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData Recipient="https://wrong-sp.example.com/saml" NotOnOrAfter="` + notAfterStr + `"/>` +
		`</SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBeforeStr + `" NotOnOrAfter="` + notAfterStr + `">` +
		`<AudienceRestriction><Audience>https://my-sp.example.com/saml</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`</Assertion>`

	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])
	signedInfoXML := buildSignedInfo("#"+assertionID, digestB64)
	sigValue := signSignedInfo(t, key, signedInfoXML)

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://my-sp.example.com/saml">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject>` +
		`<NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData Recipient="https://wrong-sp.example.com/saml" NotOnOrAfter="` + notAfterStr + `"/>` +
		`</SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBeforeStr + `" NotOnOrAfter="` + notAfterStr + `">` +
		`<AudienceRestriction><Audience>https://my-sp.example.com/saml</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for Recipient mismatch")
	}
	if !strings.Contains(err.Error(), "Recipient") {
		t.Errorf("error = %v, want mention of 'Recipient'", err)
	}
}

func TestIdentify_SubjectConfirmationExpiredNotOnOrAfter(t *testing.T) {
	// G9-VULN-11: SubjectConfirmationData@NotOnOrAfter must be validated.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://my-sp.example.com/saml",
		"audienceRestriction": "https://my-sp.example.com/saml",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(time.Hour)
	// SubjectConfirmationData.NotOnOrAfter is expired (1 hour ago).
	scNotAfter := time.Now().Add(-time.Hour)

	assertionID := "_sc-expired-" + t.Name()
	notBeforeStr := notBefore.Format(time.RFC3339)
	notAfterStr := notAfter.Format(time.RFC3339)
	scNotAfterStr := scNotAfter.Format(time.RFC3339)

	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Subject>` +
		`<NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData Recipient="https://my-sp.example.com/saml" NotOnOrAfter="` + scNotAfterStr + `"/>` +
		`</SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBeforeStr + `" NotOnOrAfter="` + notAfterStr + `">` +
		`<AudienceRestriction><Audience>https://my-sp.example.com/saml</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`</Assertion>`

	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])
	signedInfoXML := buildSignedInfo("#"+assertionID, digestB64)
	sigValue := signSignedInfo(t, key, signedInfoXML)

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://my-sp.example.com/saml">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject>` +
		`<NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData Recipient="https://my-sp.example.com/saml" NotOnOrAfter="` + scNotAfterStr + `"/>` +
		`</SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBeforeStr + `" NotOnOrAfter="` + notAfterStr + `">` +
		`<AudienceRestriction><Audience>https://my-sp.example.com/saml</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"x-saml-response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for expired SubjectConfirmationData.NotOnOrAfter")
	}
	if !strings.Contains(err.Error(), "SubjectConfirmation") {
		t.Errorf("error = %v, want mention of SubjectConfirmation", err)
	}
}

func TestIdentify_SubjectConfirmationWrongMethodRejected(t *testing.T) {
	// G9-VULN-12: SubjectConfirmation@Method must be bearer.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://my-sp.example.com/saml",
		"audienceRestriction": "https://my-sp.example.com/saml",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)

	assertionID := "_sc-method-" + t.Name()
	notBeforeStr := notBefore.Format(time.RFC3339)
	notAfterStr := notAfter.Format(time.RFC3339)

	// Use holder-of-key method instead of bearer.
	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Subject>` +
		`<NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">` +
		`<SubjectConfirmationData Recipient="https://my-sp.example.com/saml" NotOnOrAfter="` + notAfterStr + `"/>` +
		`</SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBeforeStr + `" NotOnOrAfter="` + notAfterStr + `">` +
		`<AudienceRestriction><Audience>https://my-sp.example.com/saml</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`</Assertion>`

	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])
	signedInfoXML := buildSignedInfo("#"+assertionID, digestB64)
	sigValue := signSignedInfo(t, key, signedInfoXML)

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://my-sp.example.com/saml">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject>` +
		`<NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">` +
		`<SubjectConfirmationData Recipient="https://my-sp.example.com/saml" NotOnOrAfter="` + notAfterStr + `"/>` +
		`</SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBeforeStr + `" NotOnOrAfter="` + notAfterStr + `">` +
		`<AudienceRestriction><Audience>https://my-sp.example.com/saml</Audience></AudienceRestriction>` +
		`</Conditions>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"x-saml-response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for non-bearer SubjectConfirmation Method")
	}
	if !strings.Contains(err.Error(), "SubjectConfirmation") {
		t.Errorf("error = %v, want mention of SubjectConfirmation", err)
	}
}

func TestIdentify_UnsupportedTransformRejected(t *testing.T) {
	// G9-VULN-04: Reject references with unknown transform algorithms.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute).Format(time.RFC3339)
	notAfter := time.Now().Add(time.Hour).Format(time.RFC3339)
	assertionID := "_transform-test"

	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion>`
	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Build a SignedInfo with an unknown XSLT Transform algorithm.
	signedInfoXML := `<SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>` +
		`<Reference URI="#` + assertionID + `">` +
		`<Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/></Transforms>` +
		`<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<DigestValue>` + digestB64 + `</DigestValue></Reference></SignedInfo>`

	sigValue := signSignedInfo(t, key, signedInfoXML)

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for unsupported Transform algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported Transform") {
		t.Errorf("error = %v, want mention of 'unsupported Transform'", err)
	}
}

func TestIdentify_SHA1Rejected(t *testing.T) {
	// G9-VULN-06: SHA-1 signature algorithm must be rejected.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute).Format(time.RFC3339)
	notAfter := time.Now().Add(time.Hour).Format(time.RFC3339)
	assertionID := "_sha1-test"

	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion>`
	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Build SignedInfo with SHA-1 algorithm.
	signedInfoXML := `<SignedInfo><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>` +
		`<Reference URI="#` + assertionID + `"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<DigestValue>` + digestB64 + `</DigestValue></Reference></SignedInfo>`
	sigValue := signSignedInfo(t, key, signedInfoXML)

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for SHA-1 signature algorithm")
	}
	if !strings.Contains(err.Error(), "unacceptable signature algorithm") {
		t.Errorf("error = %v, want 'unacceptable signature algorithm'", err)
	}
}

func TestIdentify_IDInCommentIgnored(t *testing.T) {
	// G9-VULN-09: An ID attribute inside a comment must not be matched
	// by resolveReference.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute).Format(time.RFC3339)
	notAfter := time.Now().Add(time.Hour).Format(time.RFC3339)
	assertionID := "_comment-test"

	// Build the real assertion.
	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion>`
	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])
	signedInfoXML := buildSignedInfo("#"+assertionID, digestB64)
	sigValue := signSignedInfo(t, key, signedInfoXML)

	// Place a comment containing the same ID BEFORE the real assertion.
	// This should NOT confuse resolveReference.
	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<!-- fake: ID="` + assertionID + `" -->` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify with comment containing ID: %v", err)
	}
	if identity.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", identity.Subject)
	}
}

func TestIdentify_ReplayCacheFull(t *testing.T) {
	// G9-VULN-07: When replay cache is full and no entries are expired,
	// new assertions should be rejected rather than evicting live entries.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	// Access the identifier's replay cache and fill it.
	samlID := id.(*identifier)
	cache := samlID.replayCache
	for j := 0; j < cache.maxSize; j++ {
		cache.Add(fmt.Sprintf("fill-%d", j), time.Hour)
	}

	// Now a valid assertion should be rejected because the cache is full.
	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	xmlData := validSAMLResponse(t, "idp", "https://sp.example.com", "alice", notBefore, notAfter, key)
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection when replay cache is full")
	}
	// Should mention replay (the cache returns false which is treated as replay).
	if !strings.Contains(err.Error(), "replay") {
		t.Errorf("error = %v, want mention of 'replay'", err)
	}
}

func TestIdentify_NonSAMLNamespaceRejected(t *testing.T) {
	// G9-VULN-08: A <Response> with wrong namespace must be rejected.
	certPEM, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// XML with a non-SAML namespace on <Response>.
	xmlData := `<Response xmlns="http://www.evil.com/fake">` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion><Subject><NameID>evil</NameID></Subject></Assertion>` +
		`</Response>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for non-SAML namespace")
	}
}

func TestSAML_VULN01_MissingSubjectConfirmationRejected(t *testing.T) {
	// SAML-VULN-01: An assertion without any SubjectConfirmation elements
	// must be rejected. Without SubjectConfirmation, there is no proof the
	// assertion was intended for this SP.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute).Format(time.RFC3339)
	notAfter := time.Now().Add(time.Hour).Format(time.RFC3339)
	assertionID := "_no-sc-test"

	// Build assertion without SubjectConfirmation.
	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Subject><NameID>alice</NameID></Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion>`
	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])
	signedInfoXML := buildSignedInfo("#"+assertionID, digestB64)
	sigValue := signSignedInfo(t, key, signedInfoXML)

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + assertionID + `">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sigValue + `</SignatureValue></Signature>` +
		`<Subject><NameID>alice</NameID></Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"><AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction></Conditions>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for missing SubjectConfirmation")
	}
	if !strings.Contains(err.Error(), "SubjectConfirmation") {
		t.Errorf("error = %v, want mention of SubjectConfirmation", err)
	}
}

func TestSAML_VULN02_MissingEntityIdRejected(t *testing.T) {
	// SAML-VULN-02: entityId must be required at config time.
	// Without it, Destination and Recipient checks are neutered.
	certPEM := testCertPEM(t)
	_, err := factory("test", map[string]any{"idpCertPEM": certPEM})
	if err == nil {
		t.Fatal("expected factory error when entityId is missing")
	}
	if !strings.Contains(err.Error(), "entityId") {
		t.Errorf("error = %v, want mention of entityId", err)
	}
}

func TestFactory_MaxClockSkewExcessive(t *testing.T) {
	// SAML-VULN-03: maxClockSkew > 10 minutes must be rejected to prevent
	// accepting expired assertions indefinitely.
	certPEM, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"maxClockSkew":        "15m",
	}
	_, err := factory("test", raw)
	if err == nil {
		t.Fatal("expected error for excessive maxClockSkew")
	}
	if !strings.Contains(err.Error(), "maxClockSkew") {
		t.Errorf("error = %v, want mention of maxClockSkew", err)
	}
}

func TestFactory_NegativeMaxClockSkew(t *testing.T) {
	// SAML-VULN-03: negative maxClockSkew must be rejected.
	certPEM, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"maxClockSkew":        "-1m",
	}
	_, err := factory("test", raw)
	if err == nil {
		t.Fatal("expected error for negative maxClockSkew")
	}
}

func TestFactory_MissingAudienceRestriction(t *testing.T) {
	// SAML-VULN-04: audienceRestriction config is mandatory.
	certPEM, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM": certPEM,
		"entityId":   "https://sp.example.com",
	}
	_, err := factory("test", raw)
	if err == nil {
		t.Fatal("expected error for missing audienceRestriction")
	}
	if !strings.Contains(err.Error(), "audienceRestriction") {
		t.Errorf("error = %v, want mention of audienceRestriction", err)
	}
}

func TestIdentify_MissingAudienceRestrictionInAssertion(t *testing.T) {
	// SAML-VULN-04: assertion without <AudienceRestriction> element must be
	// rejected when audienceRestriction is configured.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute).Format(time.RFC3339)
	notAfter := time.Now().Add(5 * time.Minute).Format(time.RFC3339)

	// Build assertion WITHOUT AudienceRestriction in Conditions.
	assertionContent := `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_no-audience">` +
		`<Issuer>idp</Issuer>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData Recipient="https://sp.example.com" NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"/>` +
		`</Assertion>`

	digest := sha256.Sum256([]byte(assertionContent))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])
	signedInfoXML := buildSignedInfo("#_no-audience", digestB64)
	sig := signSignedInfo(t, key, signedInfoXML)

	xmlData := `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example.com">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">idp</Issuer>` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_no-audience">` +
		`<Issuer>idp</Issuer>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		signedInfoXML +
		`<SignatureValue>` + sig + `</SignatureValue></Signature>` +
		`<Subject><NameID>alice</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<SubjectConfirmationData Recipient="https://sp.example.com" NotOnOrAfter="` + notAfter + `"/></SubjectConfirmation>` +
		`</Subject>` +
		`<Conditions NotBefore="` + notBefore + `" NotOnOrAfter="` + notAfter + `"/>` +
		`</Assertion></Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for missing AudienceRestriction")
	}
	if !strings.Contains(err.Error(), "AudienceRestriction") {
		t.Errorf("error = %v, want mention of AudienceRestriction", err)
	}
}

func TestSAML_VULN05_MissingDestinationAccepted(t *testing.T) {
	// Destination is OPTIONAL per SAML 2.0 Core §3.2.2 — it may be absent
	// for HTTP-Redirect binding or IdP-initiated flows. Cross-SP replay is
	// prevented by AudienceRestriction + SubjectConfirmation Recipient.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponse(t, "idp", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)

	// Strip the Destination attribute (simulates HTTP-Redirect or IdP-initiated).
	xmlData = strings.Replace(xmlData, ` Destination="https://sp.example.com"`, "", 1)

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err != nil {
		t.Fatalf("expected success for missing Destination (optional per spec): %v", err)
	}
}

func TestSAML_VULN06_NameIDControlCharsRejected(t *testing.T) {
	// SAML-VULN-06: NameID values containing control characters must be
	// rejected to prevent log injection and audit evasion.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// Craft a response with a NameID containing CRLF for log injection.
	xmlData := validSAMLResponse(t, "idp", "https://sp.example.com",
		"alice\r\nINFO [auth] user=root action=grant",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for control characters in NameID")
	}
	if !strings.Contains(err.Error(), "control") {
		t.Errorf("error = %v, want mention of control characters", err)
	}
}

func TestSAML_VULN06_NameIDExcessiveLengthRejected(t *testing.T) {
	// SAML-VULN-06: NameID values exceeding maxNameIDLen must be rejected
	// to prevent memory exhaustion in identity caches.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	longNameID := strings.Repeat("a", maxNameIDLen+1)
	xmlData := validSAMLResponse(t, "idp", "https://sp.example.com", longNameID,
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for oversized NameID")
	}
	if !strings.Contains(err.Error(), "maximum length") {
		t.Errorf("error = %v, want mention of maximum length", err)
	}
}

func TestSAML_VULN06_ValidUnicodeNameIDAccepted(t *testing.T) {
	// Valid unicode characters in NameID should be accepted.
	certPEM, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponse(t, "idp", "https://sp.example.com",
		"ålice.sørensen@例え.jp",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlData))
	r := &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "ålice.sørensen@例え.jp" {
		t.Errorf("Subject = %q", identity.Subject)
	}
}
