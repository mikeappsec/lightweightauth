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
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

// testKeyPair generates a self-signed certificate (PEM + DER) and its
// private key for testing. der is needed to embed the matching cert in a
// signature's KeyInfo (see signOrFake).
func testKeyPair(t *testing.T) (certPEM string, der []byte, key *ecdsa.PrivateKey) {
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
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return certPEM, der, key
}

// testCertPEM generates a self-signed certificate PEM for testing (no key returned).
func testCertPEM(t *testing.T) string {
	t.Helper()
	certPEM, _, _ := testKeyPair(t)
	return certPEM
}

// reqWithSAMLResponse base64-encodes xmlData and wraps it in a module.Request
// carrying the default X-Saml-Response header.
func reqWithSAMLResponse(xmlData []byte) *module.Request {
	encoded := base64.StdEncoding.EncodeToString(xmlData)
	return &module.Request{Headers: map[string][]string{
		"X-Saml-Response": {encoded},
	}}
}

// signOrFake signs el with a real goxmldsig enveloped signature when key is
// non-nil; otherwise it embeds a structurally-plausible but cryptographically
// bogus signature, for tests that only assert overall rejection regardless
// of the specific reason.
func signOrFake(t *testing.T, key *ecdsa.PrivateKey, certDER []byte, el *etree.Element) *etree.Element {
	t.Helper()
	if key == nil {
		return fakeSign(el)
	}
	// Round-trip through serialize+reparse before signing so the signed
	// content exactly matches what verification will see after the
	// document travels over the wire (e.g. XML line-ending normalization
	// on parse would otherwise desync from what was hashed in-memory).
	el = roundTrip(t, el)
	signer, err := dsig.NewSigningContext(key, [][]byte{certDER})
	if err != nil {
		t.Fatalf("NewSigningContext: %v", err)
	}
	signed, err := signer.SignEnveloped(el)
	if err != nil {
		t.Fatalf("SignEnveloped: %v", err)
	}
	return signed
}

// roundTrip serializes el and reparses it, so callers sign exactly the form
// that will be reparsed at verification time.
func roundTrip(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("round-trip serialize: %v", err)
	}
	doc2 := etree.NewDocument()
	if err := doc2.ReadFromBytes(b); err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	return doc2.Root()
}

// fakeSign embeds a well-formed but cryptographically invalid Signature,
// mirroring the "fakesig" placeholder used throughout these tests to
// exercise rejection paths without a real key.
func fakeSign(el *etree.Element) *etree.Element {
	fake := el.Copy()
	sig := fake.CreateElement("Signature")
	sig.CreateAttr("xmlns", dsig.Namespace)
	si := sig.CreateElement("SignedInfo")
	si.CreateElement("SignatureMethod").CreateAttr("Algorithm", dsig.ECDSASHA256SignatureMethod)
	ref := si.CreateElement("Reference")
	id := el.SelectAttrValue("ID", "")
	if id != "" {
		ref.CreateAttr("URI", "#"+id)
	} else {
		ref.CreateAttr("URI", "")
	}
	transforms := ref.CreateElement("Transforms")
	transforms.CreateElement("Transform").CreateAttr("Algorithm", string(dsig.EnvelopedSignatureAltorithmId))
	ref.CreateElement("DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	ref.CreateElement("DigestValue").SetText("ZmFrZQ==")
	sig.CreateElement("SignatureValue").SetText("ZmFrZXNpZw==")
	return fake
}

// wrapResponse builds the enclosing <Response> around a (possibly signed)
// Assertion element and serializes the document to bytes. destination is
// omitted from the Response when empty.
func wrapResponse(destination, responseIssuer string, assertionEl *etree.Element) []byte {
	resp := etree.NewElement("Response")
	resp.CreateAttr("xmlns", samlProtocolNS)
	if destination != "" {
		resp.CreateAttr("Destination", destination)
	}
	respIssuer := resp.CreateElement("Issuer")
	respIssuer.CreateAttr("xmlns", samlAssertionNS)
	respIssuer.SetText(responseIssuer)
	status := resp.CreateElement("Status")
	status.CreateElement("StatusCode").CreateAttr("Value", statusSuccess)
	resp.AddChild(assertionEl)

	doc := etree.NewDocument()
	doc.SetRoot(resp)
	out, _ := doc.WriteToBytes()
	return out
}

// buildFullAssertionEl builds an unsigned <Assertion> with the full set of
// fields used by most positive-path tests: NameID, a bearer
// SubjectConfirmation (Recipient=audience), Conditions/AudienceRestriction,
// AuthnStatement, and an AttributeStatement with email/Group attributes.
func buildFullAssertionEl(assertionID, issuer, audience, subject string, notBefore, notAfter time.Time) *etree.Element {
	assertion := etree.NewElement("Assertion")
	assertion.CreateAttr("xmlns", samlAssertionNS)
	if assertionID != "" {
		assertion.CreateAttr("ID", assertionID)
	}
	assertion.CreateElement("Issuer").SetText(issuer)

	subj := assertion.CreateElement("Subject")
	nameID := subj.CreateElement("NameID")
	nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress")
	nameID.SetText(subject)
	sc := subj.CreateElement("SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("SubjectConfirmationData")
	if audience != "" {
		scd.CreateAttr("Recipient", audience)
	}
	if !notAfter.IsZero() {
		scd.CreateAttr("NotOnOrAfter", notAfter.Format(time.RFC3339))
	}

	cond := assertion.CreateElement("Conditions")
	if !notBefore.IsZero() {
		cond.CreateAttr("NotBefore", notBefore.Format(time.RFC3339))
	}
	if !notAfter.IsZero() {
		cond.CreateAttr("NotOnOrAfter", notAfter.Format(time.RFC3339))
	}
	if audience != "" {
		ar := cond.CreateElement("AudienceRestriction")
		ar.CreateElement("Audience").SetText(audience)
	}

	authn := assertion.CreateElement("AuthnStatement")
	authn.CreateAttr("SessionIndex", "session-123")

	attrStmt := assertion.CreateElement("AttributeStatement")
	a1 := attrStmt.CreateElement("Attribute")
	a1.CreateAttr("Name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
	a1.CreateElement("AttributeValue").SetText("alice@example.com")
	a2 := attrStmt.CreateElement("Attribute")
	a2.CreateAttr("Name", "http://schemas.xmlsoap.org/claims/Group")
	a2.CreateElement("AttributeValue").SetText("admins")
	a2.CreateElement("AttributeValue").SetText("users")

	return assertion
}

// buildSCAssertion builds a minimal unsigned <Assertion> for
// SubjectConfirmation-focused tests: Issuer, Subject/NameID, a single
// SubjectConfirmation with the given method/recipient/notOnOrAfter (empty
// strings omit the attribute or the element entirely for method), and
// Conditions/AudienceRestriction targeting audience (omitted when empty).
func buildSCAssertion(id, issuer, subject, method, recipient, scNotOnOrAfter, audience string, notBefore, notAfter time.Time) *etree.Element {
	assertion := etree.NewElement("Assertion")
	assertion.CreateAttr("xmlns", samlAssertionNS)
	assertion.CreateAttr("ID", id)
	assertion.CreateElement("Issuer").SetText(issuer)
	subj := assertion.CreateElement("Subject")
	subj.CreateElement("NameID").SetText(subject)
	if method != "" {
		sc := subj.CreateElement("SubjectConfirmation")
		sc.CreateAttr("Method", method)
		scd := sc.CreateElement("SubjectConfirmationData")
		if recipient != "" {
			scd.CreateAttr("Recipient", recipient)
		}
		if scNotOnOrAfter != "" {
			scd.CreateAttr("NotOnOrAfter", scNotOnOrAfter)
		}
	}
	cond := assertion.CreateElement("Conditions")
	cond.CreateAttr("NotBefore", notBefore.Format(time.RFC3339))
	cond.CreateAttr("NotOnOrAfter", notAfter.Format(time.RFC3339))
	if audience != "" {
		ar := cond.CreateElement("AudienceRestriction")
		ar.CreateElement("Audience").SetText(audience)
	}
	return assertion
}

// validSAMLResponseWithID builds a complete signed (or fake-signed, if key is
// nil) SAML Response with the given assertion ID.
func validSAMLResponseWithID(t *testing.T, assertionID string, certDER []byte, issuer, audience, subject string, notBefore, notAfter time.Time, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	assertion := buildFullAssertionEl(assertionID, issuer, audience, subject, notBefore, notAfter)
	signed := signOrFake(t, key, certDER, assertion)
	return wrapResponse(audience, issuer, signed)
}

// validSAMLResponse is validSAMLResponseWithID with a test-derived assertion ID.
func validSAMLResponse(t *testing.T, certDER []byte, issuer, audience, subject string, notBefore, notAfter time.Time, key *ecdsa.PrivateKey) []byte {
	return validSAMLResponseWithID(t, "_assert-"+t.Name(), certDER, issuer, audience, subject, notBefore, notAfter, key)
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
	r := reqWithSAMLResponse([]byte("<not-valid-saml>"))
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
}

func TestIdentify_IssuerMismatch(t *testing.T) {
	certPEM, der, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"issuer":              "https://trusted-idp.com",
	}
	id, _ := factory("test", raw)
	xmlData := validSAMLResponse(t, der, "https://evil-idp.com", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
	r := reqWithSAMLResponse(xmlData)
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
}

func TestIdentify_Expired(t *testing.T) {
	certPEM, der, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"maxClockSkew":        "0s",
	}
	id, _ := factory("test", raw)
	xmlData := validSAMLResponse(t, der, "https://idp.com", "https://sp.com", "alice",
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil)
	r := reqWithSAMLResponse(xmlData)
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for expired assertion")
	}
}

func TestIdentify_NotYetValid(t *testing.T) {
	certPEM, der, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"maxClockSkew":        "0s",
	}
	id, _ := factory("test", raw)
	xmlData := validSAMLResponse(t, der, "https://idp.com", "https://sp.com", "alice",
		time.Now().Add(2*time.Hour), time.Now().Add(3*time.Hour), nil)
	r := reqWithSAMLResponse(xmlData)
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for not-yet-valid assertion")
	}
}

func TestIdentify_AudienceMismatch(t *testing.T) {
	certPEM, der, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://my-sp.com",
	}
	id, _ := factory("test", raw)
	xmlData := validSAMLResponse(t, der, "https://idp.com", "https://other-sp.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
	r := reqWithSAMLResponse(xmlData)
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
}

func TestIdentify_Valid(t *testing.T) {
	certPEM, der, key := testKeyPair(t)
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
	xmlData := validSAMLResponse(t, der, "https://idp.example.com", "https://sp.example.com", "alice@corp.com",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), key)
	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, _ := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	xmlData := validSAMLResponse(t, der, "https://idp.com", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
	r := reqWithSAMLResponse(xmlData)
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
	r := reqWithSAMLResponse([]byte(xmlData))
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for non-success status")
	}
}

func TestIdentify_ExpiredCert(t *testing.T) {
	// Generate an expired certificate, and sign with its matching key so
	// the signature itself is otherwise valid.
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
	xmlData := validSAMLResponse(t, der, "https://idp.com", "https://sp.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), key)
	r := reqWithSAMLResponse(xmlData)
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for expired IdP certificate")
	}
}

func TestIdentify_CustomHeader(t *testing.T) {
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
		"header":              "X-Custom-SAML",
	}
	id, _ := factory("test", raw)
	xmlData := validSAMLResponse(t, der, "https://idp.com", "https://sp.example.com", "bob",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), key)
	encoded := base64.StdEncoding.EncodeToString(xmlData)
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
	r := reqWithSAMLResponse([]byte(xmlData))
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
	r := reqWithSAMLResponse([]byte(xmlData))
	_, err := id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected error for bad signature algorithm")
	}
}

func TestIdentify_XSWSignatureWrapping(t *testing.T) {
	// G9-04 regression: an attacker-injected bare <SignedInfo> (not wrapped
	// in a real <Signature>) elsewhere in the document must not confuse
	// verification of the legitimate signature. With a real XML parser and
	// goxmldsig's namespace-aware Signature lookup (rather than byte-level
	// scanning), this class of attack is structurally prevented.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	assertion := buildFullAssertionEl("_xsw-test", "idp", "https://sp.example.com", "alice", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)

	resp := etree.NewElement("Response")
	resp.CreateAttr("xmlns", samlProtocolNS)
	resp.CreateAttr("Destination", "https://sp.example.com")
	respIssuer := resp.CreateElement("Issuer")
	respIssuer.CreateAttr("xmlns", samlAssertionNS)
	respIssuer.SetText("idp")

	resp.CreateComment(" injected ")
	injected := resp.CreateElement("SignedInfo")
	injected.CreateElement("SignatureMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
	injRef := injected.CreateElement("Reference")
	injRef.CreateAttr("URI", "#evil")
	injRef.CreateElement("DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	injRef.CreateElement("DigestValue").SetText("INJECTED_EVIL")

	status := resp.CreateElement("Status")
	status.CreateElement("StatusCode").CreateAttr("Value", statusSuccess)
	resp.AddChild(signed)

	doc := etree.NewDocument()
	doc.SetRoot(resp)
	xmlData, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	r := reqWithSAMLResponse(xmlData)
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("XSW regression: should verify despite injected bare SignedInfo: %v", err)
	}
	if identity.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", identity.Subject)
	}
}

func TestIdentify_MalformedTimestampRejected(t *testing.T) {
	// G9-05 regression: malformed timestamps must cause rejection, not
	// silent bypass. The assertion is genuinely, validly signed — only
	// the timestamp strings themselves are malformed.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	assertion := etree.NewElement("Assertion")
	assertion.CreateAttr("xmlns", samlAssertionNS)
	assertion.CreateAttr("ID", "_malformed-ts")
	assertion.CreateElement("Issuer").SetText("idp")
	subj := assertion.CreateElement("Subject")
	subj.CreateElement("NameID").SetText("alice")
	cond := assertion.CreateElement("Conditions")
	cond.CreateAttr("NotBefore", "not-a-date")
	cond.CreateAttr("NotOnOrAfter", "also-not-a-date")

	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://sp.example.com", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponseWithID(t, "_no-expiry", der, "idp", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Time{}, key) // zero notAfter -> no NotOnOrAfter attr

	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponse(t, der, "idp", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)
	r := reqWithSAMLResponse(xmlData)

	_, err = id.Identify(nil, r)
	if err != nil {
		t.Fatalf("first Identify should succeed: %v", err)
	}

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
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponseWithID(t, "", der, "idp", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)
	r := reqWithSAMLResponse(xmlData)
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for missing assertion ID")
	}
	if !strings.Contains(err.Error(), "no ID attribute") {
		t.Errorf("error = %v, want mention of 'no ID attribute'", err)
	}
}

func TestIdentify_TamperedAssertionContentRejected(t *testing.T) {
	// G9-07 regression: Modifying assertion content (e.g., changing the
	// subject) after signing MUST be detected via digest verification.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{"idpCertPEM": certPEM, "entityId": "https://sp.example.com", "audienceRestriction": "https://sp.example.com"}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(5 * time.Minute)
	legitimateXML := validSAMLResponse(t, der, "idp", "https://sp.example.com", "alice", notBefore, notAfter, key)

	tamperedStr := strings.Replace(string(legitimateXML), ">alice<", ">admin<", 1)
	if tamperedStr == string(legitimateXML) {
		t.Fatal("tampering failed -test is broken")
	}
	tamperedXML := []byte(tamperedStr)

	r := reqWithSAMLResponse(tamperedXML)
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for tampered assertion content")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("error = %v, want mention of signature verification failure", err)
	}
}

func TestIdentify_XSWForgedFirstAssertion(t *testing.T) {
	// G9-VULN-01: An attacker injects a forged assertion as the first
	// <Assertion> child of <Response>, and hides the legitimately signed
	// assertion inside a wrapper. The forged assertion has no valid
	// signature over its own ID, and the real assertion — though validly
	// signed — is not a direct child of Response, so neither the
	// assertion-level nor the response-level fallback verification can
	// succeed.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)

	real := buildFullAssertionEl("_real-signed-assertion", "idp", "https://sp.example.com", "legitimate-user", notBefore, notAfter)
	signedReal := signOrFake(t, key, der, real)

	forged := buildFullAssertionEl("_forged-evil", "idp", "https://sp.example.com", "attacker@evil.com", notBefore, notAfter)

	resp := etree.NewElement("Response")
	resp.CreateAttr("xmlns", samlProtocolNS)
	resp.CreateAttr("Destination", "https://sp.example.com")
	respIssuer := resp.CreateElement("Issuer")
	respIssuer.CreateAttr("xmlns", samlAssertionNS)
	respIssuer.SetText("idp")
	status := resp.CreateElement("Status")
	status.CreateElement("StatusCode").CreateAttr("Value", statusSuccess)
	resp.AddChild(forged) // first Assertion child -- what a naive parser would pick

	ext := resp.CreateElement("Extensions")
	ext.AddChild(signedReal) // real signed assertion hidden as a non-direct-child descendant

	doc := etree.NewDocument()
	doc.SetRoot(resp)
	xmlData, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	r := reqWithSAMLResponse(xmlData)
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection: forged assertion must not be trusted")
	}
}

func TestIdentify_DestinationMismatch(t *testing.T) {
	// G9-VULN-03: Response Destination must match entityId.
	certPEM, der, key := testKeyPair(t)
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
	assertion := buildFullAssertionEl("_dest-mismatch", "idp", "https://my-sp.example.com/saml", "alice", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://other-sp.example.com/saml", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, key := testKeyPair(t)
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
	assertion := buildFullAssertionEl("_dest-correct", "idp", "https://my-sp.example.com/saml", "alice", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://my-sp.example.com/saml", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, key := testKeyPair(t)
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
	assertionID := "_sc-test-" + t.Name()
	assertion := buildSCAssertion(assertionID, "idp", "alice",
		"urn:oasis:names:tc:SAML:2.0:cm:bearer", "https://wrong-sp.example.com/saml", notAfter.Format(time.RFC3339),
		"https://my-sp.example.com/saml", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://my-sp.example.com/saml", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for Recipient mismatch")
	}
	if !strings.Contains(err.Error(), "Recipient") {
		t.Errorf("error = %v, want mention of 'Recipient'", err)
	}
}

// TestIdentify_SubjectConfirmationEmptyRecipientRejected is a regression
// test for the bug where an empty Recipient attribute (SAML 2.0 Profiles
// §4.1.4.2 requires it on bearer confirmations) silently bypassed the
// Recipient check entirely, instead of being rejected like any other
// mismatch.
func TestIdentify_SubjectConfirmationEmptyRecipientRejected(t *testing.T) {
	certPEM, der, key := testKeyPair(t)
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
	assertionID := "_sc-test-" + t.Name()
	assertion := buildSCAssertion(assertionID, "idp", "alice",
		"urn:oasis:names:tc:SAML:2.0:cm:bearer", "", notAfter.Format(time.RFC3339),
		"https://my-sp.example.com/saml", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://my-sp.example.com/saml", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for empty Recipient (required on bearer confirmations)")
	}
}

func TestIdentify_SubjectConfirmationExpiredNotOnOrAfter(t *testing.T) {
	// G9-VULN-11: SubjectConfirmationData@NotOnOrAfter must be validated.
	certPEM, der, key := testKeyPair(t)
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
	scNotAfter := time.Now().Add(-time.Hour) // expired
	assertionID := "_sc-expired-" + t.Name()
	assertion := buildSCAssertion(assertionID, "idp", "alice",
		"urn:oasis:names:tc:SAML:2.0:cm:bearer", "https://my-sp.example.com/saml", scNotAfter.Format(time.RFC3339),
		"https://my-sp.example.com/saml", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://my-sp.example.com/saml", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, key := testKeyPair(t)
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
	assertion := buildSCAssertion(assertionID, "idp", "alice",
		"urn:oasis:names:tc:SAML:2.0:cm:holder-of-key", "https://my-sp.example.com/saml", notAfter.Format(time.RFC3339),
		"https://my-sp.example.com/saml", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://my-sp.example.com/saml", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
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
	// goxmldsig's own transform switch rejects any algorithm it doesn't
	// implement; we just need to smuggle one into an otherwise validly
	// signed assertion's Transforms list.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	assertion := buildFullAssertionEl("_transform-test", "idp", "https://sp.example.com", "alice", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)

	sigEl := findSignatureRecursive(signed)
	if sigEl == nil {
		t.Fatal("test setup: no Signature found in signed assertion")
	}
	signedInfo := firstChildByTag(sigEl, "SignedInfo")
	ref := firstChildByTag(signedInfo, "Reference")
	transforms := firstChildByTag(ref, "Transforms")
	if transforms == nil {
		t.Fatal("test setup: no Transforms element found")
	}
	bogus := transforms.CreateElement("Transform")
	bogus.CreateAttr("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116")

	xmlData := wrapResponse("https://sp.example.com", "idp", signed)
	r := reqWithSAMLResponse(xmlData)
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for unsupported Transform algorithm")
	}
	if !strings.Contains(err.Error(), "Transform") {
		t.Errorf("error = %v, want mention of 'Transform'", err)
	}
}

func TestIdentify_SHA1Rejected(t *testing.T) {
	// G9-VULN-06: SHA-1 signature algorithm must be rejected, even though
	// goxmldsig itself would accept a genuinely valid SHA-1 signature —
	// this must be caught by our own policy layer.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	assertion := buildFullAssertionEl("_sha1-test", "idp", "https://sp.example.com", "alice", notBefore, notAfter)

	signer, err := dsig.NewSigningContext(key, [][]byte{der})
	if err != nil {
		t.Fatalf("NewSigningContext: %v", err)
	}
	if err := signer.SetSignatureMethod(dsig.ECDSASHA1SignatureMethod); err != nil {
		t.Fatalf("SetSignatureMethod: %v", err)
	}
	signed, err := signer.SignEnveloped(assertion)
	if err != nil {
		t.Fatalf("SignEnveloped: %v", err)
	}

	xmlData := wrapResponse("https://sp.example.com", "idp", signed)
	r := reqWithSAMLResponse(xmlData)
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
	// when resolving the signed Assertion. With a real XML parser,
	// comments are never matched as element attributes, so this is
	// structurally guaranteed rather than relying on ad hoc byte-scanning.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	assertion := buildFullAssertionEl("_comment-test", "idp", "https://sp.example.com", "alice", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)

	resp := etree.NewElement("Response")
	resp.CreateAttr("xmlns", samlProtocolNS)
	resp.CreateAttr("Destination", "https://sp.example.com")
	respIssuer := resp.CreateElement("Issuer")
	respIssuer.CreateAttr("xmlns", samlAssertionNS)
	respIssuer.SetText("idp")
	resp.CreateComment(` fake: ID="_comment-test" `)
	status := resp.CreateElement("Status")
	status.CreateElement("StatusCode").CreateAttr("Value", statusSuccess)
	resp.AddChild(signed)

	doc := etree.NewDocument()
	doc.SetRoot(resp)
	xmlData, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	samlID := id.(*identifier)
	cache := samlID.replayCache
	for j := 0; j < cache.maxSize; j++ {
		cache.Add(fmt.Sprintf("fill-%d", j), time.Hour)
	}

	xmlData := validSAMLResponse(t, der, "idp", "https://sp.example.com", "alice",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), key)
	r := reqWithSAMLResponse(xmlData)
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection when replay cache is full")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Errorf("error = %v, want mention of 'replay'", err)
	}
}

func TestIdentify_NonSAMLNamespaceRejected(t *testing.T) {
	// G9-VULN-08: A <Response> with wrong namespace must be rejected.
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

	xmlData := `<Response xmlns="http://www.evil.com/fake">` +
		`<Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>` +
		`<Assertion><Subject><NameID>evil</NameID></Subject></Assertion>` +
		`</Response>`
	r := reqWithSAMLResponse([]byte(xmlData))
	_, err = id.Identify(nil, r)
	if err == nil {
		t.Fatal("expected rejection for non-SAML namespace")
	}
}

func TestSAML_VULN01_MissingSubjectConfirmationRejected(t *testing.T) {
	// SAML-VULN-01: An assertion without any SubjectConfirmation elements
	// must be rejected. Without SubjectConfirmation, there is no proof the
	// assertion was intended for this SP.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	assertion := etree.NewElement("Assertion")
	assertion.CreateAttr("xmlns", samlAssertionNS)
	assertion.CreateAttr("ID", "_no-sc-test")
	assertion.CreateElement("Issuer").SetText("idp")
	subj := assertion.CreateElement("Subject")
	subj.CreateElement("NameID").SetText("alice")
	cond := assertion.CreateElement("Conditions")
	cond.CreateAttr("NotBefore", notBefore.Format(time.RFC3339))
	cond.CreateAttr("NotOnOrAfter", notAfter.Format(time.RFC3339))
	ar := cond.CreateElement("AudienceRestriction")
	ar.CreateElement("Audience").SetText("https://sp.example.com")

	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://sp.example.com", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
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
	// SAML-VULN-03: maxClockSkew > 10 minutes must be rejected.
	certPEM := testCertPEM(t)
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
	certPEM := testCertPEM(t)
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
	certPEM := testCertPEM(t)
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
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(5 * time.Minute)
	assertion := buildSCAssertion("_no-audience", "idp", "alice",
		"urn:oasis:names:tc:SAML:2.0:cm:bearer", "https://sp.example.com", notAfter.Format(time.RFC3339),
		"", notBefore, notAfter) // empty audience -> no AudienceRestriction element
	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("https://sp.example.com", "idp", signed)

	r := reqWithSAMLResponse(xmlData)
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
	// for HTTP-Redirect binding or IdP-initiated flows.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(5 * time.Minute)
	assertion := buildFullAssertionEl("_no-dest", "idp", "https://sp.example.com", "alice", notBefore, notAfter)
	signed := signOrFake(t, key, der, assertion)
	xmlData := wrapResponse("", "idp", signed) // no Destination

	r := reqWithSAMLResponse(xmlData)
	_, err = id.Identify(nil, r)
	if err != nil {
		t.Fatalf("expected success for missing Destination (optional per spec): %v", err)
	}
}

func TestSAML_VULN06_NameIDControlCharsRejected(t *testing.T) {
	// SAML-VULN-06: NameID values containing control characters must be
	// rejected to prevent log injection and audit evasion.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponse(t, der, "idp", "https://sp.example.com",
		"alice\r\nINFO [auth] user=root action=grant",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)

	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, key := testKeyPair(t)
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
	xmlData := validSAMLResponse(t, der, "idp", "https://sp.example.com", longNameID,
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)

	r := reqWithSAMLResponse(xmlData)
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
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	xmlData := validSAMLResponse(t, der, "idp", "https://sp.example.com",
		"ålice.sørensen@例え.jp",
		time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute), key)

	r := reqWithSAMLResponse(xmlData)
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if identity.Subject != "ålice.sørensen@例え.jp" {
		t.Errorf("Subject = %q", identity.Subject)
	}
}

func TestIdentify_ResponseLevelSignatureAccepted(t *testing.T) {
	// New coverage: some IdPs sign the whole <Response> instead of the
	// assertion. verifyAndExtractAssertion must fall back to a
	// response-level signature and extract the Assertion from within the
	// validated Response element.
	certPEM, der, key := testKeyPair(t)
	raw := map[string]any{
		"idpCertPEM":          certPEM,
		"entityId":            "https://sp.example.com",
		"audienceRestriction": "https://sp.example.com",
	}
	id, err := factory("test", raw)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	assertion := buildFullAssertionEl("_response-level-test", "idp", "https://sp.example.com", "alice", notBefore, notAfter)

	resp := etree.NewElement("Response")
	resp.CreateAttr("xmlns", samlProtocolNS)
	resp.CreateAttr("ID", "_response-id")
	resp.CreateAttr("Destination", "https://sp.example.com")
	respIssuer := resp.CreateElement("Issuer")
	respIssuer.CreateAttr("xmlns", samlAssertionNS)
	respIssuer.SetText("idp")
	status := resp.CreateElement("Status")
	status.CreateElement("StatusCode").CreateAttr("Value", statusSuccess)
	resp.AddChild(assertion)

	signer, err := dsig.NewSigningContext(key, [][]byte{der})
	if err != nil {
		t.Fatalf("NewSigningContext: %v", err)
	}
	signedResp, err := signer.SignEnveloped(resp)
	if err != nil {
		t.Fatalf("SignEnveloped: %v", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(signedResp)
	xmlData, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	r := reqWithSAMLResponse(xmlData)
	identity, err := id.Identify(nil, r)
	if err != nil {
		t.Fatalf("Identify with response-level signature: %v", err)
	}
	if identity.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", identity.Subject)
	}
}
