// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

// Package saml implements a SAML 2.0 identifier module (G9 — ID-SAML-1).
//
// It validates SAML Response assertions posted by IdPs (SP-initiated and
// IdP-initiated flows) with:
//
//   - XML digital signature verification (RSA-SHA256, RSA-SHA384, RSA-SHA512)
//   - NotBefore / NotOnOrAfter temporal validation
//   - Audience restriction validation
//   - Issuer pinning
//   - SubjectConfirmation enforcement (Method=bearer, Recipient, NotOnOrAfter)
//   - Response Destination validation against entityId
//   - Subject extraction from NameID
//   - Attribute statement → claims mapping
//
// Security invariants:
//   - entityId is REQUIRED at config time; without it, Destination and
//     Recipient checks are neutered (SAML-VULN-02 fix).
//   - At least one SubjectConfirmation with Method=bearer MUST be present
//     per SAML 2.0 Profiles §4.1.4.2 (SAML-VULN-01 fix).
//
// Configuration:
//
//	type: saml
//	name: corporate-idp
//	config:
//	  idpCertPEM: |
//	    -----BEGIN CERTIFICATE-----
//	    ...
//	  entityId: https://sp.example.com/saml
//	  issuer: https://idp.example.com/saml
//	  audienceRestriction: https://sp.example.com/saml
//	  maxClockSkew: 30s
//	  attributeMapping:
//	    email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
//	    groups: http://schemas.xmlsoap.org/claims/Group
package saml

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func init() { module.RegisterIdentifier("saml", factory) }

// maxAllowedClockSkew is the upper bound for the configurable clock skew.
// SAML-VULN-03: Without a cap, operators could misconfigure a skew that
// effectively disables temporal validation (e.g. "87600h" = 10 years).
// 10 minutes is generous for any reasonable clock drift scenario.
const maxAllowedClockSkew = 10 * time.Minute

// maxNameIDLen is the maximum allowed length of a NameID subject value.
// SAML-VULN-06: Without this limit, a signed assertion with a megabyte-sized
// NameID could exhaust memory in identity caches, log storage, and downstream
// authorization systems.
const maxNameIDLen = 1024

// Compile-time guard.
var _ module.Identifier = (*identifier)(nil)

// identifier is the runtime SAML SP assertion validator.
//
// All fields are set at construction time by factory and are immutable
// thereafter. All methods are safe for concurrent use by multiple
// goroutines.
type identifier struct {
	name                string
	idpCert             *x509.Certificate
	entityID            string
	issuer              string
	audienceRestriction string
	maxClockSkew        time.Duration
	attributeMapping    map[string]string // claim name → SAML attribute name
	header              string            // header containing the SAMLResponse (Base64)
	formField           string            // form field name for POST binding
	replayCache         *assertionReplayCache
}

// Name returns the configured identifier name. Safe for concurrent use.
func (i *identifier) Name() string { return i.name }

// Identify extracts a SAML Response from the request (either from a header
// or POST form field), validates the assertion signature and temporal
// constraints, and returns the extracted Identity.
//
// Safe for concurrent use.
func (i *identifier) Identify(_ context.Context, r *module.Request) (*module.Identity, error) {
	// Try header first, then check for encoded response in a well-known header.
	raw := r.Header(i.header)
	if raw == "" {
		return nil, module.ErrNoMatch
	}

	// Decode Base64 SAML Response.
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Try URL-safe base64.
		decoded, err = base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: saml: invalid base64 encoding", module.ErrInvalidCredential)
		}
	}

	// Parse SAML Response XML.
	var resp samlResponse
	if err := xml.Unmarshal(decoded, &resp); err != nil {
		return nil, fmt.Errorf("%w: saml: invalid XML: %v", module.ErrInvalidCredential, err)
	}

	// G9-VULN-03: Validate Response Destination attribute when present.
	// Per SAML 2.0 Core §3.2.2, Destination is OPTIONAL in the schema but
	// REQUIRED for signed messages over HTTP-POST binding (Bindings §3.5.5.2).
	// For HTTP-Redirect or IdP-initiated flows it may be absent. When present
	// it MUST match the SP's entityId to prevent cross-SP replay.
	if resp.Destination != "" && i.entityID != "" {
		if resp.Destination != i.entityID {
			return nil, fmt.Errorf("%w: saml: Response Destination %q does not match entityId %q",
				module.ErrInvalidCredential, resp.Destination, i.entityID)
		}
	}

	// Validate issuer.
	if i.issuer != "" && resp.Issuer != i.issuer {
		return nil, fmt.Errorf("%w: saml: issuer mismatch: got %q, want %q",
			module.ErrInvalidCredential, resp.Issuer, i.issuer)
	}

	// Validate status.
	if resp.Status.StatusCode.Value != statusSuccess {
		return nil, fmt.Errorf("%w: saml: response status: %s",
			module.ErrInvalidCredential, resp.Status.StatusCode.Value)
	}

	// Validate assertion.
	assertion := resp.Assertion
	if assertion.Subject.NameID.Value == "" {
		return nil, fmt.Errorf("%w: saml: no NameID in assertion", module.ErrInvalidCredential)
	}

	// SAML-VULN-06: Validate NameID value to prevent log injection and
	// memory exhaustion from oversized or malicious subjects.
	if len(assertion.Subject.NameID.Value) > maxNameIDLen {
		return nil, fmt.Errorf("%w: saml: NameID exceeds maximum length (%d chars)",
			module.ErrInvalidCredential, maxNameIDLen)
	}
	if containsControlChar(assertion.Subject.NameID.Value) {
		return nil, fmt.Errorf("%w: saml: NameID contains invalid control characters",
			module.ErrInvalidCredential)
	}

	// Validate assertion issuer.
	if i.issuer != "" && assertion.Issuer != i.issuer {
		return nil, fmt.Errorf("%w: saml: assertion issuer mismatch: got %q, want %q",
			module.ErrInvalidCredential, assertion.Issuer, i.issuer)
	}

	// Validate temporal conditions.
	now := time.Now()
	if assertion.Conditions.NotBefore != "" {
		nb, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("%w: saml: malformed NotBefore timestamp: %q",
				module.ErrInvalidCredential, assertion.Conditions.NotBefore)
		}
		if now.Add(i.maxClockSkew).Before(nb) {
			return nil, fmt.Errorf("%w: saml: assertion not yet valid (NotBefore: %s)",
				module.ErrInvalidCredential, assertion.Conditions.NotBefore)
		}
	}
	if assertion.Conditions.NotOnOrAfter != "" {
		noa, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
		if err != nil {
			return nil, fmt.Errorf("%w: saml: malformed NotOnOrAfter timestamp: %q",
				module.ErrInvalidCredential, assertion.Conditions.NotOnOrAfter)
		}
		if now.Add(-i.maxClockSkew).After(noa) {
			return nil, fmt.Errorf("%w: saml: assertion expired (NotOnOrAfter: %s)",
				module.ErrInvalidCredential, assertion.Conditions.NotOnOrAfter)
		}
	} else {
		// G9-06: Assertions without NotOnOrAfter have no expiry boundary,
		// which makes replay attacks trivial. Reject them.
		return nil, fmt.Errorf("%w: saml: assertion missing NotOnOrAfter (required for replay protection)",
			module.ErrInvalidCredential)
	}

	// Validate audience restriction.
	// SAML-VULN-04: Always enforce audience when configured — also require
	// the assertion to carry at least one AudienceRestriction element.
	if i.audienceRestriction != "" {
		if len(assertion.Conditions.AudienceRestrictions) == 0 {
			return nil, fmt.Errorf("%w: saml: assertion has no AudienceRestriction (required when audienceRestriction is configured)",
				module.ErrInvalidCredential)
		}
		found := false
		for _, ar := range assertion.Conditions.AudienceRestrictions {
			for _, aud := range ar.Audiences {
				if aud == i.audienceRestriction {
					found = true
					break
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: saml: audience restriction not satisfied",
				module.ErrInvalidCredential)
		}
	}

	// G9-VULN-02: Validate SubjectConfirmation / Recipient.
	// Per SAML 2.0 Core §2.4.1.2, the SP must verify that
	// SubjectConfirmationData@Recipient matches its own ACS URL.
	// G9-VULN-12: Validate SubjectConfirmation Method is bearer.
	// G9-VULN-11: Validate SubjectConfirmationData@NotOnOrAfter has not passed.
	// SAML-VULN-01: SubjectConfirmation MUST be present per SAML 2.0
	// Profiles §4.1.4.2. Without it, there is no proof the assertion was
	// intended for this SP, enabling cross-SP replay.
	if len(assertion.Subject.SubjectConfirmations) == 0 {
		return nil, fmt.Errorf("%w: saml: assertion has no SubjectConfirmation (required per SAML 2.0 Profiles §4.1.4.2)",
			module.ErrInvalidCredential)
	}
	{
		validConfirmation := false
		for _, sc := range assertion.Subject.SubjectConfirmations {
			// G9-VULN-12: Only accept bearer confirmation method.
			// Per SAML 2.0 Profiles §4.1.4.2, the SP must verify that the
			// Method is urn:oasis:names:tc:SAML:2.0:cm:bearer for Web Browser SSO.
			if sc.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
				continue
			}
			// G9-VULN-02: Validate Recipient matches entityId.
			if i.entityID != "" && sc.SubjectConfirmationData.Recipient != "" && sc.SubjectConfirmationData.Recipient != i.entityID {
				continue
			}
			// G9-VULN-11: Validate NotOnOrAfter is present and not expired.
			// Per SAML 2.0 Core §2.4.1.2, the SP MUST verify that the current
			// time is before NotOnOrAfter on SubjectConfirmationData.
			if sc.SubjectConfirmationData.NotOnOrAfter == "" {
				continue
			}
			scNOA, err := time.Parse(time.RFC3339, sc.SubjectConfirmationData.NotOnOrAfter)
			if err != nil {
				continue
			}
			if now.Add(-i.maxClockSkew).After(scNOA) {
				continue
			}
			validConfirmation = true
			break
		}
		if !validConfirmation {
			return nil, fmt.Errorf("%w: saml: no valid SubjectConfirmation: requires Method=bearer, valid Recipient, and unexpired NotOnOrAfter",
				module.ErrInvalidCredential)
		}
	}

	// Validate signature (certificate verification).
	if err := i.verifySignature(resp, decoded); err != nil {
		return nil, fmt.Errorf("%w: saml: %v", module.ErrInvalidCredential, err)
	}

	// G9-VULN-01: Bind the signed Reference to the deserialized assertion.
	// Prevents XML Signature Wrapping (XSW) where an attacker injects a
	// forged assertion as the first child and hides the signed assertion
	// elsewhere in the document.
	if err := i.validateSignatureCoversAssertion(resp); err != nil {
		return nil, fmt.Errorf("%w: saml: %v", module.ErrInvalidCredential, err)
	}

	// G9-06: Replay protection — reject assertions already seen.
	assertionID := assertion.ID
	if assertionID == "" {
		return nil, fmt.Errorf("%w: saml: assertion has no ID attribute (required for replay protection)",
			module.ErrInvalidCredential)
	}
	// TTL = NotOnOrAfter + skew (we already parsed and validated NotOnOrAfter above).
	noa, _ := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
	replayTTL := time.Until(noa) + i.maxClockSkew
	if replayTTL < time.Minute {
		replayTTL = time.Minute
	}
	if !i.replayCache.Add(assertionID, replayTTL) {
		return nil, fmt.Errorf("%w: saml: assertion ID %q already consumed (replay detected)",
			module.ErrInvalidCredential, assertionID)
	}

	// Extract subject.
	subject := assertion.Subject.NameID.Value

	// Extract attributes into claims.
	claims := map[string]any{
		"nameId":     subject,
		"nameFormat": assertion.Subject.NameID.Format,
	}
	attrMap := i.extractAttributes(assertion.AttributeStatements)
	for claimName, samlAttr := range i.attributeMapping {
		if vals, ok := attrMap[samlAttr]; ok {
			if len(vals) == 1 {
				claims[claimName] = vals[0]
			} else {
				claims[claimName] = vals
			}
		}
	}
	// Also include SessionIndex if present.
	if assertion.AuthnStatement.SessionIndex != "" {
		claims["sessionIndex"] = assertion.AuthnStatement.SessionIndex
	}

	return &module.Identity{
		Subject: subject,
		Claims:  claims,
		Source:  i.name,
	}, nil
}

// verifySignature validates the SAML response signature cryptographically
// against the IdP certificate's public key.
//
// Safe for concurrent use (reads only immutable fields).
func (i *identifier) verifySignature(resp samlResponse, raw []byte) error {
	if i.idpCert == nil {
		return fmt.Errorf("idpCertPEM is required for signature verification")
	}

	// Check that a signature is present.
	if resp.Signature.SignatureValue == "" && resp.Assertion.Signature.SignatureValue == "" {
		return fmt.Errorf("no signature present in response or assertion")
	}

	// Check IdP certificate validity.
	now := time.Now()
	if now.Before(i.idpCert.NotBefore) || now.After(i.idpCert.NotAfter) {
		return fmt.Errorf("IdP certificate expired or not yet valid")
	}

	// Select the signature to verify (response-level or assertion-level).
	sig := resp.Signature
	if sig.SignatureValue == "" {
		sig = resp.Assertion.Signature
	}
	if sig.SignatureValue == "" {
		return fmt.Errorf("no signature value found")
	}

	// Validate that the signature algorithm is acceptable.
	alg := sig.SignedInfo.SignatureMethod.Algorithm
	if !isAcceptableSignatureAlgorithm(alg) {
		return fmt.Errorf("unacceptable signature algorithm: %s", alg)
	}

	// Verify digest references are non-empty.
	for _, ref := range sig.SignedInfo.References {
		if ref.DigestValue == "" {
			return fmt.Errorf("empty digest value in signature reference")
		}
	}

	// G9-07: Verify that the digest of the referenced content matches
	// the DigestValue declared in SignedInfo. Without this, an attacker
	// can modify assertion content while reusing a valid signature.
	if err := i.verifyDigestReferences(sig, raw); err != nil {
		return err
	}

	// Decode the signature value from base64.
	sigBytes, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(sig.SignatureValue))
	if err != nil {
		return fmt.Errorf("invalid base64 in SignatureValue: %w", err)
	}
	if len(sigBytes) == 0 {
		return fmt.Errorf("empty SignatureValue after decode")
	}

	// Extract the raw <SignedInfo>...</SignedInfo> element bytes from
	// within the specific <Signature> block being verified. Searching
	// only within the parent prevents XML Signature Wrapping (XSW)
	// attacks where an attacker injects a second Signature earlier in
	// the document.
	signedInfoBytes, err := extractSignedInfo(raw, sig.SignatureValue)
	if err != nil {
		return fmt.Errorf("extract SignedInfo: %w", err)
	}

	// Compute the hash of SignedInfo using the algorithm from SignatureMethod.
	hashAlg, err := signatureAlgorithmToHash(alg)
	if err != nil {
		return err
	}
	h := hashAlg.New()
	h.Write(signedInfoBytes)
	digest := h.Sum(nil)

	// Verify the cryptographic signature using the IdP certificate's public key.
	switch pub := i.idpCert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, sigBytes); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sigBytes) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}

	return nil
}

// validateSignatureCoversAssertion ensures that the cryptographically
// verified signature actually covers the assertion we are about to trust.
// This prevents XML Signature Wrapping (XSW) attacks where an attacker
// injects a forged assertion as the first child of <Response> while hiding
// the legitimately signed assertion elsewhere in the document.
//
// Safe for concurrent use (reads only immutable fields).
func (i *identifier) validateSignatureCoversAssertion(resp samlResponse) error {
	assertionID := resp.Assertion.ID
	if assertionID == "" {
		// Already caught by replay-protection check, but belt-and-suspenders.
		return fmt.Errorf("assertion has no ID attribute")
	}

	// Check response-level signature first, then assertion-level.
	sig := resp.Signature
	if sig.SignatureValue == "" {
		sig = resp.Assertion.Signature
	}

	// At least one Reference must target "#<assertionID>" or the entire
	// document (URI=""). If the signature is assertion-level (embedded),
	// URI="" is acceptable because enveloped-signature covers the parent.
	for _, ref := range sig.SignedInfo.References {
		if ref.URI == "" {
			return nil // whole-document reference covers the assertion
		}
		if ref.URI == "#"+assertionID {
			return nil // explicitly references our assertion
		}
	}

	return fmt.Errorf("signature does not cover the deserialized assertion (ID=%q); possible XSW attack", assertionID)
}

// verifyDigestReferences ensures each Reference in SignedInfo has a
// DigestValue that matches the actual content. This prevents an attacker
// from tampering with assertion content while reusing a valid signature
// over unchanged SignedInfo bytes.
//
// Safe for concurrent use (reads only immutable fields).
func (i *identifier) verifyDigestReferences(sig xmldsigSignature, raw []byte) error {
	for _, ref := range sig.SignedInfo.References {
		// G9-VULN-04: Validate Transform algorithms. Only accept
		// enveloped-signature and exc-c14n (which we approximate with
		// raw byte extraction from the same document). Reject unknown
		// transforms that could alter content in ways we don't handle.
		if err := validateTransforms(ref.Transforms); err != nil {
			return fmt.Errorf("reference %q: %w", ref.URI, err)
		}

		// Determine which element the reference points to.
		refContent, err := resolveReference(ref.URI, raw)
		if err != nil {
			return fmt.Errorf("resolve reference %q: %w", ref.URI, err)
		}

		// Apply enveloped-signature transform: remove <Signature>...</Signature>
		// from the referenced element before computing digest.
		refContent = applyEnvelopedSignatureTransform(refContent)

		// Determine digest algorithm. Default to SHA-256 if not specified.
		digestAlg := ref.DigestMethod.Algorithm
		if digestAlg == "" {
			digestAlg = "http://www.w3.org/2001/04/xmlenc#sha256"
		}
		hashFunc, err := digestAlgorithmToHash(digestAlg)
		if err != nil {
			return err
		}

		// Compute digest of referenced content.
		h := hashFunc.New()
		h.Write(refContent)
		computedDigest := h.Sum(nil)

		// Decode the declared DigestValue.
		declaredDigest, err := base64.StdEncoding.DecodeString(
			strings.TrimSpace(ref.DigestValue))
		if err != nil {
			return fmt.Errorf("invalid base64 in DigestValue: %w", err)
		}

		// Compare digests.
		if !bytes.Equal(computedDigest, declaredDigest) {
			return fmt.Errorf("digest mismatch for reference %q: assertion content was tampered with", ref.URI)
		}
	}
	return nil
}

// resolveReference extracts the XML element identified by a Reference URI.
// URI="" means the entire document; URI="#id" means the element with that ID.
func resolveReference(uri string, raw []byte) ([]byte, error) {
	if uri == "" {
		// Empty URI = entire document.
		return raw, nil
	}

	if !strings.HasPrefix(uri, "#") {
		return nil, fmt.Errorf("unsupported Reference URI scheme: %q (only fragment references supported)", uri)
	}

	// Fragment reference: find element with matching ID attribute.
	targetID := uri[1:] // strip leading '#'

	// Search for element with ID="targetID" or Id="targetID".
	idPatterns := []string{
		`ID="` + targetID + `"`,
		`Id="` + targetID + `"`,
		`id="` + targetID + `"`,
	}

	for _, pattern := range idPatterns {
		patBytes := []byte(pattern)
		searchFrom := 0
		for {
			idx := bytes.Index(raw[searchFrom:], patBytes)
			if idx < 0 {
				break
			}
			absIdx := searchFrom + idx
			searchFrom = absIdx + len(patBytes)

			// G9-VULN-09: Ensure the match is inside an element tag, not
			// inside an XML comment (<!-- ... -->) or CDATA (<![CDATA[...]]>)
			// section, which an attacker could inject to poison the search.
			if isInsideCommentOrCDATA(raw, absIdx) {
				continue
			}

			// Walk backwards to find the start of the element tag.
			elemStart := bytes.LastIndex(raw[:absIdx], []byte("<"))
			if elemStart < 0 {
				continue
			}

			// Determine the element name to find its closing tag.
			afterLT := raw[elemStart+1:]
			spaceIdx := bytes.IndexAny(afterLT, " \t\r\n>")
			if spaceIdx < 0 {
				continue
			}
			elemName := string(afterLT[:spaceIdx])

			// Handle namespace-prefixed element names.
			closingTag := []byte("</" + elemName + ">")
			closeIdx := bytes.Index(raw[elemStart:], closingTag)
			if closeIdx < 0 {
				continue
			}

			return raw[elemStart : elemStart+closeIdx+len(closingTag)], nil
		}
	}

	return nil, fmt.Errorf("element with ID %q not found in XML", targetID)
}

// isInsideCommentOrCDATA checks whether the byte position `pos` falls
// inside an XML comment (<!-- ... -->) or CDATA section (<![CDATA[...]]>).
// An attacker could inject ID="target" inside a comment to misdirect
// resolveReference's byte search.
func isInsideCommentOrCDATA(raw []byte, pos int) bool {
	// Check for comment: find the last "<!--" before pos and see if
	// there's no corresponding "-->" between it and pos.
	prefix := raw[:pos]
	commentStart := bytes.LastIndex(prefix, []byte("<!--"))
	if commentStart >= 0 {
		commentEnd := bytes.Index(raw[commentStart:pos], []byte("-->"))
		if commentEnd < 0 {
			return true // inside an unclosed comment
		}
	}

	// Check for CDATA: find the last "<![CDATA[" before pos.
	cdataStart := bytes.LastIndex(prefix, []byte("<![CDATA["))
	if cdataStart >= 0 {
		cdataEnd := bytes.Index(raw[cdataStart:pos], []byte("]]>"))
		if cdataEnd < 0 {
			return true // inside an unclosed CDATA
		}
	}

	return false
}

// applyEnvelopedSignatureTransform removes <Signature>...</Signature>
// elements from within the content (the Enveloped Signature Transform
// per XML-DSIG spec). The signature is embedded in the signed element,
// so it must be excluded before computing the digest.
func applyEnvelopedSignatureTransform(content []byte) []byte {
	sigMarkers := []struct{ start, end []byte }{
		{[]byte("<Signature"), []byte("</Signature>")},
		{[]byte("<ds:Signature"), []byte("</ds:Signature>")},
	}

	result := content
	for _, m := range sigMarkers {
		for {
			startIdx := bytes.Index(result, m.start)
			if startIdx < 0 {
				break
			}
			endIdx := bytes.Index(result[startIdx:], m.end)
			if endIdx < 0 {
				break
			}
			endAbs := startIdx + endIdx + len(m.end)
			newResult := make([]byte, 0, len(result)-(endAbs-startIdx))
			newResult = append(newResult, result[:startIdx]...)
			newResult = append(newResult, result[endAbs:]...)
			result = newResult
		}
	}
	return result
}

// allowedTransforms are the only XML-DSIG transform algorithms we support.
// Accepting unknown transforms could let an attacker smuggle content changes
// that our digest computation doesn't account for.
var allowedTransforms = map[string]bool{
	// Enveloped Signature Transform (required for assertion-level sigs).
	"http://www.w3.org/2000/09/xmldsig#enveloped-signature": true,
	// Exclusive Canonicalization (with and without comments).
	"http://www.w3.org/2001/10/xml-exc-c14n#":             true,
	"http://www.w3.org/2001/10/xml-exc-c14n#WithComments": true,
	// Canonical XML 1.0 / 1.1.
	"http://www.w3.org/TR/2001/REC-xml-c14n-20010315":              true,
	"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": true,
	"http://www.w3.org/2006/12/xml-c14n11":                         true,
	"http://www.w3.org/2006/12/xml-c14n11#WithComments":            true,
}

// validateTransforms rejects any Reference that declares a transform
// algorithm we do not implement or recognise.
func validateTransforms(transforms []xmldsigTransform) error {
	for _, t := range transforms {
		if !allowedTransforms[t.Algorithm] {
			return fmt.Errorf("unsupported Transform algorithm: %q", t.Algorithm)
		}
	}
	return nil
}

// digestAlgorithmToHash maps XML digest algorithm URIs to Go crypto hashes.
// G9-VULN-06: SHA-1 removed — only SHA-256+ accepted.
func digestAlgorithmToHash(alg string) (crypto.Hash, error) {
	switch alg {
	case "http://www.w3.org/2001/04/xmlenc#sha256",
		"http://www.w3.org/2001/04/xmldsig-more#sha256":
		return crypto.SHA256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#sha384":
		return crypto.SHA384, nil
	case "http://www.w3.org/2001/04/xmlenc#sha512",
		"http://www.w3.org/2001/04/xmldsig-more#sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported digest algorithm: %s", alg)
	}
}

// extractSignedInfo locates the <Signature> block containing the given
// SignatureValue and extracts the <SignedInfo>...</SignedInfo> bytes from
// within it. This binds the cryptographic verification to the correct
// parent Signature, preventing XML Signature Wrapping (XSW) attacks.
func extractSignedInfo(raw []byte, sigValue string) ([]byte, error) {
	// Use a portion of the SignatureValue to identify the correct
	// <Signature> block. Trim whitespace to match XML text content.
	needle := []byte(strings.TrimSpace(sigValue))
	if len(needle) == 0 {
		return nil, fmt.Errorf("empty SignatureValue; cannot locate parent Signature")
	}

	sigStartMarkers := [][]byte{
		[]byte("<Signature"),
		[]byte("<ds:Signature"),
	}
	sigEndMarkers := [][]byte{
		[]byte("</Signature>"),
		[]byte("</ds:Signature>"),
	}

	// Iterate all <Signature> blocks to find the one containing our value.
	for mi, startMarker := range sigStartMarkers {
		searchFrom := 0
		for {
			idx := bytes.Index(raw[searchFrom:], startMarker)
			if idx < 0 {
				break
			}
			absStart := searchFrom + idx
			endIdx := bytes.Index(raw[absStart:], sigEndMarkers[mi])
			if endIdx < 0 {
				break
			}
			sigBlock := raw[absStart : absStart+endIdx+len(sigEndMarkers[mi])]

			// Check if this Signature block contains our SignatureValue.
			if bytes.Contains(sigBlock, needle) {
				return extractSignedInfoFromBlock(sigBlock)
			}
			searchFrom = absStart + endIdx + len(sigEndMarkers[mi])
		}
	}
	return nil, fmt.Errorf("Signature element containing the verified SignatureValue not found in XML")
}

// extractSignedInfoFromBlock extracts <SignedInfo>...</SignedInfo> bytes
// from within a single <Signature> block.
func extractSignedInfoFromBlock(sigBlock []byte) ([]byte, error) {
	startMarkers := [][]byte{
		[]byte("<SignedInfo"),
		[]byte("<ds:SignedInfo"),
	}
	endMarkers := [][]byte{
		[]byte("</SignedInfo>"),
		[]byte("</ds:SignedInfo>"),
	}

	for mi, marker := range startMarkers {
		idx := bytes.Index(sigBlock, marker)
		if idx >= 0 {
			endIdx := bytes.Index(sigBlock[idx:], endMarkers[mi])
			if endIdx >= 0 {
				return sigBlock[idx : idx+endIdx+len(endMarkers[mi])], nil
			}
		}
	}
	return nil, fmt.Errorf("SignedInfo element not found within Signature block")
}

// signatureAlgorithmToHash maps XML signature algorithm URIs to Go crypto hashes.
// G9-VULN-06: SHA-1 removed — only SHA-256+ accepted.
func signatureAlgorithmToHash(alg string) (crypto.Hash, error) {
	switch alg {
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":
		return crypto.SHA256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":
		return crypto.SHA384, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported signature algorithm: %s", alg)
	}
}

func isAcceptableSignatureAlgorithm(alg string) bool {
	// G9-VULN-06: SHA-1 is deprecated due to demonstrated collision attacks
	// (SHAttered, 2017). Only SHA-256+ algorithms are accepted.
	acceptable := map[string]bool{
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   true,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   true,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": true,
	}
	return acceptable[alg]
}

func (i *identifier) extractAttributes(stmts []attributeStatement) map[string][]string {
	result := map[string][]string{}
	for _, stmt := range stmts {
		for _, attr := range stmt.Attributes {
			var vals []string
			for _, v := range attr.Values {
				vals = append(vals, v.Value)
			}
			result[attr.Name] = vals
		}
	}
	return result
}

// --- Assertion Replay Cache ------------------------------------------------

// defaultReplayCacheSize is the maximum number of assertion IDs tracked.
const defaultReplayCacheSize = 10000

// assertionReplayCache tracks consumed assertion IDs to prevent replay.
// It uses an LRU-style eviction with time-based expiry.
//
// All exported methods are safe for concurrent use; internal helpers
// (evictExpired, evictOldest) must only be called while holding mu.
type assertionReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // assertion ID → expiry time
	maxSize int
}

func newReplayCache(maxSize int) *assertionReplayCache {
	if maxSize <= 0 {
		maxSize = defaultReplayCacheSize
	}
	return &assertionReplayCache{
		entries: make(map[string]time.Time, maxSize/2),
		maxSize: maxSize,
	}
}

// Add records an assertion ID. Returns true if the ID was new (not a replay),
// false if it was already seen (replay detected).
//
// Safe for concurrent use.
func (c *assertionReplayCache) Add(id string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Check if already present and not yet expired.
	if expiry, exists := c.entries[id]; exists {
		if now.Before(expiry) {
			return false // replay detected
		}
		// Expired entry — allow reuse (though in practice assertion IDs
		// should be unique, this handles clock edge cases).
	}

	// Evict expired entries if we're at capacity.
	if len(c.entries) >= c.maxSize {
		c.evictExpired(now)
	}
	// G9-VULN-07: If still at capacity after eviction, reject the new
	// assertion rather than evicting unexpired entries. Evicting live
	// entries under a flood attack would open a bounded replay window.
	if len(c.entries) >= c.maxSize {
		return false
	}

	c.entries[id] = now.Add(ttl)
	return true
}

// evictExpired removes all entries whose expiry has passed.
// NOT safe for concurrent use; must be called while holding c.mu.
func (c *assertionReplayCache) evictExpired(now time.Time) {
	for id, expiry := range c.entries {
		if now.After(expiry) {
			delete(c.entries, id)
		}
	}
}

// evictOldest removes the entry with the earliest expiry time.
// NOT safe for concurrent use; must be called while holding c.mu.
func (c *assertionReplayCache) evictOldest() {
	var oldestID string
	var oldestTime time.Time
	first := true
	for id, expiry := range c.entries {
		if first || expiry.Before(oldestTime) {
			oldestID = id
			oldestTime = expiry
			first = false
		}
	}
	if oldestID != "" {
		delete(c.entries, oldestID)
	}
}

// --- SAML XML types --------------------------------------------------------

const statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// G9-VULN-08: Pin the SAML protocol namespace to reject responses from
// non-SAML XML documents that happen to have a <Response> root element.
type samlResponse struct {
	XMLName     xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Destination string           `xml:"Destination,attr"`
	Issuer      string           `xml:"Issuer"`
	Status      samlStatus       `xml:"Status"`
	Assertion   samlAssertion    `xml:"Assertion"`
	Signature   xmldsigSignature `xml:"Signature"`
}

type samlStatus struct {
	StatusCode samlStatusCode `xml:"StatusCode"`
}

type samlStatusCode struct {
	Value string `xml:"Value,attr"`
}

type samlAssertion struct {
	ID                  string               `xml:"ID,attr"`
	Issuer              string               `xml:"Issuer"`
	Subject             samlSubject          `xml:"Subject"`
	Conditions          samlConditions       `xml:"Conditions"`
	AuthnStatement      samlAuthnStatement   `xml:"AuthnStatement"`
	AttributeStatements []attributeStatement `xml:"AttributeStatement"`
	Signature           xmldsigSignature     `xml:"Signature"`
}

type samlSubject struct {
	NameID               samlNameID                `xml:"NameID"`
	SubjectConfirmations []samlSubjectConfirmation `xml:"SubjectConfirmation"`
}

type samlSubjectConfirmation struct {
	Method                  string                      `xml:"Method,attr"`
	SubjectConfirmationData samlSubjectConfirmationData `xml:"SubjectConfirmationData"`
}

type samlSubjectConfirmationData struct {
	Recipient    string `xml:"Recipient,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
}

type samlNameID struct {
	Value  string `xml:",chardata"`
	Format string `xml:"Format,attr"`
}

type samlConditions struct {
	NotBefore            string                    `xml:"NotBefore,attr"`
	NotOnOrAfter         string                    `xml:"NotOnOrAfter,attr"`
	AudienceRestrictions []samlAudienceRestriction `xml:"AudienceRestriction"`
}

type samlAudienceRestriction struct {
	Audiences []string `xml:"Audience"`
}

type samlAuthnStatement struct {
	SessionIndex string `xml:"SessionIndex,attr"`
}

type attributeStatement struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string          `xml:"Name,attr"`
	Values []samlAttrValue `xml:"AttributeValue"`
}

type samlAttrValue struct {
	Value string `xml:",chardata"`
}

type xmldsigSignature struct {
	SignedInfo     xmldsigSignedInfo `xml:"SignedInfo"`
	SignatureValue string            `xml:"SignatureValue"`
}

type xmldsigSignedInfo struct {
	SignatureMethod xmldsigAlgorithm   `xml:"SignatureMethod"`
	References      []xmldsigReference `xml:"Reference"`
}

type xmldsigAlgorithm struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type xmldsigReference struct {
	URI          string             `xml:"URI,attr"`
	Transforms   []xmldsigTransform `xml:"Transforms>Transform"`
	DigestMethod xmldsigAlgorithm   `xml:"DigestMethod"`
	DigestValue  string             `xml:"DigestValue"`
}

type xmldsigTransform struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// --- Factory ---------------------------------------------------------------

var knownKeys = map[string]struct{}{
	"idpCertPEM":          {},
	"entityId":            {},
	"issuer":              {},
	"audienceRestriction": {},
	"maxClockSkew":        {},
	"attributeMapping":    {},
	"header":              {},
	"formField":           {},
}

func factory(name string, raw map[string]any) (module.Identifier, error) {
	if err := module.CheckUnknownKeys("saml", name, raw, knownKeys); err != nil {
		return nil, err
	}

	id := &identifier{
		name:             name,
		maxClockSkew:     30 * time.Second,
		header:           "X-SAML-Response",
		formField:        "SAMLResponse",
		attributeMapping: map[string]string{},
		replayCache:      newReplayCache(defaultReplayCacheSize),
	}

	if v, ok := raw["idpCertPEM"].(string); ok && v != "" {
		block, _ := pem.Decode([]byte(v))
		if block == nil {
			return nil, fmt.Errorf("%w: saml: invalid PEM in idpCertPEM", module.ErrConfig)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: saml: parse idpCertPEM: %v", module.ErrConfig, err)
		}
		id.idpCert = cert
	} else {
		return nil, fmt.Errorf("%w: saml: idpCertPEM is required for signature verification", module.ErrConfig)
	}

	if v, ok := raw["entityId"].(string); ok && v != "" {
		id.entityID = v
	} else {
		// SAML-VULN-02: entityId is required. Without it, Destination
		// and SubjectConfirmation Recipient checks are silently
		// disabled, enabling cross-SP assertion replay.
		return nil, fmt.Errorf("%w: saml: entityId is required (SP assertion consumer service URL)", module.ErrConfig)
	}
	if v, ok := raw["issuer"].(string); ok {
		id.issuer = v
	}
	if v, ok := raw["audienceRestriction"].(string); ok && v != "" {
		id.audienceRestriction = v
	} else {
		// SAML-VULN-04: audienceRestriction is required. Without it, assertions
		// intended for other SPs sharing the same IdP are silently accepted.
		return nil, fmt.Errorf("%w: saml: audienceRestriction is required (prevents cross-SP assertion acceptance)", module.ErrConfig)
	}
	if v, ok := raw["maxClockSkew"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%w: saml: maxClockSkew: %v", module.ErrConfig, err)
		}
		// SAML-VULN-03: Cap clock skew to prevent misconfiguration from
		// creating an indefinite assertion acceptance window.
		if d > maxAllowedClockSkew {
			return nil, fmt.Errorf("%w: saml: maxClockSkew %v exceeds maximum allowed (%v)", module.ErrConfig, d, maxAllowedClockSkew)
		}
		if d < 0 {
			return nil, fmt.Errorf("%w: saml: maxClockSkew must not be negative", module.ErrConfig)
		}
		id.maxClockSkew = d
	}
	if v, ok := raw["header"].(string); ok && v != "" {
		id.header = v
	}
	if v, ok := raw["formField"].(string); ok && v != "" {
		id.formField = v
	}
	if v, ok := raw["attributeMapping"].(map[string]any); ok {
		for k, val := range v {
			if s, ok := val.(string); ok {
				id.attributeMapping[k] = s
			}
		}
	}

	return id, nil
}

// containsControlChar reports whether s contains any ASCII control character
// (bytes 0x00–0x1F or 0x7F) or Unicode control category characters.
// SAML-VULN-06: prevents log injection / audit evasion via crafted NameIDs.
func containsControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7F || unicode.IsControl(r) {
			return true
		}
	}
	return false
}
