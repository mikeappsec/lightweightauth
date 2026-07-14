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
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"sync"
	"time"
	"unicode"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/mikeappsec/lightweightauth/internal/replay"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func init() { module.RegisterIdentifierWithDeps("saml", factoryWithDeps) }

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
	replay              *replay.Guard
}

// Name returns the configured identifier name. Safe for concurrent use.
func (i *identifier) Name() string { return i.name }

// Identify extracts a SAML Response from the request (either from a header
// or POST form field), validates the assertion signature and temporal
// constraints, and returns the extracted Identity.
//
// Safe for concurrent use.
func (i *identifier) Identify(ctx context.Context, r *module.Request) (*module.Identity, error) {
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

	// Parse SAML Response XML (outer envelope only — Destination/Issuer/
	// Status are not covered by an assertion-level signature, matching
	// long-standing behavior; see verifyAndExtractAssertion for the
	// cryptographically verified assertion content).
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

	// Cryptographically verify the signature (assertion-level or
	// response-level, whichever is present) and extract ONLY the verified
	// Assertion content. Every check below reads from `assertion` — never
	// from a separately parsed copy of the raw response — which is what
	// prevents XML Signature Wrapping (XSW): a candidate element is
	// trusted only if goxmldsig itself found and verified a signature over
	// that specific element. See verifyAndExtractAssertion's doc comment.
	assertion, err := i.verifyAndExtractAssertion(decoded)
	if err != nil {
		return nil, fmt.Errorf("%w: saml: %v", module.ErrInvalidCredential, err)
	}

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
			// G9-VULN-02: Validate Recipient matches entityId. Recipient
			// is REQUIRED on bearer confirmations per SAML 2.0 Profiles
			// §4.1.4.2 — an empty Recipient must fail this check like any
			// other mismatch, not be treated as "no opinion."
			if i.entityID != "" && sc.SubjectConfirmationData.Recipient != i.entityID {
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
	firstUse, rerr := i.replay.Consume(ctx, assertionID, replayTTL)
	if rerr != nil {
		return nil, fmt.Errorf("%w: saml: replay check: %v", module.ErrUpstream, rerr)
	}
	if !firstUse {
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

// samlProtocolNS / samlAssertionNS are the SAML 2.0 XML namespaces. G9-VULN-08:
// pinning these rejects non-SAML documents that happen to reuse element names.
const (
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
)

// acceptableSignatureAlgorithms / acceptableDigestAlgorithms enforce a
// SHA-256+ floor on top of goxmldsig's own cryptographic acceptance.
// G9-VULN-06: SHA-1 is deprecated (SHAttered, 2017), but goxmldsig itself
// accepts it for legacy interop — we must reject it ourselves.
var acceptableSignatureAlgorithms = map[string]bool{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   true,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   true,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": true,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": true,
}

var acceptableDigestAlgorithms = map[string]bool{
	"http://www.w3.org/2001/04/xmlenc#sha256":       true,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
	"http://www.w3.org/2001/04/xmlenc#sha512":       true,
}

// verifyAndExtractAssertion cryptographically verifies the SAML Response's
// XML signature using goxmldsig (real C14N canonicalization and XML-DSIG
// Reference/digest semantics, replacing a hand-rolled byte-scanning
// implementation that both used the wrong ECDSA signature encoding and
// skipped canonicalization entirely) and returns the single verified
// Assertion, re-parsed from exactly the bytes goxmldsig validated.
//
// Every downstream business-logic check in Identify reads from the
// returned assertion, never from a separately parsed copy of the raw
// response. This is what prevents XML Signature Wrapping (XSW): a
// candidate element is trusted only if goxmldsig itself found and verified
// a signature over that specific element — an attacker's decoy assertion
// simply has no valid signature over its own ID to be found.
//
// Safe for concurrent use (reads only immutable fields).
func (i *identifier) verifyAndExtractAssertion(decoded []byte) (*samlAssertion, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(decoded); err != nil {
		return nil, fmt.Errorf("invalid XML: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != samlProtocolNS {
		return nil, fmt.Errorf("root element is not a SAML Response")
	}

	assertionEl, err := singleAssertionChild(root)
	if err != nil {
		return nil, err
	}

	certStore := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{i.idpCert}}
	ctx := dsig.NewDefaultValidationContext(certStore)

	var validatedAssertionEl *etree.Element
	var signedEl *etree.Element // element whose embedded Signature we policy-check below

	if v, verr := ctx.Validate(assertionEl); verr == nil {
		validatedAssertionEl = v
		signedEl = assertionEl
	} else {
		// No valid assertion-level signature — fall back to a
		// response-level (whole-document) signature, then take the
		// Assertion from WITHIN the validated Response element so it's
		// still the crypto-verified copy, not a separate parse.
		v2, verr2 := ctx.Validate(root)
		if verr2 != nil {
			return nil, fmt.Errorf("signature verification failed: %v", verr)
		}
		inner, ierr := singleAssertionChild(v2)
		if ierr != nil {
			return nil, ierr
		}
		validatedAssertionEl = inner
		signedEl = root
	}

	sigEl := findSignatureRecursive(signedEl)
	if sigEl == nil {
		return nil, fmt.Errorf("no signature present in response or assertion")
	}
	sigAlg, digestAlg := signatureAlgorithms(sigEl)
	if !acceptableSignatureAlgorithms[sigAlg] {
		return nil, fmt.Errorf("unacceptable signature algorithm: %s", sigAlg)
	}
	if !acceptableDigestAlgorithms[digestAlg] {
		return nil, fmt.Errorf("unacceptable digest algorithm: %s", digestAlg)
	}

	// Re-serialize the exact, signature-verified element and re-parse it
	// into the typed struct so all downstream checks operate on what was
	// actually signed, never a separately parsed copy.
	outDoc := etree.NewDocument()
	outDoc.SetRoot(validatedAssertionEl)
	assertionBytes, err := outDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize validated assertion: %w", err)
	}
	var assertion samlAssertion
	if err := xml.Unmarshal(assertionBytes, &assertion); err != nil {
		return nil, fmt.Errorf("unmarshal validated assertion: %w", err)
	}
	return &assertion, nil
}

// singleAssertionChild returns el's sole direct-child <Assertion> element in
// the SAML assertion namespace, rejecting documents with zero or multiple
// candidates. Requiring exactly one closes off decoy-assertion smuggling at
// the parsing layer, independent of the signature check that follows.
func singleAssertionChild(el *etree.Element) (*etree.Element, error) {
	var found []*etree.Element
	for _, child := range el.ChildElements() {
		if child.Tag == "Assertion" && child.NamespaceURI() == samlAssertionNS {
			found = append(found, child)
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("expected exactly one Assertion element, found %d", len(found))
	}
	return found[0], nil
}

// findSignatureRecursive locates the first ds:Signature element anywhere
// within el's subtree, for post-hoc algorithm-policy inspection (see
// acceptableSignatureAlgorithms/acceptableDigestAlgorithms) — goxmldsig has
// already cryptographically verified it by the time this is called.
func findSignatureRecursive(el *etree.Element) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == "Signature" && c.NamespaceURI() == dsig.Namespace {
			return c
		}
		if found := findSignatureRecursive(c); found != nil {
			return found
		}
	}
	return nil
}

// signatureAlgorithms extracts the declared SignatureMethod and (first
// Reference's) DigestMethod algorithm URIs from a ds:Signature element.
func signatureAlgorithms(sigEl *etree.Element) (sigMethod, digestMethod string) {
	signedInfo := firstChildByTag(sigEl, "SignedInfo")
	if signedInfo == nil {
		return "", ""
	}
	if sm := firstChildByTag(signedInfo, "SignatureMethod"); sm != nil {
		sigMethod = sm.SelectAttrValue("Algorithm", "")
	}
	if ref := firstChildByTag(signedInfo, "Reference"); ref != nil {
		if dm := firstChildByTag(ref, "DigestMethod"); dm != nil {
			digestMethod = dm.SelectAttrValue("Algorithm", "")
		}
	}
	return sigMethod, digestMethod
}

func firstChildByTag(el *etree.Element, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}
	return nil
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

// Consume implements replay.LocalStore so this bounded, fail-closed-at-capacity
// assertion cache can serve as the in-process fallback for replay.Guard. It
// preserves G9-VULN-07: a flood of distinct IDs is rejected at capacity rather
// than evicting live entries.
func (c *assertionReplayCache) Consume(id string, ttl time.Duration) bool { return c.Add(id, ttl) }

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
	XMLName     xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Destination string     `xml:"Destination,attr"`
	Issuer      string     `xml:"Issuer"`
	Status      samlStatus `xml:"Status"`
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

	// Default to the in-process bounded, fail-closed-at-capacity assertion
	// cache (G9-VULN-07). factoryWithDeps re-wires this to also use a remote
	// cross-replica backend when one is configured.
	id.replay = replay.NewWithLocal(nil, id.replayCache)

	return id, nil
}

// factoryWithDeps is the deps-aware registration entrypoint. It builds the
// identifier via factory, then routes assertion-ID replay through the
// injected cache layer: the bounded assertion cache remains the in-process
// fallback while the Atomic/SetNX path engages only for a genuinely remote,
// cross-replica backend (e.g. Valkey).
func factoryWithDeps(name string, raw map[string]any, deps module.Deps) (module.Identifier, error) {
	id, err := factory(name, raw)
	if err != nil {
		return nil, err
	}
	samlID := id.(*identifier)
	samlID.replay = replay.NewWithLocal(deps.CacheProvider().Cache("replay"), samlID.replayCache)
	return samlID, nil
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
