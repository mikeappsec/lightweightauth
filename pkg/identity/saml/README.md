# pkg/identity/saml

SAML 2.0 assertion validator identifier module (G9 — ID-SAML-1).

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/saml"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

id, err := module.BuildIdentifier("saml", "corporate-idp", map[string]any{
    "idpCertPEM":          certPEM,
    "entityId":            "https://sp.example.com/saml",
    "issuer":              "https://idp.example.com/saml",
    "audienceRestriction": "https://sp.example.com/saml",
    "maxClockSkew":        "30s",
    "attributeMapping": map[string]any{
        "email":  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "groups": "http://schemas.xmlsoap.org/claims/Group",
    },
})
```

## Configuration

```yaml
identifiers:
  - name: corporate-idp
    type: saml
    config:
      idpCertPEM: |
        -----BEGIN CERTIFICATE-----
        ...
        -----END CERTIFICATE-----
      entityId: https://sp.example.com/saml
      issuer: https://idp.example.com/saml
      audienceRestriction: https://sp.example.com/saml
      maxClockSkew: 30s
      header: X-SAML-Response
      formField: SAMLResponse
      attributeMapping:
        email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
        groups: http://schemas.xmlsoap.org/claims/Group
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `idpCertPEM` | string | *required* | PEM-encoded IdP X.509 certificate for signature verification |
| `entityId` | string | *required* | SP entity ID (validates Response Destination and SubjectConfirmation Recipient) |
| `issuer` | string | — | Expected IdP issuer URI |
| `audienceRestriction` | string | *required* | Required audience value in assertion conditions — `factory()` fails with "audienceRestriction is required (prevents cross-SP assertion acceptance)" (SAML-VULN-04) if omitted |
| `maxClockSkew` | duration | `"30s"` | Tolerance for NotBefore/NotOnOrAfter validation |
| `header` | string | `"X-SAML-Response"` | HTTP header containing the Base64-encoded SAMLResponse |
| `formField` | string | `"SAMLResponse"` | POST form field name (POST binding) |
| `attributeMapping` | map | — | Claim name → SAML attribute name mapping |

## Features

- XML digital signature verification (RSA-SHA256, RSA-SHA384, RSA-SHA512, ECDSA-SHA256/384/512)
- SHA-1 rejected — only SHA-256+ signature and digest algorithms accepted (G9-VULN-06)
- NotBefore / NotOnOrAfter temporal validation with configurable clock skew
- Audience restriction validation
- Issuer pinning (Response and Assertion level)
- Response Destination validation (G9-VULN-03)
- SubjectConfirmation enforcement: at least one bearer confirmation MUST be present (SAML-VULN-01 fix)
- SubjectConfirmation Recipient validation (G9-VULN-02)
- `entityId` is mandatory at config time — prevents silent bypass of Destination and Recipient checks (SAML-VULN-02 fix)
- XML Signature Wrapping (XSW) protection — signature must cover the deserialized assertion (G9-VULN-01)
- Digest reference verification with transform allowlist (G9-VULN-04)
- Comment/CDATA injection bypass protection in ID resolution (G9-VULN-09)
- SAML protocol namespace pinning rejects non-SAML XML documents (G9-VULN-08)
- Replay detection with bounded assertion ID cache (G9-VULN-07)
- Subject extraction from NameID
- Attribute statement → claims mapping
- IdP certificate expiry checking

## How It Works

1. Extracts Base64-encoded SAML Response from the configured header.
2. Parses and validates the XML against the pinned SAML 2.0 protocol namespace.
3. Validates Response Destination against the configured `entityId`.
4. Validates Response and Assertion Issuer.
5. Validates temporal conditions (NotBefore, NotOnOrAfter) with clock skew tolerance.
6. Validates audience restriction.
7. Enforces SubjectConfirmation: at least one element with Method=bearer, valid Recipient matching `entityId`, and unexpired NotOnOrAfter MUST be present.
8. Verifies the XML digital signature (algorithm allowlist → digest verification → cryptographic verification).
9. Confirms the signature covers the assertion being trusted (anti-XSW).
10. Checks the assertion ID against the replay cache.
11. Extracts NameID subject and maps SAML attributes to claims.

## Thread Safety

| Type | Safe for concurrent use? | Notes |
|------|--------------------------|-------|
| `Identifier` | ✅ Yes | All fields immutable after construction; replay cache is mutex-protected |
| `assertionReplayCache` | ✅ Yes | `sync.Mutex` protects entries map |
| `assertionReplayCache.Add` | ✅ Yes | Acquires lock internally |
| `assertionReplayCache.evictExpired` | ❌ No | Internal helper; must only be called while holding the mutex |
| `assertionReplayCache.evictOldest` | ❌ No | Internal helper; must only be called while holding the mutex |

The `Identifier` is safe for concurrent use from the pipeline hot path. All configuration fields are set once at construction and never mutated. The replay cache uses a `sync.Mutex` for all reads and writes.
