# `saml` — SAML 2.0 assertion validator

Verifies SAML 2.0 assertions posted by an enterprise IdP (ADFS, Okta SAML,
Azure AD SAML, PingFederate). Validates the XML digital signature,
temporal conditions, audience restriction, and subject confirmation before
mapping SAML attributes to identity claims.

**Source:** [pkg/identity/saml](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/saml) — registered as `saml`.

## When to use

- IdP issues SAML 2.0 assertions rather than OIDC/JWT tokens (common with
  older enterprise IdPs and ADFS deployments).
- The assertion arrives as a Base64-encoded `SAMLResponse`, either in a
  request header or an HTML form POST field.

**Don't use** for OIDC/JWT-issuing IdPs — reach for [`jwt`](jwt.md) instead;
SAML and OIDC are not interchangeable even when the same IdP supports both.

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
      maxClockSkew: 30s              # default
      header: X-SAML-Response        # default
      formField: SAMLResponse        # default (POST binding)
      attributeMapping:
        email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
        groups: http://schemas.xmlsoap.org/claims/Group
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `idpCertPEM` | string | *required* | PEM-encoded IdP X.509 certificate for signature verification |
| `entityId` | string | *required* | SP entity ID — validates Response `Destination` and `SubjectConfirmation` `Recipient` |
| `issuer` | string | — | Expected IdP issuer URI |
| `audienceRestriction` | string | — | Required audience value in assertion conditions |
| `maxClockSkew` | duration | `"30s"` | Tolerance for `NotBefore`/`NotOnOrAfter` validation |
| `header` | string | `"X-SAML-Response"` | HTTP header containing the Base64-encoded `SAMLResponse` |
| `formField` | string | `"SAMLResponse"` | POST form field name (POST binding) |
| `attributeMapping` | map | — | Claim name → SAML attribute name mapping |

`entityId` is mandatory at config time — omitting it would silently bypass
the Destination and Recipient checks, so the module refuses to start
without it rather than degrade quietly.

## Security posture

Only SHA-256+ signature and digest algorithms are accepted (SHA-1 is
rejected outright). The module additionally enforces, beyond the SAML 2.0
core spec's minimums: Response Destination validation, mandatory bearer
`SubjectConfirmation` with Recipient/expiry checks, XML Signature Wrapping
(XSW) protection (the signature must cover the exact assertion being
trusted, not just *an* assertion in the document), digest reference
verification with a transform allowlist, comment/CDATA injection
protection in ID resolution, SAML protocol namespace pinning, and replay
detection via a bounded assertion-ID cache. See
[pkg/identity/saml](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/saml/README.md)
for the full validation sequence.

## Helm wiring

File mode (default chart):

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: corporate-idp
        type: saml
        config:
          idpCertPEM: ${IDP_CERT_PEM}
          entityId: https://sp.example.com/saml
          issuer: https://idp.example.com/saml
    authorizers:
      - { name: gate, type: rbac, config: { rolesFrom: "claim:groups", allow: ["admin"] } }
```

CRD mode adds nothing extra — the same YAML lives under
`spec.identifiers` of an `AuthConfig` CR.

## Composition

- Pair with [`rbac`](rbac.md) or [`cel`](cel.md), reading the mapped
  `attributeMapping` claims (e.g. `groups`) for authorization decisions.
- Use [`firstMatch`](README.md) alongside [`jwt`](jwt.md) if the same
  deployment fronts both a legacy SAML IdP and a newer OIDC one during a
  migration window.

## References

- SAML 2.0 Core, SAML 2.0 Bindings (OASIS).
- [DESIGN.md §4](../DESIGN.md) — identity & credential modules.
- Source: [pkg/identity/saml](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/saml/README.md).
