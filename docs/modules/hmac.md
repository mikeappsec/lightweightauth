# `hmac` — Request-signature identifier

Verifies AWS-SigV4-style HMAC signatures over a canonical request
string. Default canonicalization covers `method | path | date |
sha256(body)`; the `Canonicalizer` is a function value so plug-ins can
ship custom shapes.

**Source:** [pkg/identity/hmac](../../pkg/identity/hmac/hmac.go) — registered as `hmac`.

## When to use

- AWS-SigV4-flavored CLIs / SDKs.
- Webhook receivers (GitHub, Stripe, Slack — each has its own canon).
- You can pin clock skew tightly (default ±5 min via `Date` header).

## Configuration

```yaml
identifiers:
  - name: webhooks
    type: hmac
    config:
      header:    Authorization     # default
      scheme:    HMAC              # accepts both `HMAC keyId="...", signature="..."`
                                   # and the compact `keyId:signature` form
      dateHeader: Date             # set to "" to skip skew enforcement
      clockSkew:  5m               # default

      keys:
        partner-acme:  ${ACME_HMAC}      # base64 or hex; rotate by adding a new keyId
        partner-globex: ${GLOBEX_HMAC}
```

Verification (constant-time): canonicalize → HMAC-SHA256 with the
`keyId`'s secret → compare. Matching key produces
`Identity{Subject: <keyId>, Source: "webhooks", Claims: {keyId}}`.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: webhooks
        type: hmac
        config:
          keys:
            partner-acme: ${ACME_HMAC}
extraEnv:
  - name: ACME_HMAC
    valueFrom: { secretKeyRef: { name: webhook-secrets, key: acme } }
```

For provider-specific canons (GitHub: `X-Hub-Signature-256`, Stripe:
`Stripe-Signature`), write a small in-process plugin that sets
`hmac.SetCanonicalizer("github", canonGithub)` and reference
`canonicalizer: github` in the config — see DESIGN.md §9 (tier 2 plugins).

## Worked example

Client signs `GET /webhook/acme | 2026-04-27T10:00:00Z | sha256("")`:

```http
GET /webhook/acme HTTP/1.1
Date: 2026-04-27T10:00:00Z
Authorization: HMAC keyId="partner-acme", signature="aGVsbG8gd29ybGQ..."
```

→ `Identity{Subject: "partner-acme"}` → [`rbac`](rbac.md) with
`allow: ["partner-acme"]` (or [`cel`](cel.md) for path-scoped checks).

## Composition

- `firstMatch: [jwt, hmac]`: human callers send Bearer, partner systems sign.
- The `Date` header is mandatory — without it any captured signature
  replays forever. Combine with the [`dpop`](dpop.md) replay cache for
  belt-and-braces if your canonicalizer doesn't include a nonce.

## References

- Generic HMAC pattern; AWS SigV4 specification.
- Source: [pkg/identity/hmac/hmac.go](../../pkg/identity/hmac/hmac.go).
