# `jwt-issue` — Mint a fresh internal JWT for upstream

Signs a short-lived JWT carrying selected claims from the verified
`Identity` and drops it on the upstream request. Lets your edge accept
opaque tokens / cookies / mTLS / API keys, while east-west traffic uses
a uniform signed assertion.

**Source:** [pkg/mutator/jwtissue](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/mutator/jwtissue/jwtissue.go) — registered as `jwt-issue`.

## When to use

- Decouple edge auth (cookie, opaque, mTLS) from internal auth (JWT).
- Avoid leaking long-lived bearers into east-west traffic.
- Give downstream services a verifiable, time-bounded identity stamp.

## Configuration

```yaml
mutators:
  - name: internal-jwt
    type: jwt-issue
    config:
      issuer:    https://lwauth.svc.cluster.local
      audience:  internal-services
      ttl:       2m                 # short — refreshed per request anyway
      algorithm: ES256              # ES256 | RS256 | EdDSA

      header: Authorization         # default
      scheme: Bearer                # default

      # Pick ONE of:
      privateKeyFile: /etc/lwauth/keys/internal.pem
      # key: |
      #   -----BEGIN EC PRIVATE KEY-----
      #   ...
      #   -----END EC PRIVATE KEY-----

      # Whitelist of claim keys to copy from Identity.Claims.
      copyClaims: [tenant, roles, email]
```

Generated JWT shape:

```json
{
  "iss": "https://lwauth.svc.cluster.local",
  "aud": "internal-services",
  "sub": "alice",
  "iat": 1731000000,
  "exp": 1731000120,
  "tenant": "acme",
  "roles": ["editor"],
  "email": "alice@acme.example"
}
```

Sibling services verify with `pkg/identity/jwt` pointed at lwauth's
`/.well-known/jwks.json` (M3 already publishes this).

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    mutators:
      - name: strip
        type: header-remove
        config: { upstream: [Authorization, Cookie, X-Api-Key] }
      - name: internal-jwt
        type: jwt-issue
        config:
          issuer: https://lwauth.svc
          audience: internal-services
          ttl: 2m
          algorithm: ES256
          privateKeyFile: /etc/lwauth/keys/internal.pem
          copyClaims: [tenant, roles, email]
extraVolumes:
  - name: signing-key
    secret: { secretName: lwauth-internal-jwt }
extraVolumeMounts:
  - name: signing-key
    mountPath: /etc/lwauth/keys
    readOnly: true
```

Rotate by writing a new Secret and bouncing the Pod (M11 will add
hot-reload for signing keys).

## Worked example

Edge identifier: [`apikey`](apikey.md) → `Identity{subject: alice, claims: {tenant: acme, roles: [editor]}}`.

Upstream sees:

```http
GET /things HTTP/1.1
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6Im...
```

(no original `X-Api-Key`; mutator stripped it then minted the JWT.)

## Composition

- Always pair with [`header-remove`](header-remove.md) on the original
  bearer/cookie/key — otherwise both reach upstream.
- Sibling services use [`jwt`](jwt.md) (`jwksUrl: https://lwauth/.well-known/jwks.json`) to verify.

## References

- RFC 7519 (JWT), RFC 8037 (EdDSA JWS).
- Source: [pkg/mutator/jwtissue/jwtissue.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/mutator/jwtissue/jwtissue.go).
