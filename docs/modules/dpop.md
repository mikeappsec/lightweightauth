# `dpop` — RFC 9449 sender-constrained bearers

Wrapper identifier. On every request it verifies a `DPoP` proof JWT
that binds the request to a key, then delegates the *bearer*
verification to an inner identifier (typically [`jwt`](jwt.md) or
[`oauth2-introspection`](oauth2-introspection.md)).

**Source:** [pkg/identity/dpop](../../pkg/identity/dpop/dpop.go) — registered as `dpop`.

## When to use

- Public clients (mobile, SPA) where you can't trust bearer secrecy.
- IdPs that issue tokens with a `cnf.jkt` claim binding key thumbprint.
- You want stolen-token resistance without going full mTLS.

## Configuration

```yaml
identifiers:
  - name: dpop-bearer
    type: dpop
    config:
      required: true                 # false = fall through to inner if no DPoP header
      proofHeader:  DPoP             # default
      bearerHeader: Authorization    # default
      skew: 30s                      # iat tolerance; jti replay TTL = 2·skew
      replayCacheSize: 10000         # in-process; switches to valkey if AuthConfig.cache.backend = valkey

      inner:
        type: jwt                    # any registered Identifier
        name: bearer
        config:
          jwksUrl: https://idp.example.com/.well-known/jwks.json
```

Per-request checks (RFC 9449 §4.3):

1. Proof `typ=dpop+jwt` and embedded public `jwk` validate the signature.
2. `alg` allow-list (RS/PS/ES/EdDSA only — no HMAC, no `none`).
3. `htm` matches request method (case-insensitive).
4. `htu` matches host + path; query/fragment ignored. Scheme cross-checked against `X-Forwarded-Proto`.
5. `iat` within ±`skew`.
6. `jti` not seen in the replay cache (default: in-process LRU; shared across replicas when `cache.backend: valkey`).
7. If inner identity surfaces `cnf.jkt`, it must equal RFC 7638 SHA-256 thumbprint of the proof's JWK.
8. If a bearer header is present, proof's `ath` must equal `base64url(sha256(token))`.

## Helm wiring

```yaml
# values.yaml — DPoP-protected JWT API
config:
  inline: |
    identifiers:
      - name: dpop-bearer
        type: dpop
        config:
          required: true
          inner:
            type: jwt
            name: inner
            config:
              jwksUrl: https://idp.example.com/.well-known/jwks.json
          # Use the shared replay cache so a stolen jti can't replay
          # against another replica.
    cache:
      backend: valkey
      addr: valkey-master.cache.svc:6379
      keyPrefix: lwauth/dpop/
```

## Worked example

```http
POST /orders HTTP/1.1
Authorization: DPoP eyJhbGciOiJSUzI1...
DPoP:          eyJ0eXAiOiJkcG9wK2p3...
```

The proof JWT's `jwk` recreates Alice's public key. lwauth verifies the
proof, hashes the bearer's `ath`, then hands the bearer to inner=`jwt`
which checks the IdP signature. `cnf.jkt` from the JWT must match the
SHA-256 thumbprint of `jwk` — guaranteeing the proof was made by the
key the IdP bound the token to.

## Composition

- DPoP is a pure wrapper — combine with anything that produces an
  `Identity` from a bearer.
- Use the shared `valkey` cache backend so jti replays are rejected
  cluster-wide, not just per-replica.

## References

- RFC 9449 (DPoP), RFC 7638 (JWK Thumbprint), RFC 7800 (`cnf` claim).
- Source: [pkg/identity/dpop/dpop.go](../../pkg/identity/dpop/dpop.go).
