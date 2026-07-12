# `dpop` — RFC 9449 sender-constrained bearers

Wrapper identifier. On every request it verifies a `DPoP` proof JWT
that binds the request to a key, then delegates the *bearer*
verification to an inner identifier (typically [`jwt`](jwt.md) or
[`oauth2-introspection`](oauth2-introspection.md)).

**Source:** [pkg/identity/dpop](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/dpop/dpop.go) — registered as `dpop`.

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

## Proof key pinning (optional)

Beyond the `cnf.jkt` cross-check above (which trusts whatever thumbprint
the inner identifier's token asserts), `pinnedKeys` lets you pin proof
keys to an explicit, operator-controlled allowlist independent of what
the bearer token claims — useful when you don't fully trust the IdP to
enforce key binding, or want a hard key-rotation boundary:

```yaml
identifiers:
  - name: dpop-bearer
    type: dpop
    config:
      # ... required/inner/etc. as above ...
      pinnedKeys:
        - kid: "2026-q3"
          thumbprint: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"  # RFC 7638 SHA-256
          notBefore: "2026-07-01T00:00:00Z"   # optional, RFC 3339
          notAfter:  "2026-10-01T00:00:00Z"   # optional, RFC 3339
          gracePeriod: 24h                    # optional, tolerance past notAfter
```

| Field | Type | Default | Description |
|---|---|---|---|
| `kid` | string | *required* | Key identifier for this pinned entry. |
| `thumbprint` | string | *required* | RFC 7638 SHA-256 JWK thumbprint the proof's embedded `jwk` must match. |
| `notBefore` | RFC 3339 timestamp | — | Key not valid before this time. |
| `notAfter` | RFC 3339 timestamp | — | Key not valid after this time. |
| `gracePeriod` | duration | — | Extends acceptance past `notAfter` for in-flight rotation windows. |

When `pinnedKeys` is set (non-empty), every proof's key is checked
against this set in addition to the standard RFC 9449 checks above — a
proof signed by a key not in the set is rejected even if otherwise valid.

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
- Source: [pkg/identity/dpop/dpop.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/dpop/dpop.go).
