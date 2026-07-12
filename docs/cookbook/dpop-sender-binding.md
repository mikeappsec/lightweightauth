# DPoP sender-constrained tokens

Implement RFC 9449 Demonstrating Proof-of-Possession (DPoP) to bind
access tokens to the client's ephemeral key pair. A stolen token is
useless without the corresponding private key — preventing token
replay and exfiltration attacks from public clients (SPAs, mobile
apps).

## What this recipe assumes

- An OAuth 2.0 IdP that issues DPoP-bound tokens (includes `cnf.jkt`
  in the access token).
- Clients send both the `Authorization: DPoP <token>` header and a
  `DPoP` proof JWT on every request.
- lwauth validates the full DPoP proof chain per RFC 9449 §4.3.
- `lwauthctl` v1.0+ on your workstation.

## 1. How DPoP works (overview)

```text
Client                      Gateway (lwauth)              Resource Server
  │                              │                              │
  │ 1. Generate ephemeral key    │                              │
  │ 2. Get DPoP-bound token      │                              │
  │    from IdP (cnf.jkt in AT)  │                              │
  │                              │                              │
  │ 3. Request with:             │                              │
  │    Authorization: DPoP <AT>  │                              │
  │    DPoP: <proof JWT>         │                              │
  │ ─────────────────────────────→                              │
  │                              │ 4. Verify:                   │
  │                              │    - DPoP proof signature    │
  │                              │    - htm matches method      │
  │                              │    - htu matches URL         │
  │                              │    - jti not replayed        │
  │                              │    - cnf.jkt matches proof   │
  │                              │    - ath matches token hash  │
  │                              │                              │
  │                              │ 5. Forward if valid ─────────→
```

## 2. Configure DPoP validation

The `dpop` identifier wraps an inner identifier (typically `jwt`) and
adds DPoP proof verification:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: api-dpop
  namespace: production
spec:
  identifiers:
    - name: dpop-bearer
      type: dpop
      config:
        # The DPoP proof header name (RFC 9449 default)
        proofHeader: DPoP

        # Allowed signing algorithms for the DPoP proof
        allowedAlgorithms:
          - ES256    # recommended for mobile/SPA
          - RS256    # fallback

        # Clock skew tolerance for iat claim
        skew: 60s

        # Replay prevention: LRU cache of seen jti values
        replayCache:
          maxSize: 100000
          ttl: 300s    # jti entries expire after 5 minutes

        # Inner identifier: the actual access token validation
        inner:
          type: jwt
          config:
            issuerUrl: https://idp.example.com
            audiences: [api]
            header: Authorization
            scheme: DPoP        # DPoP scheme instead of Bearer

  authorizers:
    - name: rbac
      type: rbac
      config:
        rolesFrom: claim:roles
        allow: [user, admin]
```

## 3. DPoP verification steps (RFC 9449 §4.3)

lwauth performs these checks in order:

| Step | Check | Failure |
|------|-------|---------|
| 1 | DPoP header present and parseable as JWT | 401 |
| 2 | `typ` header is `dpop+jwt` | 401 |
| 3 | `alg` is in `allowedAlgorithms` | 401 |
| 4 | `jwk` header contains the public key | 401 |
| 5 | Signature valid against embedded `jwk` | 401 |
| 6 | `htm` matches request method | 401 |
| 7 | `htu` matches request URL (scheme + host + path) | 401 |
| 8 | `iat` within `skew` window | 401 |
| 9 | `jti` not in replay cache | 401 |
| 10 | `ath` = base64url(sha256(access_token)) | 401 |
| 11 | Access token `cnf.jkt` = thumbprint of DPoP `jwk` | 401 |

If any check fails, the entire request is rejected — no fallback to
the next identifier.

## 4. Client implementation example

### JavaScript (SPA)

```javascript
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

// Generate ephemeral key pair (once per session)
const { privateKey, publicKey } = await generateKeyPair('ES256');
const jwk = await exportJWK(publicKey);

// Create DPoP proof for each request
async function createDPoPProof(method, url, accessToken) {
  const ath = btoa(String.fromCharCode(
    ...new Uint8Array(await crypto.subtle.digest('SHA-256',
      new TextEncoder().encode(accessToken)))
  )).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return new SignJWT({ htm: method, htu: url, ath })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .sign(privateKey);
}

// Make authenticated request
const proof = await createDPoPProof('GET', 'https://api.example.com/resource', accessToken);
const response = await fetch('https://api.example.com/resource', {
  headers: {
    'Authorization': `DPoP ${accessToken}`,
    'DPoP': proof,
  },
});
```

### Go (service client)

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

func createDPoPProof(key *ecdsa.PrivateKey, method, url, accessToken string) (string, error) {
    ath := sha256.Sum256([]byte(accessToken))

    token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
        "htm": method,
        "htu": url,
        "ath": base64.RawURLEncoding.EncodeToString(ath[:]),
        "jti": uuid.New().String(),
        "iat": time.Now().Unix(),
    })
    token.Header["typ"] = "dpop+jwt"
    token.Header["jwk"] = publicKeyJWK(key)

    return token.SignedString(key)
}
```

## 5. X-Forwarded-Proto awareness

When lwauth sits behind a TLS-terminating proxy, the DPoP `htu` check
must match the external URL (https) not the internal one (http). The
`dpop` identifier automatically reads `X-Forwarded-Proto`:

```text
Client → https://api.example.com/resource
           ↓ (TLS terminated at LB)
         http://lwauth-pod:8080/resource
           ↓ (X-Forwarded-Proto: https)
         DPoP htu check: https://api.example.com/resource ✓
```

No extra configuration needed — as long as your proxy sets
`X-Forwarded-Proto` correctly.

## 6. Replay prevention

The `jti` claim prevents token replay. lwauth maintains a cache of
recently seen jti values — but there's no `replayCache:` config block
on the `dpop` identifier (`pkg/identity/dpop/dpop.go`'s `knownKeys`
only has `replayCacheSize`, and that field is parsed but never
actually read anywhere in the package — it's presently dead). The
cache handle instead comes from the shared, named cache-pool
infrastructure: `deps.CacheProvider().Cache("replay")` requests a
pool named `"replay"` from the top-level `caches:` block. If you
don't declare one, lwauth synthesizes an implicit in-memory default
pool so existing configs keep working:

```yaml
identifiers:
  - name: dpop-bearer
    type: dpop
    config:
      required: true
      # no replayCache: block — nothing to configure here
      inner:
        type: oauth2-introspection
        name: introspect
        config: { ... }
```

To size or back the replay cache explicitly, declare a pool named
`replay` at the top level (sibling to `identifiers:`/`authorizers:`):

```yaml
caches:
  - name: replay
    backend: memory
    size: 100000
```

!!! warning "Per-replica cache (default `memory` backend)"
    With `backend: memory`, the replay cache is local to each lwauth
    replica. With N replicas, a proof sent to replica A can be
    replayed against replica B. For strict single-use enforcement,
    use the Valkey-backed pool below.

## 7. Valkey-backed replay cache (multi-replica)

Point the same `replay` pool at Valkey instead of `memory` — this is
a top-level `caches:` pool, not a per-identifier config block:

```yaml
caches:
  - name: replay
    backend: valkey
    addr: valkey-master.cache.svc:6379
    password: "${VALKEY_PASSWORD}"   # see warning below
    keyPrefix: "lwauth/dpop-jti/"
```

Every jti is checked against Valkey before acceptance. One
round-trip per request (~0.2ms in-cluster).

!!! warning "`password` is read literally — no `${VAR}` substitution"
    lwauth does not expand `${VALKEY_PASSWORD}`-style placeholders
    anywhere in `AuthConfig`, including `caches[].password`. Two ways
    to actually inject a secret: use `secretRef: "vault://kv/lwauth/valkey#password"`
    (resolved at compile time — `internal/config/loader.go` checks
    `caches[].password` for a `secretRef` specifically, alongside
    every module config field recursively), or template the
    `AuthConfig` YAML itself at the deployment-pipeline layer (Helm,
    Kustomize, CI) so the real value is already inlined before lwauth
    parses it.

## 8. Helm wiring

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: dpop-bearer
        type: dpop
        config:
          proofHeader: DPoP
          allowedAlgorithms: [ES256]
          skew: 60s
          replayCache:
            maxSize: 100000
            ttl: 300s
          inner:
            type: jwt
            config:
              issuerUrl: https://idp.example.com
              audiences: [api]
              header: Authorization
              scheme: DPoP
    authorizers:
      - name: rbac
        type: rbac
        config:
          rolesFrom: claim:roles
          allow: [user, admin]
```

## 9. Validate

```bash
# Valid DPoP request
curl -H "Authorization: DPoP ${ACCESS_TOKEN}" \
     -H "DPoP: ${DPOP_PROOF}" \
     https://gateway/api/resource
# expect: 200

# Replayed proof (same jti)
curl -H "Authorization: DPoP ${ACCESS_TOKEN}" \
     -H "DPoP: ${SAME_PROOF_AGAIN}" \
     https://gateway/api/resource
# expect: 401 (jti replay detected)

# Stolen token without proof
curl -H "Authorization: DPoP ${ACCESS_TOKEN}" \
     https://gateway/api/resource
# expect: 401 (missing DPoP proof)

# Token with wrong key (key doesn't match cnf.jkt)
curl -H "Authorization: DPoP ${ACCESS_TOKEN}" \
     -H "DPoP: ${PROOF_SIGNED_WITH_DIFFERENT_KEY}" \
     https://gateway/api/resource
# expect: 401 (key binding mismatch)

# Dry-run
lwauthctl explain --config api-dpop.yaml \
    --request '{"method":"GET","path":"/api/resource","headers":{"authorization":"DPoP eyJ...","dpop":"eyJ..."}}'
# identify  ✓  dpop  proof=valid  jti=unique  cnf=matched  inner=jwt(sub=alice)
# authorize ✓  rbac
```

## Security notes

- **Ephemeral keys.** Clients should generate a new key pair per
  session (not per request). Key persistence across sessions weakens
  the "stolen token is useless" guarantee.
- **Algorithm restriction.** Only allow `ES256` in production. RSA
  keys are unnecessarily large for DPoP proofs.
- **Replay window.** Set `ttl` to at least `2 × skew`. A 60s skew
  with 300s replay TTL is safe. Lower TTL = less protection.
- **HTTPS required.** DPoP's `htu` check binds the proof to the URL.
  Without TLS, an attacker can MITM and extract both token + proof.

## Teardown

```bash
kubectl delete authconfig api-dpop -n production
```
