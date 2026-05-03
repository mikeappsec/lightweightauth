# Static API key authentication

Service-to-service calls where one backend needs to authenticate
against lwauth using a pre-shared API key — hashed with argon2id,
stored inline or from a file, with zero-downtime key rotation via the
multi-key overlap window.

## What this recipe assumes

- lwauth running as an `ext_authz` provider (Envoy or Istio).
- One or more backend services that authenticate with static API keys.
- Keys are hashed before they appear in config (argon2id, RFC 9106).
- `lwauthctl` v1.0+ on your workstation.
- You understand that **plaintext keys in config are a security
  vulnerability** — always hash first.

## 1. Hash your API keys

Never store raw keys. Use `lwauthctl` to produce argon2id hashes:

```bash
# Generate a random 32-byte key and hash it
API_KEY=$(openssl rand -base64 32)
echo "Save this key securely: ${API_KEY}"

# Hash for config storage
lwauthctl hash-apikey --key "${API_KEY}"
# output: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
```

For multiple tenants, hash each key separately:

```bash
lwauthctl hash-apikey --key "${TENANT_A_KEY}"
lwauthctl hash-apikey --key "${TENANT_B_KEY}"
```

## 2. Configure the AuthConfig

Inline hashed keys — suitable for small deployments:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: internal-api
  namespace: backend
spec:
  identifiers:
    - name: service-key
      type: apikey
      config:
        # Where to find the key in the request:
        header: X-API-Key           # default; also supports query param
        # scheme: ""                # no Bearer prefix for raw keys

        # Inline hashed entries:
        keys:
          - hash: "$argon2id$v=19$m=65536,t=3,p=4$salt1$hash1"
            subject: "billing-service"
            claims:
              tenant: acme
              roles: ["writer"]
          - hash: "$argon2id$v=19$m=65536,t=3,p=4$salt2$hash2"
            subject: "reporting-service"
            claims:
              tenant: acme
              roles: ["reader"]

  authorizers:
    - name: rbac
      type: rbac
      config:
        rolesFrom: claim:roles
        allow: [writer, reader]
```

## 3. File-based key store (large deployments)

For many keys, use a hashed directory — one file per key:

```yaml
identifiers:
  - name: service-key
    type: apikey
    config:
      header: X-API-Key
      store:
        type: hashed-directory
        path: /etc/lwauth/apikeys/
        # Files are named <subject>.key, each containing the argon2id hash.
        # Hot-reloaded on change (fsnotify).
```

Directory layout:

```text
/etc/lwauth/apikeys/
├── billing-service.key      # contains: $argon2id$v=19$m=...
├── reporting-service.key
└── analytics-service.key
```

Mount via ConfigMap or Secret in Helm:

```yaml
# values.yaml
extraVolumes:
  - name: apikeys
    secret:
      secretName: lwauth-apikeys
extraVolumeMounts:
  - name: apikeys
    mountPath: /etc/lwauth/apikeys
    readOnly: true
```

## 4. Zero-downtime key rotation

The API key identifier supports multiple hashes per subject —
allowing an overlap window where both old and new keys are accepted:

```yaml
keys:
  # New key (just issued to billing-service)
  - hash: "$argon2id$v=19$m=65536,t=3,p=4$newsalt$newhash"
    subject: "billing-service"
    claims: { tenant: acme, roles: ["writer"] }
  # Old key (still valid during rotation window)
  - hash: "$argon2id$v=19$m=65536,t=3,p=4$oldsalt$oldhash"
    subject: "billing-service"
    claims: { tenant: acme, roles: ["writer"] }
```

Rotation procedure:

1. Generate a new key and hash it.
2. Add the new hash to the config (keep the old one).
3. Apply the config — both keys now work.
4. Update the calling service to use the new key.
5. After confirmation, remove the old hash from config.

```bash
# Step 1: Generate and hash
NEW_KEY=$(openssl rand -base64 32)
NEW_HASH=$(lwauthctl hash-apikey --key "${NEW_KEY}")

# Step 2-3: Add to config and apply
kubectl apply -f updated-authconfig.yaml

# Step 4: Update the calling service's env/secret
kubectl -n billing set env deploy/billing API_KEY="${NEW_KEY}"

# Step 5: Remove old key after drain window (e.g. 1 hour)
kubectl apply -f authconfig-old-key-removed.yaml
```

## 5. Per-tenant isolation with rate limiting

Combine API key auth with per-tenant rate limits:

```yaml
spec:
  rateLimit:
    perTenant:
      rps: 100
      burst: 200
    overrides:
      acme:
        rps: 500
        burst: 1000

  identifiers:
    - name: service-key
      type: apikey
      config:
        header: X-API-Key
        keys:
          - hash: "$argon2id$v=19$..."
            subject: "billing-service"
            claims:
              tenant: acme
              roles: ["writer"]
```

The `tenant` claim populates `Request.TenantID` when
`tenantFrom: claim:tenant` is set, linking API key identity to
rate-limit buckets.

## 6. Validate

```bash
# Successful auth
curl -H "X-API-Key: ${API_KEY}" https://gateway/api/internal/health
# expect: 200

# Wrong key
curl -H "X-API-Key: wrong" https://gateway/api/internal/health
# expect: 401

# Missing key
curl https://gateway/api/internal/health
# expect: 401

# Dry-run explain
lwauthctl explain --config internal-api.yaml \
    --request '{"method":"GET","path":"/api/internal/health","headers":{"x-api-key":"'${API_KEY}'"}}'
# identify  ✓  apikey  subject=billing-service
# authorize ✓  rbac
```

## Security notes

- **Constant-time comparison.** The argon2id verifier uses
  `crypto/subtle.ConstantTimeCompare` — timing attacks against the
  hash are not viable.
- **No plaintext storage.** Raw keys appear only in the calling
  service's config/env. lwauth never sees or logs them in cleartext.
- **Rate limiting first.** The rate limiter runs before identification,
  so brute-force attacks burn quota before any argon2id work happens.

## Teardown

```bash
kubectl delete authconfig internal-api -n backend
kubectl delete secret lwauth-apikeys -n backend
```
