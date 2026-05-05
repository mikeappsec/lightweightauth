# HMAC Key Revocation & Replacement Runbook

## Overview

This runbook covers the full lifecycle of revoking a compromised or
rotated HMAC signing key and replacing it with a new one — without
downtime and with immediate denial of requests signed with the old key.

**Applies to**: lwauth deployments using the `hmac` identifier module.

---

## Architecture

```
┌────────────┐    Authorization: HMAC-SHA256 keyId="abc", ...
│ API Client │─────────────────────────────────────────────────▶
└────────────┘

   ┌─────────────┐
   │  lwauth pod │
   │             │──1. Parse keyId from Authorization header
   │             │──2. Look up shared secret by keyId
   │             │──3. Verify HMAC-SHA256 over canonical request
   │             │──4. Check clock skew (Date header)
   │             │──5. Check revocation store (if enabled)
   │             │──6. Return identity {subject, keyId, roles}
   └─────────────┘
         ▲
         │ hot-reload (fsnotify)
   ┌─────┴───────┐
   │  ConfigMap  │  keys: { kid → {secret, subject, roles} }
   └─────────────┘
```

### HMAC Authorization Header Format

```
Authorization: HMAC-SHA256 keyId="svc-a-v2", signedHeaders="date;host", signature="<base64>"
```

### Canonical Signed String

```
HMAC-SHA256-V1
GET
api.example.com
/api/resource

date:Sun, 04 May 2026 12:00:00 GMT
host:api.example.com
date,host
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

## Method 1: Config-Driven Revocation (Hot-Reload)

Best for: planned rotation, key expiry, permanent removal.

### Prerequisites

- lwauth started with `--watch-config-file`
- HMAC keys in config YAML (inline or Secret-mounted)

### Step 1: Generate New Shared Secret

```bash
# Generate a 256-bit (32-byte) secret, base64-encoded
NEW_SECRET=$(openssl rand -base64 32)
echo "New secret (base64): $NEW_SECRET"
```

### Step 2: Update Configuration

**Before** (single key):
```yaml
identifiers:
  - name: hmac-auth
    type: hmac
    config:
      clockSkew: "5m"
      keys:
        svc-a-v1:
          secret: "b2xkLXNlY3JldC10aGF0LXdhcy1jb21wcm9taXNlZA=="
          subject: "service-a"
          roles: [writer]
```

**After** (old key removed, new key added):
```yaml
identifiers:
  - name: hmac-auth
    type: hmac
    config:
      clockSkew: "5m"
      keys:
        svc-a-v2:
          secret: "bmV3LXNlY3JldC1nZW5lcmF0ZWQtYnktb3BlcmF0b3I="
          subject: "service-a"
          roles: [writer]
```

### Step 3: Apply ConfigMap

```bash
kubectl create configmap lwauth-config \
  --from-file=config.yaml=./config.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

# lwauth reloads automatically via --watch-config-file
```

### Step 4: Verify

```bash
# Old keyId should be rejected (unknown keyId → 401)
# New keyId with correct signature should be accepted (200)
```

---

## Method 2: Graceful Rotation (Zero-Downtime)

Best for: coordinated rotation where both old and new secrets must be
valid during a transition window while clients upgrade.

### Timeline

```
Day 0:  Add new key (both keys in config)     → both valid
Day 0:  Distribute new secret to client teams
Day 7:  Confirm clients switched (audit logs show new keyId)
Day 7:  Remove old key from config            → old key rejected
```

### Step 1: Both Keys Active

```yaml
identifiers:
  - name: hmac-auth
    type: hmac
    config:
      clockSkew: "5m"
      keys:
        svc-a-v1:
          secret: "b2xkLXNlY3JldC1zdGlsbC12YWxpZA=="
          subject: "service-a"
          roles: [writer]
        svc-a-v2:
          secret: "bmV3LXNlY3JldC1nZW5lcmF0ZWQtYnktb3BlcmF0b3I="
          subject: "service-a"
          roles: [writer]
```

Apply → lwauth reloads → requests signed with either key succeed.

### Step 2: Monitor Key Usage

```bash
# Check which keyId appears in lwauth decision logs
kubectl logs deployment/lwauth | grep '"keyId"' | sort | uniq -c
```

### Step 3: Remove Old Key

Once all clients confirmed on `svc-a-v2`:

```yaml
keys:
  svc-a-v2:
    secret: "bmV3LXNlY3JldC1nZW5lcmF0ZWQtYnktb3BlcmF0b3I="
    subject: "service-a"
    roles: [writer]
```

Apply → old key immediately rejected (unknown keyId).

---

## Method 3: Key Rotation with Lifecycle (keyrotation.KeySet)

Best for: automated rotation with time-based transitions.

### Config (secrets format)

```yaml
identifiers:
  - name: hmac-auth
    type: hmac
    config:
      clockSkew: "5m"
      secrets:
        - kid: "svc-a-v1"
          secret: "b2xkLXNlY3JldA=="
          subject: "service-a"
          roles: [writer]
          notAfter: "2026-06-01T00:00:00Z"
          gracePeriod: "24h"
        - kid: "svc-a-v2"
          secret: "bmV3LXNlY3JldA=="
          subject: "service-a"
          roles: [writer]
          notBefore: "2026-05-25T00:00:00Z"
```

### Lifecycle

| Date     | svc-a-v1 | svc-a-v2 | Effect |
|----------|----------|----------|--------|
| May 20   | active   | pending  | Only v1 works |
| May 25   | active   | active   | Both work |
| Jun 1    | retiring | active   | Both work (grace) |
| Jun 2    | retired  | active   | Only v2 works |

No restarts or config changes needed after deployment.

---

## Method 4: Admin API Revocation (Runtime)

Best for: emergency revocation without waiting for config reload.

> **Requires**: `revocation.enabled: true` and admin endpoints configured.

### Revoke by Key ID

```bash
curl -X POST http://lwauth:8080/v1/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jti": "kid:svc-a-v1", "reason": "compromised", "ttl": "720h"}'
```

### Revoke by Subject (All Keys for a Service)

```bash
curl -X POST http://lwauth:8080/v1/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject": "service-a", "reason": "service decommissioned", "ttl": "720h"}'
```

### Limitation

Memory-backed revocations are lost on pod restart (G19 persistent
storage gap). Use `backend: valkey` for durable revocation.

---

## Emergency Revocation Checklist

When a shared secret is confirmed compromised:

1. **Immediate**: Remove the key entry from the lwauth ConfigMap
2. **Apply**: `kubectl apply` the updated ConfigMap
3. **Verify**: Confirm lwauth reloaded (logs: "config reloaded")
4. **Test**: Attempt request signed with compromised key → 401
5. **Audit**: Review access logs for unauthorized usage window
6. **Rotate**: Generate new secret, distribute to affected client
7. **Client update**: Client updates its signing code with new keyId + secret
8. **Document**: Record incident, exposure window, and remediation

---

## Client-Side Signing Example (Go)

```go
func signRequest(req *http.Request, keyID string, secret []byte) {
    now := time.Now().UTC()
    req.Header.Set("Date", now.Format(http.TimeFormat))

    // Build canonical string
    bodyHash := sha256.Sum256(body)
    signedHeaders := []string{"date", "host"}
    canonical := fmt.Sprintf("HMAC-SHA256-V1\n%s\n%s\n%s\n\n%s:%s\n%s:%s\n%s\n%s",
        strings.ToUpper(req.Method),
        strings.ToLower(req.Host),
        req.URL.Path,
        "date", now.Format(http.TimeFormat),
        "host", strings.ToLower(req.Host),
        strings.Join(signedHeaders, ","),
        hex.EncodeToString(bodyHash[:]),
    )

    mac := hmac.New(sha256.New, secret)
    mac.Write([]byte(canonical))
    sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

    req.Header.Set("Authorization",
        fmt.Sprintf(`HMAC-SHA256 keyId="%s", signedHeaders="date;host", signature="%s"`,
            keyID, sig))
}
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `signature mismatch` | Client/server canonical string differs | Check method/host/path casing, signedHeaders order |
| `clock skew > 5m` | Client Date header too far from server time | Sync NTP; increase `clockSkew` config |
| `unknown keyId` | Key removed or keyId misspelled | Check config; ensure keyId matches exactly |
| `signedHeaders missing required "host"` | Client didn't include host in signed headers | Client must sign at least host + date |
| Old key still works after removal | File watcher didn't trigger | Restart: `kubectl rollout restart deployment/lwauth` |

---

## E2E Validation Script

See `lightweightauth-idp/cmd/e2e-hmac-revocation-test/main.go` for an
automated test that exercises:

1. HMAC request accepted with valid key
2. Key removed from config → immediate rejection
3. Replacement key added → accepted with new keyId
4. Graceful rotation (both keys active during transition)
