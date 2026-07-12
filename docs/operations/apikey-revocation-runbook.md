# API Key Revocation & Replacement Runbook

## Overview

This runbook covers the full lifecycle of revoking a compromised or expired
API key and replacing it with a new one — without downtime and with
immediate denial of the old credential.

**Applies to**: lwauth deployments using the `apikey` identifier module
with `hashed.file`, `hashed.dir`, or `hashed.entries` backends.

---

## Architecture

```
┌────────────┐         ┌─────────────┐        ┌───────────────────┐
│ API Client │──key──▶ │  lwauth pod │──check──▶ HashedStore (mem) │
└────────────┘         │             │         └───────────────────┘
                       │  Revocation │──check──▶ RevocationStore    │
                       │    Store    │         │ (memory or Valkey) │
                       └─────────────┘         └───────────────────┘
                              ▲
                              │ hot-reload (fsnotify)
                       ┌──────┴──────┐
                       │  ConfigMap  │
                       │  /apikeys/  │
                       └─────────────┘
```

lwauth checks API keys in two stages:
1. **Identification**: Is the key valid? (HashedStore lookup)
2. **Revocation**: Is the key/subject revoked? (RevocationStore check)

---

## Method 1: Config-Driven Revocation (Hot-Reload)

Best for: planned rotation, key expiry, permanent removal.

### Prerequisites

- lwauth started with `--watch-config-file` (file-watcher mode)
- API keys stored in a hashed file mounted via ConfigMap/Secret

### Step 1: Generate New Key

```bash
# Generate a new 32-byte API key
NEW_KEY=$(openssl rand -base64 32)
echo "New key: $NEW_KEY"

# Hash it for storage — there's no CLI subcommand for this yet;
# apikey.HashKey is a plain Go function, call it with `go run`.
cat > /tmp/hash-apikey.go <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/mikeappsec/lightweightauth/pkg/identity/apikey"
)

func main() {
	hash, err := apikey.HashKey(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
EOF

NEW_HASH=$(go run /tmp/hash-apikey.go "$NEW_KEY")
echo "Hash: $NEW_HASH"
```

### Step 2: Update the API Key File

The hashed key file format:
```
# id            hash                                                          subject   roles
new-key-2026    $argon2id$v=19$m=65536,t=2,p=1$<salt>$<digest>               svc-a     api,reader
# REVOKED — compromised 2026-05-04, ticket INC-1234
# old-key-2025  $argon2id$v=19$m=65536,t=2,p=1$<old-salt>$<old-digest>      svc-a     api,reader
```

**To revoke**: comment out or delete the line for the old key.
**To replace**: add the new key line before commenting the old one.

### Step 3: Apply the ConfigMap

```bash
# Update ConfigMap from file
kubectl create configmap lwauth-apikeys \
  --from-file=apikeys.txt=/path/to/apikeys.txt \
  --dry-run=client -o yaml | kubectl apply -f -

# lwauth detects the change via --watch-config-file and reloads.
# No restart required.
```

### Step 4: Verify

```bash
# Old key should be rejected (401)
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Api-Key: $OLD_KEY" \
  http://lwauth:8080/v1/authorize \
  -d '{"method":"GET","host":"api.example.com","path":"/resource","headers":{"x-api-key":["'"$OLD_KEY"'"]}}'
# Expected: 401

# New key should be accepted (200)
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Api-Key: $NEW_KEY" \
  http://lwauth:8080/v1/authorize \
  -d '{"method":"GET","host":"api.example.com","path":"/resource","headers":{"x-api-key":["'"$NEW_KEY"'"]}}'
# Expected: 200
```

### Step 5: Distribute New Key to Client

Provide the new key to the service via:
- Kubernetes Secret mounted as env var
- Vault / AWS Secrets Manager
- Secure channel (out-of-band)

---

## Method 2: Graceful Rotation (Zero-Downtime Replacement)

Best for: scheduled rotation where both old and new keys must work
during a transition window.

### Timeline

```
Day 0:  Add new key to config (both keys valid)
Day 0:  Distribute new key to client team
Day 7:  Confirm client is using new key (check audit logs)
Day 7:  Remove old key from config → immediate revocation
```

### Step 1: Add New Key (Both Active)

```yaml
# apikeys.txt — both keys active during transition
old-key-2025  $argon2id$...  svc-a  api,reader
new-key-2026  $argon2id$...  svc-a  api,reader
```

Apply ConfigMap → lwauth reloads → both keys work.

### Step 2: Monitor Usage

Check which key ID is being used in audit logs or the identity claims:

```bash
# Check lwauth decision logs for keyId field
kubectl logs deployment/lwauth | grep -o '"keyId":"[^"]*"' | sort | uniq -c
```

### Step 3: Remove Old Key

Once confirmed the client switched:

```yaml
# apikeys.txt — old key removed
new-key-2026  $argon2id$...  svc-a  api,reader
```

Apply ConfigMap → lwauth reloads → old key immediately rejected.

---

## Method 3: Key Rotation with Lifecycle — not currently wired in

`pkg/identity/apikey/rotatable.go` implements exactly this
(`rotatableStore`/`buildRotatableStore`, backed by
`pkg/keyrotation.KeySet`, with `notBefore`/`notAfter`/`gracePeriod`
per key), but nothing calls it — `factory()`/`buildStore()` in
`apikey.go` only ever construct a `static` or `hashed` store; there's
no code path that reaches `buildRotatableStore`. A `secrets:` field
on the `apikey` config isn't recognized either (`buildStore` requires
exactly one of `static`/`hashed`) — using it fails config validation
with `one of static / hashed is required`, not a working rotation.

For time-bounded key rotation today, use
[`hashed.entries` with two overlapping entries](../cookbook/apikey-static-backend.md#4-zero-downtime-key-rotation)
(manual add-then-remove, no automatic expiry) instead.

---

## Method 4: Admin API Revocation (Runtime)

Best for: emergency revocation of a compromised key without waiting for
config reload.

> **Note**: Requires `revocation.enabled: true` in config and admin
> endpoints enabled with proper authentication.

### Config

```yaml
revocation:
  enabled: true
  backend: memory    # or "valkey" for multi-replica
  defaultTTL: "720h"  # 30 days
  onStoreError: deny   # fail-closed
```

### Revoke by Key ID — not directly possible

The `apikey` identifier derives a `kid:<keyId>` revocation key
internally (`pkg/identity/apikey/apikey.go`'s `RevocationKeys()`),
but `POST /v1/admin/revoke` has no body field to submit a `kid:`
value directly — only `jti`, `token_hash`, and `subject` are
accepted, and each is prefixed with its own fixed key kind
(`jti:`/`hash:`/`sub:`) by the handler. Submitting
`{"jti": "kid:old-key-2025"}` writes a `jti:kid:old-key-2025`
revocation entry, which will never match the `kid:old-key-2025` key
the `apikey` identifier actually looks up — it's a no-op that looks
like it worked. Use subject-based revocation instead (below), which
revokes every key for that subject rather than just one.

### Revoke by Subject (All Keys for a Service)

```bash
curl -X POST http://lwauth:8080/v1/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject": "svc-a", "reason": "service decommissioned", "ttl": "720h"}'
```

### Limitations

- **Memory backend**: Revocation lost on pod restart (this is the G19
  persistent storage gap). Use Valkey backend for durability.
- **Admin wiring**: The admin `/v1/admin/revoke` endpoint requires
  `Admin.Enabled: true` in the lwauth Options with JWT or mTLS
  authentication configured.

---

## Emergency Revocation Checklist

When a key is confirmed compromised:

1. **Immediate**: Remove the key from the apikeys ConfigMap/Secret
2. **Apply**: `kubectl apply` the updated ConfigMap
3. **Verify**: Confirm lwauth reloaded (check logs for "config reloaded")
4. **Test**: Attempt authentication with the compromised key → 401
5. **Audit**: Review access logs for unauthorized usage during exposure window
6. **Rotate**: Generate and distribute replacement key to affected client
7. **Document**: Record incident, exposure window, and remediation steps

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Old key still works after ConfigMap update | File watcher didn't trigger | Restart pod: `kubectl rollout restart deployment/lwauth` |
| New key rejected | Malformed hash in file | Verify hash format: `$argon2id$v=19$m=65536,t=2,p=1$<b64>$<b64>` |
| All keys rejected | Broken config after reload | Check logs for parse errors; fix file format |
| Revocation lost after restart | Memory backend | Use `backend: valkey` or re-apply revocation after restart |

---

## E2E Validation Script

See `lightweightauth-idp/cmd/e2e-apikey-revocation-test/main.go` for an
automated test that exercises:

1. API key accepted with valid hashed key
2. Key removed from config → immediate rejection
3. Replacement key added → accepted
4. Rotatable key with `notAfter` in past → automatic rejection
