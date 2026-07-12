# Static API key authentication

Service-to-service calls where one backend needs to authenticate
against lwauth using a pre-shared API key — hashed with argon2id,
stored inline or from a file/directory, with zero-downtime key rotation
via the multi-entry overlap window.

## What this recipe assumes

- lwauth running as an `ext_authz` provider (Envoy or Istio).
- One or more backend services that authenticate with static API keys.
- Keys are hashed before they appear in config (argon2id, RFC 9106).
- You understand that **plaintext keys in config are a security
  vulnerability** — always hash first. The `static:` backend below
  stores keys in plaintext and is for tests/dev only; lwauth logs a
  startup warning if it's loaded.

## 1. Hash your API keys

There's no CLI subcommand for this yet — `apikey.HashKey` is a plain
Go function. Call it directly with `go run`:

```bash
# Generate a random 32-byte key
API_KEY=$(openssl rand -base64 32)
echo "Save this key securely: ${API_KEY}"

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

go run /tmp/hash-apikey.go "${API_KEY}"
# → $argon2id$v=19$m=65536,t=2,p=1$<salt>$<digest>
```

Run it once per key. Each hash is independently salted, so hashing the
same key twice produces different output — that's expected.

## 2. Configure the AuthConfig

Inline hashed entries — suitable for small deployments. Each entry is
keyed by an arbitrary ID (used for revocation and audit attribution):

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
        headerName: X-Api-Key       # default
        hashed:
          entries:
            billing-key-2026:
              hash: "$argon2id$v=19$m=65536,t=2,p=1$salt1$hash1"
              subject: billing-service
              roles: [writer]
            reporting-key-2026:
              hash: "$argon2id$v=19$m=65536,t=2,p=1$salt2$hash2"
              subject: reporting-service
              roles: [reader]

  authorizers:
    - name: rbac
      type: rbac
      config:
        rolesFrom: claim:roles
        allow: [writer, reader]
```

The `apikey` identifier doesn't accept arbitrary custom claims — only
`subject`, `roles`, and (for hashed entries) `keyId` land in
`Identity.Claims`. If you need a tenant claim for `tenantFrom`, put it
in a different identifier (e.g. derive it from the subject naming
convention in an OPA/CEL authorizer) rather than relying on `apikey`
config.

## 3. File-based key store (large deployments)

For many keys without editing YAML per key, use a flat file — one
line per key, whitespace-separated `id hash subject [roles]`:

```yaml
identifiers:
  - name: service-key
    type: apikey
    config:
      headerName: X-Api-Key
      hashed:
        file: /etc/lwauth/apikeys.txt
```

```text
# id                 hash                                                 subject            roles
billing-key-2026      $argon2id$v=19$m=65536,t=2,p=1$salt1$hash1          billing-service    writer
reporting-key-2026    $argon2id$v=19$m=65536,t=2,p=1$salt2$hash2          reporting-service  reader
```

Or a directory — one file per key (K8s Secret volume friendly), where
each file's contents are `<hash>\n<subject>\n[<role1,role2>]`:

```yaml
identifiers:
  - name: service-key
    type: apikey
    config:
      headerName: X-Api-Key
      hashed:
        dir: /etc/lwauth/apikeys/
```

Directory layout:

```text
/etc/lwauth/apikeys/
├── billing-service      # line 1: $argon2id$..., line 2: billing-service, line 3: writer
├── reporting-service
└── analytics-service
```

`hashed.dir` skips Kubernetes' `..data` atomic-rename symlinks
automatically, so it's safe to mount directly from a Secret.

Mount via Helm:

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

`hashed.entries` (and `file`/`dir`) can hold multiple entries for the
same subject — allowing an overlap window where both old and new keys
are accepted:

```yaml
hashed:
  entries:
    billing-key-new:
      hash: "$argon2id$v=19$m=65536,t=2,p=1$newsalt$newhash"
      subject: billing-service
      roles: [writer]
    billing-key-old:
      hash: "$argon2id$v=19$m=65536,t=2,p=1$oldsalt$oldhash"
      subject: billing-service
      roles: [writer]
```

Rotation procedure:

1. Generate a new key and hash it (Step 1 above).
2. Add the new entry to the config (keep the old one).
3. Apply the config — both keys now work.
4. Update the calling service to use the new key.
5. After confirmation, remove the old entry from config.

```bash
# Step 1: Generate and hash
NEW_KEY=$(openssl rand -base64 32)
NEW_HASH=$(go run /tmp/hash-apikey.go "${NEW_KEY}")

# Step 2-3: Add to config and apply
kubectl apply -f updated-authconfig.yaml

# Step 4: Update the calling service's env/secret
kubectl -n billing set env deploy/billing API_KEY="${NEW_KEY}"

# Step 5: Remove old entry after drain window (e.g. 1 hour)
kubectl apply -f authconfig-old-key-removed.yaml
```

## 5. Validate

```bash
# Successful auth
curl -H "X-Api-Key: ${API_KEY}" https://gateway/api/internal/health
# expect: 200

# Wrong key
curl -H "X-Api-Key: wrong" https://gateway/api/internal/health
# expect: 401

# Missing key
curl https://gateway/api/internal/health
# expect: 401

# Dry-run explain
lwauthctl explain --config internal-api.yaml \
    --request '{"method":"GET","path":"/api/internal/health","headers":{"x-api-key":"'${API_KEY}'"}}'
# identify:
#   ✓ service-key (apikey) → subject="billing-service" claims=2
# authorize: ✓ rbac (rbac) allow: ...
# decision: allow identifier="service-key" authorizer="rbac" upstreamHeaders=0 responseHeaders=0
```

## Security notes

- **Constant-time comparison.** The argon2id verifier uses
  `crypto/subtle.ConstantTimeCompare` — timing attacks against the
  hash are not viable.
- **No plaintext storage.** Raw keys appear only in the calling
  service's config/env. lwauth never sees or logs them in cleartext
  in any `hashed.*` backend.
- **`static:` is dev/test only.** It stores keys in plaintext and
  logs a startup warning when loaded — never use it in production.

## Teardown

```bash
kubectl delete authconfig internal-api -n backend
kubectl delete secret lwauth-apikeys -n backend
```
