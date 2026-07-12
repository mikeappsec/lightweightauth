# pkg/identity/apikey

API-key identifier with argon2id hashing for secure at-rest storage.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/apikey"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("apikey", "api-keys", map[string]any{
    "headerName": "X-Api-Key",
    "hashed": map[string]any{
        "file": "/etc/lwauth/api-keys.txt",
    },
})
```

## Configuration

```yaml
identifiers:
  - name: api-keys
    type: apikey
    config:
      headerName: "X-Api-Key"
      hashed:
        file: "/etc/lwauth/api-keys.txt"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `headerName` | string | `"X-Api-Key"` | Header to read the key from |
| `static` | map | `nil` | Plaintext keys (dev/test only) |
| `hashed.file` | string | — | Flat file of argon2id digests |
| `hashed.dir` | string | — | Directory of digest files |
| `hashed.entries` | map (id → `{hash, subject, roles}`) | — | Inline argon2id hashes, keyed by entry ID |

## Features

- Argon2id hashing (RFC 9106 interactive profile: time=2, memory=64MiB (`m=65536` KiB), threads=1)
- Constant-time comparison via `subtle.ConstantTimeCompare`
- Multiple backends: static (dev), hashed file, hashed directory, inline entries
- Empty subjects rejected at configuration time across all backends (APIKEY-VULN-01 fix)
- `pkg/identity/apikey/rotatable.go` implements time-bounded key rotation via
  `keyrotation.KeySet`, but it's **not wired in** — `factory()` never
  constructs it, and `secrets:` isn't a recognized config key (fails
  with `unknown config key(s)`). Use `hashed.entries` with two
  overlapping entries for manual rotation instead.
- Revocation key derivation from keyId and subject
- Production warning when plaintext static backend is loaded

## How It Works

1. Extracts the API key from the configured header.
2. For hashed backends: iterates stored entries, recomputes argon2id with the entry's salt, and uses constant-time comparison.
3. On match, returns `module.Identity` with the key's subject and pre-configured claims/roles.
4. Wire keys are NEVER stored in plaintext in production modes — only argon2id digests.
5. Registers itself as `"apikey"` via `module.RegisterIdentifier` in `init()`.
