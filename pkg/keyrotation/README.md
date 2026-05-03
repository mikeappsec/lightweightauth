# pkg/keyrotation

Seamless verifier-side key rotation with overlap model and lifecycle metrics.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/keyrotation"
)

ks := keyrotation.NewKeySet[[]byte](nil) // nil clock = real time

ks.Put(keyrotation.KeyMeta{
    KID:         "key-2024",
    NotBefore:   time.Now(),
    NotAfter:    time.Now().Add(90 * 24 * time.Hour),
    GracePeriod: 5 * time.Minute,
}, []byte("secret-material"))

key, meta, ok := ks.Get("key-2024")
if ok && meta.IsValid(time.Now()) {
    // Use key for verification
}
```

## Configuration

```yaml
# Common secrets config format used by HMAC, API-key, etc.
secrets:
  - kid: "key-2024"
    secret: "base64-encoded-secret"
    notBefore: "2024-01-01T00:00:00Z"
    notAfter: "2024-12-31T23:59:59Z"
    gracePeriod: "5m"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `KID` | string | *required* | Key identifier |
| `NotBefore` | time | zero (immediately) | Earliest valid time |
| `NotAfter` | time | zero (no expiry) | Key retirement time |
| `GracePeriod` | duration | `5m` | How long after NotAfter key remains usable |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DefaultGracePeriod` | 5 minutes | Grace period when not specified |
| `DefaultMaxEntries` | 64 | Max keys per KeySet |
| `MinSecretLen` | 16 bytes | Minimum secret material length |
| `MaxGracePeriod` | 168h (7 days) | Maximum allowed grace period |

## Key States

| State | Description |
|-------|-------------|
| `Pending` | Before NotBefore — key is registered but not yet valid |
| `Active` | Between NotBefore and NotAfter — primary verification key |
| `Retiring` | Between NotAfter and NotAfter+GracePeriod — still verifies, not for new signing |
| `Retired` | After NotAfter+GracePeriod — no longer usable |

## Features

- Generic `KeySet[T]` supports any secret material type ([]byte, *x509.Certificate, etc.)
- Auto-prunes retired keys when at capacity
- Clock injection for deterministic testing
- `ParseSecretsConfig` handles base64/UTF-8 decoding with min-length enforcement
- Prometheus metrics: `lwauth_key_verify_total`, `lwauth_key_refresh_total`, `lwauth_key_state`

## How It Works

1. Operators configure multiple keys with overlapping validity windows.
2. During the overlap period, both old and new keys are valid for verification.
3. Once the old key passes NotAfter + GracePeriod, it transitions to Retired and is pruned.
4. Metrics track verify attempts per kid, allowing operators to confirm the old key has drained before removal.
