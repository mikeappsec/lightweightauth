# pkg/identity/mtls

mTLS/SPIFFE client certificate identifier. The CA bundle is loaded
once at factory build time by default; set `watchCAFile: true` (with
exactly one `trustedCAFiles` entry) to hot-reload it via
`CABundleWatcher` whenever the file changes on disk — see Features
below.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/mtls"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("mtls", "mtls-id", map[string]any{
    "trustForwardedClientCert": true,
    "trustedCAFiles":           []string{"/etc/lwauth/ca-bundle.pem"},
})
```

## Configuration

```yaml
identifiers:
  - name: mtls-id
    type: mtls
    config:
      trustForwardedClientCert: true
      trustedCAFiles:
        - "/etc/lwauth/ca-bundle.pem"
      trustedIssuers:
        - "CN=My CA,O=Example"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `header` | string | `"X-Forwarded-Client-Cert"` | XFCC header name |
| `trustForwardedClientCert` | bool | `false` | Must be true to read XFCC |
| `trustedCAFiles` | []string | `nil` | PEM bundle file paths |
| `trustedCAs` | string | `""` | Inline PEM bundle |
| `trustedIssuers` | []string | `nil` | Subject-DN allow-list |
| `watchCAFile` | bool | `false` | Hot-reload the CA bundle via `CABundleWatcher` — requires exactly one `trustedCAFiles` entry and no `trustedCAs` |

## Features

- In-process TLS termination (PeerCerts) and Envoy XFCC header support
- XFCC trust is opt-in (`trustForwardedClientCert: true`) — default-deny
- SPIFFE URI SAN support (`spiffe://` URIs become the identity subject)
- `ca_watcher.go`'s `CABundleWatcher` (fsnotify-based hot-reload with
  `keyrotation.Metrics.RefreshTotal` counters) is wired into `factory()`
  when `watchCAFile: true` is set: the watcher's goroutine is bound to
  the engine-lifecycle context (`deps.Ctx`) so it's torn down when the
  engine is swapped on hot-reload, and every request reads the current
  pool via an indirection (`identifier.caPool`) rather than a pool
  captured once at construction.
- Fail-closed: XFCC trust requires at least one CA anchor
- Revocation key derivation from certificate serial number

## How It Works

1. If the request has `PeerCerts` (in-process TLS termination), those take precedence.
2. Otherwise, if `trustForwardedClientCert` is true, parses the Envoy XFCC header.
3. Decodes the URL-encoded PEM certificate from the XFCC `Cert=` field.
4. Verifies the certificate chain against the configured CA bundle.
5. Extracts identity: SPIFFE URI (if present), or CN, plus full claims (issuer, serial, DNS SANs, etc.).
6. The CA bundle is loaded once when the identifier is built, unless
   `watchCAFile: true` is set, in which case it's re-read from disk on
   every file-system change event.
