# pkg/identity/mtls

mTLS/SPIFFE client certificate identifier with hot-reloadable CA bundles.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/mtls"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("mtls-id", "mtls", map[string]any{
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

## Features

- In-process TLS termination (PeerCerts) and Envoy XFCC header support
- XFCC trust is opt-in (`trustForwardedClientCert: true`) — default-deny
- SPIFFE URI SAN support (`spiffe://` URIs become the identity subject)
- CA bundle hot-reload via fsnotify (zero-downtime rotation)
- Fail-closed: XFCC trust requires at least one CA anchor
- Revocation key derivation from certificate serial number

## How It Works

1. If the request has `PeerCerts` (in-process TLS termination), those take precedence.
2. Otherwise, if `trustForwardedClientCert` is true, parses the Envoy XFCC header.
3. Decodes the URL-encoded PEM certificate from the XFCC `Cert=` field.
4. Verifies the certificate chain against the configured CA bundle.
5. Extracts identity: SPIFFE URI (if present), or CN, plus full claims (issuer, serial, DNS SANs, etc.).
6. `CABundleWatcher` uses fsnotify to hot-reload the CA file without pod restart.
