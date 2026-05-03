# pkg/identity/introspection

RFC 7662 OAuth 2.0 token introspection identifier with three-tier caching.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/identity/introspection"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

identifier, err := module.BuildIdentifier("introspect", "oauth2-introspection", map[string]any{
    "url":          "https://idp.example.com/oauth2/introspect",
    "clientId":     "lwauth",
    "clientSecret": "secret",
})
```

## Configuration

```yaml
identifiers:
  - name: introspect
    type: oauth2-introspection
    config:
      url: "https://idp.example.com/oauth2/introspect"
      clientId: "lwauth"
      clientSecret: "secret"
      cacheSize: 100000
      maxCacheTtl: "5m"
      negativeTtl: "10s"
      errorTtl: "5s"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | *required* | IdP introspection endpoint |
| `clientId` | string | `""` | HTTP Basic auth username |
| `clientSecret` | string | `""` | HTTP Basic auth password |
| `headerName` | string | `"Authorization"` | Header to extract bearer token |
| `cacheSize` | int | `100000` | LRU cache entries per tier |
| `maxCacheTtl` | duration | `5m` | Positive cache cap |
| `negativeTtl` | duration | `10s` | Negative cache TTL |
| `errorTtl` | duration | `5s` | Error cache TTL |

## Features

- Three-tier LRU caching: positive (active tokens), negative (inactive), error (upstream failure)
- Singleflight deduplication for concurrent introspection of the same token
- Circuit breaker via `upstream.Guard` for IdP resilience
- Response body capped at 1 MiB (prevents memory attacks)
- Cache key uses `sha256(token)` — raw tokens never stored
- Client-secret rotation via `keyrotation.KeySet[string]`
- Negative cache prevents DoS amplification to the IdP (K-AUTHN-2)

## How It Works

1. Extracts bearer token from the configured header.
2. Computes `sha256(token)` as the cache key.
3. Checks positive/negative/error caches in order.
4. On cache miss, POSTs `token=<value>&token_type_hint=access_token` to the IdP via circuit breaker.
5. If `active: true`: caches claims with TTL = `min(exp - now, maxCacheTtl)`.
6. If `active: false`: caches in negative tier for `negativeTtl`.
7. On upstream error: caches in error tier for `errorTtl`, returns 503.
