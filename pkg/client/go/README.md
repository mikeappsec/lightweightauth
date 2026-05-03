# pkg/client/go

Go SDK for callers of lwauth-protected services.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/client/go"
)

// Connect to lwauth Door B
client, err := lwclient.Dial("localhost:9001")
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Direct authorization call
resp, err := client.Authorize(ctx, &lwclient.Request{
    Method:  "GET",
    Host:    "api.example.com",
    Path:    "/users/123",
    Headers: map[string]string{"Authorization": "Bearer token"},
})
if resp.Allow { ... }

// gRPC server interceptor (one-line integration)
grpcServer := grpc.NewServer(
    grpc.UnaryInterceptor(client.UnaryServerInterceptor()),
)

// HTTP middleware (one-line integration)
mux := http.NewServeMux()
handler := client.HTTPMiddleware(mux)
```

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `HTTPStatusOnError` | int | `503` | HTTP status when lwauth call fails |
| Dial options | `grpc.DialOption` | insecure creds | Pass `grpc.WithTransportCredentials(...)` for mTLS |

## Features

- Hides generated proto types behind a clean `Request`/`Response` interface
- `UnaryServerInterceptor()` for one-line gRPC server integration
- `HTTPMiddleware()` for one-line HTTP server integration
- Callers never import `api/proto/...` — SDK evolves independently
- Deny maps to `codes.Unauthenticated` (401) or `codes.PermissionDenied` (403)
- Incoming gRPC metadata becomes request headers (first value wins)
- Peer certificates NOT forwarded (lwauth derives from its own TLS stack)

## How It Works

1. `Dial()` connects to the lwauth Door B gRPC service.
2. `Authorize()` sends an `AuthorizeRequest` proto and maps the response to the SDK's `Response` type.
3. `UnaryServerInterceptor()` extracts method name, metadata, and peer info from each incoming RPC; calls Authorize; rejects with appropriate gRPC status code on deny.
4. `HTTPMiddleware()` extracts headers, method, and path from `*http.Request`; calls Authorize; returns the configured error status on deny.
