# pkg/session

Browser session management with pluggable backends.

## Usage

```go
import (
    "github.com/mikeappsec/lightweightauth/pkg/session"
)

store, err := session.NewCookieStore(session.CookieStoreConfig{
    Name:   "_lwauth_session",
    Secret: []byte("at-least-16-bytes-secret-key!!"),
    Secure: true,
})
if err != nil {
    log.Fatal(err)
}

// Save a session
sess := &session.Session{
    Subject: "user@example.com",
    Email:   "user@example.com",
    Expiry:  time.Now().Add(8 * time.Hour),
}
store.Save(w, sess)

// Load a session
sess, err := store.Load(r)
if sess.Valid() { ... }
```

## Configuration

### CookieStore (stateless, encrypted)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Name` | string | `"_lwauth_session"` | Cookie name |
| `Secret` | []byte | *required* (≥16 bytes) | AES-256 key material |
| `Path` | string | `"/"` | Cookie scope |
| `Secure` | bool | `true` | HTTPS-only |
| `SameSite` | http.SameSite | `Lax` | SameSite attribute |
| `HTTPOnly` | bool | `true` | No JavaScript access |
| `MaxAge` | duration | `8h` | Browser cookie lifetime |
| `CookieMaxBytes` | int | `3500` | Max encrypted cookie size |

### MemoryStore (server-side)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Name` | string | `"_lwauth_sid"` | Session-ID cookie name |
| `JanitorInterval` | duration | `0` (disabled) | Expired session cleanup interval |

## Features

- **CookieStore**: stateless AES-256-GCM encrypted cookies (no server-side state)
- **MemoryStore**: server-side storage with 256-bit random opaque session IDs
- Cookie size guard prevents oversized payloads
- Secret always SHA-256 hashed to derive AES key (normalizes any input length)
- MemoryStore janitor goroutine for automatic expired session cleanup
- Both stores implement the same `Store` interface for easy swapping

## How It Works

- **CookieStore**: serializes session to JSON, encrypts with AES-256-GCM (random 12-byte nonce), base64url-encodes `nonce || ciphertext || tag`, sets as cookie value.
- **MemoryStore**: generates a 256-bit random session ID, stores session in a `sync.Map`, sets the session ID as a cookie. Janitor periodically removes expired entries.
