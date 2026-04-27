# `header-remove` — Strip headers before upstream

Drops named headers from the upstream request before it reaches your
application. Pairs with `header-add` so lwauth has full control over
which auth-relevant headers cross the trust boundary.

**Source:** [pkg/mutator/headers](../../pkg/mutator/headers/headers.go) — registered as `header-remove`.

## When to use

- Strip raw bearer / cookie / API key so the application never sees credentials.
- Remove client-spoofable headers (`X-User-Id`, `X-Roles`) that only
  lwauth is allowed to set.
- Hide IdP-specific headers from downstream services.

## Configuration

```yaml
mutators:
  - name: strip
    type: header-remove
    config:
      upstream:
        - Authorization
        - Cookie
        - X-Api-Key
        - X-User-Id     # belt-and-braces against header injection
        - X-Roles
```

`upstream` is a list of header names (case-insensitive). No template
substitution — names are literal.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    mutators:
      - name: strip
        type: header-remove
        config:
          upstream: [Authorization, Cookie, X-Api-Key, X-User-Id, X-Roles]
      - name: stamp
        type: header-add
        config:
          subjectHeader: X-User-Id
          upstream: { X-Roles: "{{ joinClaims .Claims.roles \", \" }}" }
```

The order in `mutators` is significant — strip first, then stamp.

## Worked example

Incoming:

```http
GET /things HTTP/1.1
Authorization: Bearer eyJ...
X-User-Id: attacker          # client-supplied
X-Api-Key: ak_alice_2026
```

After `header-remove` then `header-add`, upstream sees:

```http
GET /things HTTP/1.1
X-User-Id: alice             # set by lwauth, not the client
X-Roles: editor
```

## Composition

- Always pair with [`header-add`](header-add.md). Strip first, stamp second.
- Use [`header-passthrough`](header-passthrough.md) if you want a
  selective allow-list instead of an explicit drop-list.

## References

- Source: [pkg/mutator/headers/headers.go](../../pkg/mutator/headers/headers.go).
