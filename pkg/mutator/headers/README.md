# pkg/mutator/headers

Response header mutators: add, remove, and passthrough.

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/mutator/headers"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

mutator, err := module.BuildMutator("add-user-header", "header-add", map[string]any{
    "upstream": map[string]string{
        "X-User":  "${sub}",
        "X-Email": "${claim:email}",
    },
})
```

## Configuration

### header-add

```yaml
mutators:
  - name: add-user-header
    type: header-add
    config:
      upstream:
        X-User: "${sub}"
        X-Email: "${claim:email}"
        X-Tenant: "acme"
      response:
        X-Request-Id: "${claim:jti}"
      subjectHeader: "X-Auth-Subject"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `upstream` | map[string]string | — | Headers to add upstream (supports `${claim:x}`, `${sub}`) |
| `response` | map[string]string | — | Headers to add to client response |
| `subjectHeader` | string | — | Convenience: sets this header = identity subject |

### header-remove

```yaml
mutators:
  - name: strip-internal
    type: header-remove
    config:
      upstream:
        - X-Internal-Debug
        - X-Forwarded-For
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `upstream` | []string | *required* | Header names to strip |

### header-passthrough

```yaml
mutators:
  - name: pass-trace
    type: header-passthrough
    config:
      headers:
        - X-Request-Id
        - X-Trace-Id
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `headers` | []string | *required* | Header names to copy from inbound request |

## Features

- Three registered module types: `header-add`, `header-remove`, `header-passthrough`
- Placeholder expansion: `${sub}` (identity subject), `${claim:<key>}` (any claim value)
- Unknown placeholders left as-is for debugging visibility
- `header-remove` sets value to `""` — Envoy ext_authz interprets as delete
- At least one field required for `header-add` (validated at factory time)

## How It Works

1. **header-add**: Resolves placeholders in configured values using the identity, then sets the headers on the decision's upstream/response maps.
2. **header-remove**: Sets specified header names to empty string in upstream headers (signals deletion to the proxy).
3. **header-passthrough**: Copies the first value of each listed header from the inbound request to the upstream headers.
