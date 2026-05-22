# pkg/authz/assurance

Step-up MFA / assurance-level authorizer module (G5 — ID-MFA-1).

## Usage

```go
import (
    "context"
    _ "github.com/mikeappsec/lightweightauth/pkg/authz/assurance"
    "github.com/mikeappsec/lightweightauth/pkg/module"
)

az, err := module.BuildAuthorizer("assurance", "step-up", map[string]any{
    "rules": []any{
        map[string]any{
            "match":   map[string]any{"methods": []any{"DELETE", "PUT"}},
            "require": map[string]any{"acr": []any{"urn:mfa"}},
        },
        map[string]any{
            "match":   map[string]any{"paths": []any{"/admin/**"}},
            "require": map[string]any{"acr": []any{"urn:hwk"}, "amr": []any{"hwk"}, "maxAge": 300},
        },
    },
})
```

## Configuration

```yaml
authorizers:
  - name: step-up
    type: assurance
    config:
      rules:
        - match:
            methods: ["DELETE", "PUT"]
          require:
            acr: ["urn:mfa"]
        - match:
            paths: ["/admin/**"]
          require:
            acr: ["urn:hwk"]
            amr: ["hwk"]
            maxAge: 300
        - require:             # catch-all rule (no match = all requests)
            acr: ["urn:mfa", "urn:otp"]
```

| Field | Type | Description |
|-------|------|-------------|
| `rules` | []Rule | *required* — ordered list of assurance rules (first match wins) |
| `rules[].match.methods` | []string | HTTP methods this rule applies to (empty = all) |
| `rules[].match.paths` | []string | Glob patterns for request path (supports `**` suffix; empty = all) |
| `rules[].require.acr` | []string | Acceptable ACR values (identity must have at least one) |
| `rules[].require.amr` | []string | Required AMR methods (identity must have ALL) |
| `rules[].require.maxAge` | int | Max auth age in seconds (checked against `auth_time` claim) |

## Features

- Rule-based assurance requirements with first-match-wins semantics
- ACR (Authentication Context Class Reference) validation — identity must match at least one
- AMR (Authentication Methods Reference) validation — identity must have ALL required methods
- `auth_time` / `maxAge` freshness enforcement with negative-age rejection (G5-03)
- Step-up challenge response with `WWW-Authenticate` header per RFC 6750 §3 + OIDC extensions
- Glob path matching with `/**` prefix support
- Case-insensitive HTTP method matching
- Returns 401 with structured `StepUp` challenge on insufficient assurance
- Catch-all rules (no `match` block) for default assurance requirements
- No-identity case handled (returns 401 immediately)
- No-rules-matched case allows the request (no assurance constraint)

## How It Works

1. If no identity is present, immediately returns 401.
2. Iterates rules in order until one matches the request (by method and/or path).
3. Checks the identity's ACR against the rule's required values (at-least-one match).
4. Checks the identity's AMR against the rule's required methods (must have ALL).
5. If `maxAge` is set, verifies the `auth_time` claim is within bounds.
6. On failure: returns a 401 deny with a `StepUpChallenge` and `WWW-Authenticate` header.
7. On success: returns allow. If no rule matches the request, allows (no constraint).

## Thread Safety

| Type | Safe for concurrent use? | Notes |
|------|--------------------------|-------|
| `Authorizer` | ✅ Yes | All fields immutable after construction; rules slice is read-only |
| `Rule` | ✅ Yes | Plain value type |
| `MatchPredicate` | ✅ Yes | Plain value type |
| `Requirement` | ✅ Yes | Plain value type |

The `Authorizer` is safe for concurrent use from the pipeline hot path. It holds an immutable slice of rules that are only read during authorization. Each `Authorize` call operates on stack-local variables with no shared mutable state.
