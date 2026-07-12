# `assurance` — Step-up MFA / authentication assurance level

Checks the identity's authentication context (`acr`/`amr` claims, and
authentication age) against configurable per-route requirements, and
returns a step-up challenge (`401` with `WWW-Authenticate`) rather than a
flat deny when the identity's current session doesn't meet the bar for
the requested action.

**Source:** [pkg/authz/assurance](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/assurance/assurance.go) — registered as `assurance`.

## When to use

- You want destructive or sensitive operations (`DELETE`, admin routes)
  to require a stronger authentication factor than routine reads, without
  forcing MFA on every request.
- Your IdP populates `acr` (Authentication Context Class Reference) and/or
  `amr` (Authentication Methods References) claims your other identifiers
  already surface on `Identity`.

**Don't use** as your only authorizer — `assurance` checks *how* the
caller authenticated, not *whether* they're allowed to act at all; pair
it with [`rbac`](rbac.md), [`cel`](cel.md), or another authorizer via
[`composite`](composite.md) for the actual allow/deny decision.

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
        - require:                       # default rule — no match means all requests
            acr: ["urn:mfa", "urn:otp"]
```

| Field | Type | Description |
|---|---|---|
| `rules` | list of `Rule` | Evaluated in order; the **first matching** rule whose requirement passes decides the request. A rule with no `match` applies to every request — put it last as a default. |
| `rules[].match.methods` | list of string | HTTP methods this rule applies to (e.g. `["DELETE", "PUT", "PATCH"]`). Omit to match all methods. |
| `rules[].match.paths` | list of glob string | Request paths this rule applies to (e.g. `["/admin/**"]`). Omit to match all paths. |
| `rules[].require.acr` | list of string | Acceptable `acr` values — identity must have **at least one**. Omit to skip the `acr` check. |
| `rules[].require.amr` | list of string | Required `amr` methods — identity must have **all** of these present. Omit to skip the `amr` check. |
| `rules[].require.maxAge` | int (seconds) | Maximum acceptable authentication age, checked against the `auth_time` claim. `0` means no constraint. |

## Behavior

For each request, rules are evaluated in order; the first rule whose
`match` predicate matches the request is applied (unmatched rules are
skipped, not merged). If the identity's claims satisfy that rule's
`require`, the request proceeds to the next authorizer in the chain. If
not, `assurance` returns a `401` decision with `Reason: "assurance:
step-up required for <method> <path>"`, a `StepUp` payload describing what's
missing, and a `WWW-Authenticate` response header built from the step-up
requirement — enough for a client to know what additional authentication
to perform and retry.

If no identity is present at all, the request is denied outright
(`401`, `"assurance: no identity"`) rather than evaluating rules against
an empty identity.

## Composition

- Pair with [`composite`](composite.md) (`allOf: [rbac, assurance]`) so a
  request must pass both a coarse role check and a step-up requirement.
- Typically placed after the primary authorizer in a chain, so routine
  reads never pay the cost of an assurance check that would never fire.

## References

- [DESIGN.md §4](../DESIGN.md) — identity & credential modules.
- OIDC Core §3.1.2.1 — `acr`/`amr` claim semantics.
- Source: [pkg/authz/assurance/assurance.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/assurance/assurance.go).
