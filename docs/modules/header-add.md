# `header-add` — Stamp upstream / response headers

Adds (or overwrites) headers on the upstream request and/or downstream
response. The most common mutator — used to forward identity downstream
without re-parsing the bearer.

**Source:** [pkg/mutator/headers](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/mutator/headers/headers.go) — registered as `header-add`.

## When to use

- Send `X-User-Id`, `X-Tenant`, `X-Roles` to your application.
- Inject correlation / audit headers for downstream observability.
- Produce a per-tenant `Vary` cache key on the response.

## Configuration

```yaml
response:
  - name: stamp
    type: header-add
    config:
      # Convenience: stamp Identity.Subject into a single header.
      subjectHeader: X-User-Id

      upstream:
        X-Tenant: "${claim:tenant}"
        X-User:   "${sub}"

      response:
        X-Auth-By: lwauth
```

Values support two placeholders, expanded per request: `${sub}`
(`Identity.Subject`) and `${claim:<name>}` (looked up in
`Identity.Claims`, stringified with `fmt.Sprint`). There is no
template engine (`.Source` / `.Claims` / `{{ }}` / `joinClaims` don't
exist) — an unknown `${...}` token is left in the header verbatim, so
a typo'd claim name is easy to spot at runtime. A claim holding a list
(e.g. `roles: [editor, admin]`) stringifies as Go's default slice
format (`[editor admin]`), not a custom join — do the join upstream if
you need `editor, admin` shaped output.

Setting `at least one of upstream / response / subjectHeader` is
required; unmatched keys are left unset (no `X-Foo: ""` emitted for a
header you didn't configure).

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    response:
      - name: stamp
        type: header-add
        config:
          subjectHeader: X-User-Id
          upstream:
            X-Tenant: "${claim:tenant}"
```

In Mode A (Envoy ext_authz) the `upstream` map maps to the
`OkResponse.headers` field that Envoy adds to the forwarded request.

## Worked example

Identity `{subject: alice, claims: {tenant: acme}}` → upstream sees:

```http
X-User-Id: alice
X-Tenant:  acme
```

## Composition

- Pair with [`header-passthrough`](header-passthrough.md) to keep an
  IdP-set header alongside lwauth-derived ones.
- Pair with [`jwt-issue`](jwt-issue.md) when you need a *signed*
  identity assertion downstream rather than plain headers.

## References

- Source: [pkg/mutator/headers/headers.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/mutator/headers/headers.go).
- DESIGN.md §6 — response mutators.
