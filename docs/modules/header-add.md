# `header-add` — Stamp upstream / response headers

Adds (or overwrites) headers on the upstream request and/or downstream
response. The most common mutator — used to forward identity downstream
without re-parsing the bearer.

**Source:** [pkg/mutator/headers](../../pkg/mutator/headers/headers.go) — registered as `header-add`.

## When to use

- Send `X-User-Id`, `X-Tenant`, `X-Roles` to your application.
- Inject correlation / audit headers for downstream observability.
- Produce a per-tenant `Vary` cache key on the response.

## Configuration

```yaml
mutators:
  - name: stamp
    type: header-add
    config:
      # Convenience: stamp Identity.Subject into a single header.
      subjectHeader: X-User-Id

      upstream:
        X-Tenant: "{{ .Claims.tenant }}"
        X-Roles:  "{{ joinClaims .Claims.roles \", \" }}"
        X-Source: "{{ .Source }}"

      response:
        X-Auth-By: lwauth
```

Values are Go `text/template` expressions evaluated per request with
`.Subject`, `.Source`, and `.Claims` (a `map[string]any`). The helper
`joinClaims` is registered for the common list-of-strings case.

Setting an empty value omits the header (handy for conditional templates).

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    mutators:
      - name: stamp
        type: header-add
        config:
          subjectHeader: X-User-Id
          upstream:
            X-Tenant: "{{ .Claims.tenant }}"
            X-Roles:  "{{ joinClaims .Claims.roles \", \" }}"
```

In Mode A (Envoy ext_authz) the `upstream` map maps to the
`OkResponse.headers` field that Envoy adds to the forwarded request.

## Worked example

Identity `{subject: alice, claims: {tenant: acme, roles: [editor]}}` →
upstream sees:

```http
X-User-Id: alice
X-Tenant:  acme
X-Roles:   editor
X-Source:  bearer
```

## Composition

- Pair with [`header-passthrough`](header-passthrough.md) to keep an
  IdP-set header alongside lwauth-derived ones.
- Pair with [`jwt-issue`](jwt-issue.md) when you need a *signed*
  identity assertion downstream rather than plain headers.

## References

- Source: [pkg/mutator/headers/headers.go](../../pkg/mutator/headers/headers.go).
- DESIGN.md §6 — response mutators.
