# `opa` — Open Policy Agent / Rego authorizer

Evaluates a Rego policy via embedded OPA. Policy is inline Rego source
only — there is no bundle-loading support (disk or HTTP) today.

**Source:** [pkg/authz/opa](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/opa/opa.go) — registered as `opa`.

## When to use

- Existing Rego corpus you don't want to rewrite.
- Policy team owns rules independently and ships bundles.
- Decisions need explanation traces (Rego `print` / decision logs).

**Don't use** for trivial role checks ([`rbac`](rbac.md)) or relationship
graphs ([`openfga`](openfga.md)).

## Configuration

Config accepts exactly two keys, `rego` and `query`
(`pkg/authz/opa/opa.go`'s `knownKeys`) — any other key, including a
bundle-related one, fails with `unknown config key(s)`.

```yaml
authorizers:
  - name: policy
    type: opa
    config:
      rego: |
        package lwauth

        default allow := false

        allow if {
          input.identity.claims.roles[_] == "admin"
        }

        allow if {
          input.request.method == "GET"
          startswith(input.request.path, sprintf("/tenants/%s/", [input.request.tenantId]))
        }
      query: data.lwauth.allow   # default if omitted
```

`rego` is required (compiled once at config-load time via
`rego.PrepareForEval` — a syntax error fails config compilation, not
a request). `query` defaults to `data.lwauth.allow` if omitted.

`input` shape (`buildInput` in `opa.go`):
`{identity: {subject, source, claims}, request: {method, host, path, tenantId, headers}, context: {...}}`.
`request.headers` is flattened to first-value-only
(`map[string]string`, not `map[string][]string]`) — repeated headers
lose everything past the first value. There is no `request.query`
field (`module.Request` has no query-string field at all in this
codebase).

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    authorizers:
      - name: policy
        type: opa
        config:
          rego: |
            package lwauth
            default allow := false
            allow if input.identity.claims.roles[_] == "admin"
          query: data.lwauth.allow
```

If you want to manage the Rego source as its own file rather than
inline in `values.yaml`, use Helm's `.Files.Get` to read it at chart
render time and interpolate it into `config.inline` — there's no
runtime bundle-loading to mount a file into instead.

## Worked example

```rego
package lwauth
default allow := false
allow if input.identity.claims.roles[_] == "admin"
```

Identity `{claims: {roles: [admin]}}`, any request → `allow=true` → permit.

## Composition

- `composite` `allOf: [rbac, opa]` — fast pre-gate then nuanced policy.
- Cache decisions (M5) keyed on `(identity.subject, request.method, request.path)` to amortize Rego compilation overhead under load.

## References

- OPA / Rego docs: <https://www.openpolicyagent.org>.
- Source: [pkg/authz/opa/opa.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/opa/opa.go).
