# `opa` — Open Policy Agent / Rego authorizer

Evaluates a Rego policy via embedded OPA. Bundles can be loaded from
disk or pulled from an OPA bundle service.

**Source:** [pkg/authz/opa](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/authz/opa/opa.go) — registered as `opa`.

## When to use

- Existing Rego corpus you don't want to rewrite.
- Policy team owns rules independently and ships bundles.
- Decisions need explanation traces (Rego `print` / decision logs).

**Don't use** for trivial role checks ([`rbac`](rbac.md)) or relationship
graphs ([`openfga`](openfga.md)).

## Configuration

```yaml
authorizers:
  - name: policy
    type: opa
    config:
      # Inline policy (great for tests / small rules):
      module: |
        package lwauth

        default allow := false

        allow if {
          input.identity.claims.roles[_] == "admin"
        }

        allow if {
          input.request.method == "GET"
          startswith(input.request.path, sprintf("/tenants/%s/", [input.identity.claims.tenant]))
        }
      query: data.lwauth.allow

      # Or load a bundle:
      # bundleDir: /etc/lwauth/bundles
      # bundleUrl: https://opa-bundles.example.com/lwauth.tar.gz
      # bundlePollInterval: 30s
```

`input` shape: `{identity: {subject, source, claims}, request: {method, path, host, headers, query}}`.

## Helm wiring

Bundle from a ConfigMap:

```yaml
# values.yaml
config:
  inline: |
    authorizers:
      - name: policy
        type: opa
        config:
          bundleDir: /etc/lwauth/opa
          query: data.lwauth.allow
extraVolumes:
  - name: opa-bundle
    configMap: { name: lwauth-opa-bundle }
extraVolumeMounts:
  - name: opa-bundle
    mountPath: /etc/lwauth/opa
    readOnly: true
```

For a bundle service:

```yaml
config:
  inline: |
    authorizers:
      - name: policy
        type: opa
        config:
          bundleUrl: https://opa-bundles.svc.cluster.local/lwauth.tar.gz
          bundlePollInterval: 30s
          query: data.lwauth.allow
```

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
