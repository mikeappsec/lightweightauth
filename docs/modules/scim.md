# `scim` — SCIM 2.0 provisioning callback identifier

Authenticates SCIM 2.0 provisioning webhook calls from an IdP (Okta,
Azure AD, OneLogin) via a shared bearer token, and extracts the
provisioned user's identity from the SCIM JSON request body. Unlike the
other identifiers, this one is meant for an IdP-to-lwauth provisioning
callback endpoint, not for authenticating end-user traffic.

**Source:** [pkg/identity/scim](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/scim) — registered as `scim`.

## When to use

- You're exposing a SCIM provisioning endpoint that an IdP calls to push
  user lifecycle events (create/update/deactivate), and need to
  authenticate that the caller is genuinely the configured IdP.
- You want the provisioned user's identity (username, groups, active
  status) available as claims for downstream authorizers, e.g. to reject
  provisioning calls for deactivated accounts.

**Don't use** for end-user request authentication — this identifier
authenticates the *provisioning system*, not individual end users; reach
for [`jwt`](jwt.md), [`saml`](saml.md), or [`apikey`](apikey.md) for that.

## Configuration

```yaml
identifiers:
  - name: scim-provisioning
    type: scim
    config:
      bearerToken: "secret-provisioning-token"
      header: Authorization      # default
      scheme: Bearer             # default
      subjectClaim: userName     # default
      groupsClaim: groups        # default
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bearerToken` | string | *required* | Shared secret token the IdP uses to authenticate provisioning requests |
| `header` | string | `"Authorization"` | HTTP header containing the token |
| `scheme` | string | `"Bearer"` | Authentication scheme prefix |
| `subjectClaim` | string | `"userName"` | JSON field in the SCIM body to extract as subject |
| `groupsClaim` | string | `"groups"` | JSON field in the SCIM body to extract as groups claim |

## Security posture

`bearerToken` is stored as a SHA-256 hash after construction — the
plaintext token is never held in memory beyond config load. Comparison
against the presented token is constant-time. Request bodies are capped
at 1 MiB to prevent memory-exhaustion from an oversized payload. If the
body has no extractable user identity, the module falls back to a
`"scim-provisioner"` subject rather than failing closed, since some SCIM
lifecycle calls (e.g. a bare deactivation) may not carry a full user
object.

## Helm wiring

File mode (default chart):

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: scim-provisioning
        type: scim
        config:
          bearerToken: "vault://kv/lwauth/scim#token"
    authorizers:
      - { name: gate, type: rbac, config: { rolesFrom: "claim:groups", allow: ["provisioner"] } }
```

lwauth does not expand `${VAR}`-style placeholders anywhere in
`AuthConfig` — `bearerToken: ${SCIM_PROVISIONING_TOKEN}` would send
the literal six characters. `secretRef: "vault://..."` (shown above)
is resolved at compile time; templating the YAML at the
deployment-pipeline layer (Helm, Kustomize, CI) works too.

CRD mode adds nothing extra — the same YAML lives under
`spec.identifiers` of an `AuthConfig` CR.

## Composition

- Pair with [`rbac`](rbac.md) or [`cel`](cel.md) to gate provisioning
  actions on the extracted `active`/`groups` claims (e.g. deny writes for
  a deactivated user).
- Typically the only identifier on a dedicated provisioning route —
  combine with routing/path-based `AuthConfig` scoping rather than
  `firstMatch` alongside end-user identifiers, since SCIM callers and end
  users hit different paths.

## References

- SCIM 2.0: RFC 7643 (Core Schema), RFC 7644 (Protocol).
- [DESIGN.md §4](../DESIGN.md) — identity & credential modules.
- Source: [pkg/identity/scim](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/scim/README.md).
