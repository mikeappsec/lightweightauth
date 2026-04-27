# `header-passthrough` — Selective header allow-list

Forwards only the named headers to upstream, dropping everything else
auth-related. Inverse of [`header-remove`](header-remove.md): you list
what stays, not what goes.

**Source:** [pkg/mutator/headers](../../pkg/mutator/headers/headers.go) — registered as `header-passthrough`.

## When to use

- "Zero-trust" stance: deny by default, list the small set of headers
  the application actually needs.
- Multi-tenant gateways where tenant-scoped headers must survive but
  everything else is stripped.

## Configuration

```yaml
mutators:
  - name: allowlist
    type: header-passthrough
    config:
      headers:
        - X-Request-Id
        - X-Forwarded-For
        - X-Forwarded-Proto
        - User-Agent
        - Accept
        - Content-Type
```

Names are case-insensitive. Headers not on the list are not added to the
upstream request. Headers lwauth itself stamps (via `header-add`) are
not affected — this mutator only filters incoming client headers.

## Helm wiring

```yaml
# values.yaml
config:
  inline: |
    mutators:
      - name: allowlist
        type: header-passthrough
        config:
          headers: [X-Request-Id, X-Forwarded-For, User-Agent, Accept, Content-Type]
      - name: stamp
        type: header-add
        config: { subjectHeader: X-User-Id }
```

## Worked example

Client sends 25 headers. `header-passthrough` configured with 6 → only
those 6 reach upstream. Then `header-add` adds `X-User-Id`. Net upstream
header count: 7.

## Composition

- Choose **one** of `header-remove` (drop-list) or `header-passthrough`
  (allow-list) per pipeline — combining them is confusing.
- Always run before [`header-add`](header-add.md) so lwauth-stamped
  headers survive the filter step.

## References

- Source: [pkg/mutator/headers/headers.go](../../pkg/mutator/headers/headers.go).
