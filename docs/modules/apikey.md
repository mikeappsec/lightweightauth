# `apikey` — API key identifier with argon2id storage

Validates static API keys carried in a header. Three production storage
backends (argon2id-hashed) plus a plaintext static map for tests.

**Source:** [pkg/identity/apikey](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/apikey/apikey.go) — registered as `apikey`.

## When to use

- Long-lived programmatic credentials (CI tokens, partner integrations).
- You want hashing at rest (argon2id RFC 9106 §4 interactive params).
- Keys can be rotated by adding a new entry alongside the old one.

**Don't use** for human users. Reach for [`oauth2`](oauth2.md) or [`jwt`](jwt.md).

## Configuration

```yaml
identifiers:
  - name: tenant-keys
    type: apikey
    config:
      headerName: X-Api-Key            # default
      # Pick exactly ONE of static / hashed.

      # ── For tests only ─────────────────────────────────────────────
      static:
        dev-admin-key:  { subject: alice,  roles: [admin] }
        dev-viewer-key: { subject: carol,  roles: [viewer] }

      # ── Production ────────────────────────────────────────────────
      hashed:
        # 1. inline argon2id digests (small static fleets)
        entries:
          ak_alice_2026: { subject: alice, roles: [admin],
                           digest: "$argon2id$v=19$m=65536,t=3,p=2$..." }

        # 2. flat file (one digest per line, ConfigMap-friendly)
        # file: /etc/lwauth/apikeys.txt

        # 3. directory (one file per key — K8s Secret volume mount).
        #    Skips Kubernetes' "..data" symlinks automatically.
        # dir: /etc/lwauth/keys.d
```

Each accepted key produces `Identity{Subject: <subject>, Claims: {keyId, roles, ...}}`. The `keyId` lands in `Identity.Claims["keyId"]` for audit attribution.

Generate a digest:

```bash
lwauthctl apikey hash --subject alice --roles admin
# → ak_alice_2026: $argon2id$v=19$m=65536,t=3,p=2$...
```

## Helm wiring

For `hashed.dir` mode mount a Secret volume:

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: tenant-keys
        type: apikey
        config:
          hashed:
            dir: /etc/lwauth/keys.d
extraVolumes:
  - name: apikeys
    secret: { secretName: lwauth-apikeys }
extraVolumeMounts:
  - name: apikeys
    mountPath: /etc/lwauth/keys.d
    readOnly: true
```

Rotate by `kubectl create secret generic lwauth-apikeys --from-file=...`
and the next argon2id verify picks up the new file (no Pod restart).

## Worked example

```http
GET /things HTTP/1.1
X-Api-Key: ak_alice_2026
```

→ `Identity{Subject: "alice", Source: "tenant-keys", Claims: {keyId: "ak_alice_2026", roles: ["admin"]}}` → [`rbac`](rbac.md) sees `roles=[admin]` → allow.

## Composition

- `firstMatch` with [`jwt`](jwt.md) so service callers can present Bearer
  *or* X-Api-Key.
- `Mutators: [jwt-issue]` to mint an internal JWT downstream — keeps the
  raw API key out of east-west traffic.

## References

- argon2id: RFC 9106.
- Source: [pkg/identity/apikey/apikey.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/apikey/apikey.go), [store.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/apikey/store.go).
