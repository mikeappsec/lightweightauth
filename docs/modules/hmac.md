# HMAC identifier

Symmetric-key request signing for service-to-service traffic. The
client signs a canonical representation of the request with a shared
secret, the server reproduces the same canonical bytes and re-signs
under the looked-up key, and the two are compared in constant time.

## Configuration

```yaml
identifiers:
  - name: services
    type: hmac
    header: Authorization              # default
    scheme: HMAC-SHA256                # default
    dateHeader: Date                   # default
    clockSkew: 5m                      # default
    requiredSignedHeaders: [host, date]  # default; extend to harden
    keys:
      abc:
        secret: "<base64-or-utf8>"
        subject: service-a
        roles: [machine]
```

| Field | Default | Notes |
|---|---|---|
| `header` | `Authorization` | Where the credential is read. |
| `scheme` | `HMAC-SHA256` | Token prefix the parser strips. |
| `dateHeader` | `Date` | Used for replay protection; auto-added to `requiredSignedHeaders`. |
| `clockSkew` | `5m` | Reject if `\|now - Date\|` exceeds this. Set to `0` to disable (not recommended). |
| `requiredSignedHeaders` | `[host, date]` | Headers the signer **must** declare in `signedHeaders`. The verifier rejects an Authorization that omits any of these, even if the math is consistent. Empty list rejected at config load. |
| `keys` | — | Map of `keyId → {secret, subject, roles}`. `secret` is base64 by default; if it doesn't decode, the literal UTF-8 bytes are used. |

## Wire format

### Authorization header

```
Authorization: HMAC-SHA256 keyId="abc", signedHeaders="date;host", signature="<b64>"
```

- `signedHeaders` is `;`-separated by default so the top-level comma
  still cleanly separates the three Authorization parameters. A
  quoted-comma form (`signedHeaders="date,host"`) is also accepted.
- The compact `keyId:signature` form is **not** accepted: it cannot
  carry a `signedHeaders` list, which would let an attacker drop
  headers from the bound set.

### Canonical string

```
HMAC-SHA256-V1
upper(method)
lower(host)
pathWithoutQuery
canonicalQuery
lower(name1):joinedValues1
lower(name2):joinedValues2
...
signedHeadersList
hex(sha256(body))
```

- `canonicalQuery` is the raw query string split on `&`, sorted
  byte-lexicographically, and rejoined. We never URL-decode — signer
  and verifier just need to apply the same transformation, and
  preserving `%xx` escapes verbatim avoids round-trip ambiguity.
- Each header line reproduces the values **in the order the request
  carried them**, joined with a single `,`. Surrounding whitespace
  per value is trimmed (RFC 7230 §3.2.4).
- Header lines appear in the same order as the signer's
  `signedHeaders` list — signer and verifier must agree on order.
- `signedHeadersList` itself is comma-joined and lowercased, and is
  the second-to-last line so an attacker can't pad headers without
  invalidating the signature.

## Replay protection

The verifier requires the configured `dateHeader` (default `Date`),
parses it as either an HTTP date (RFC 7231) or RFC 3339, and rejects
the request if `|now - Date| > clockSkew`.

## Why required signed headers

`requiredSignedHeaders` defends against a downgrade attack where a
compromised signer emits an Authorization header whose `signedHeaders`
list omits `host` (so the verifier reproduces canonical bytes without
binding host). With the requirement in place the verifier walks the
parsed `signedHeaders` list and rejects any request that is missing a
required entry — `host` and the configured `dateHeader` are always
required, and operators can extend the list (e.g. `content-type`,
`x-amz-target`) per route.

## Operational notes

- **Key rotation.** Multiple `keys` entries can coexist. Roll a new
  `keyId` first, switch signers over, then remove the old entry.
- **Body capture.** `MaxBytesReader` upstream will truncate oversized
  bodies; ensure the limit is at least as large as the largest signed
  payload, otherwise verification fails on truncation rather than on
  signature mismatch.
- **Constant-time compare.** Signature comparison uses
  `crypto/subtle.ConstantTimeCompare`; do not switch to byte-wise
  comparison.
