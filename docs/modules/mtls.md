# `mtls` — Client-certificate / SPIFFE identity

Extracts identity from a TLS peer certificate. Two ingestion paths:
in-process `Request.PeerCerts` (Mode B / native gRPC) and Envoy's
`x-forwarded-client-cert` header (Mode A).

**Source:** [pkg/identity/mtls](../../pkg/identity/mtls/mtls.go) — registered as `mtls`.

## When to use

- Service-to-service identity in a mesh (Istio, Linkerd, Consul).
- SPIFFE / SPIRE workloads (URI SAN like `spiffe://td/ns/foo/sa/bar`).
- You terminate mTLS at Envoy and want the SAN to flow into authz.

## Configuration

```yaml
identifiers:
  - name: mesh-mtls
    type: mtls
    config:
      header: x-forwarded-client-cert    # default; Envoy XFCC
      # Optional Subject-DN allow-list for the issuer.
      trustedIssuers:
        - "CN=workload-ca,O=acme"
        - "CN=bootstrap-ca,O=acme"
```

Identity precedence: SPIFFE URI SAN > first DNS SAN > Subject CN. The
identity result is `Identity{Subject: "spiffe://td/ns/foo/sa/bar", Source: "mesh-mtls", Claims: {issuer, dnsSANs, uriSANs, ...}}`.

## Helm wiring

Envoy must be configured to forward XFCC. Operator-side snippet:

```yaml
# Envoy upstream (DESIGN.md §1, Door A)
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service: { envoy_grpc: { cluster_name: lwauth } }
    include_peer_certificate: true       # ← required
```

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: mesh-mtls
        type: mtls
        config:
          trustedIssuers: ["CN=workload-ca,O=acme"]
    authorizers:
      - { name: by-spiffe, type: cel, config: { expression: "identity.subject.startsWith('spiffe://td/ns/orders/')" } }
```

## Worked example

```http
POST /grpc.foo.Bar/Method HTTP/2
x-forwarded-client-cert: By=spiffe://td/ns/api/sa/lwauth;Hash=...;URI=spiffe://td/ns/orders/sa/worker
```

→ `Identity{Subject: "spiffe://td/ns/orders/sa/worker", Source: "mesh-mtls"}` → `cel` allows because the SPIFFE namespace is `orders`.

## Composition

- `firstMatch: [jwt, mtls]`: human users present a JWT, services present a cert.
- Pair with [`rbac`](rbac.md) `rolesFrom: claim:spiffeNs` after stamping
  the SPIFFE namespace into a derived claim via [`cel`](cel.md).

## References

- SPIFFE / SPIRE specs.
- Envoy `x-forwarded-client-cert` header format.
- Source: [pkg/identity/mtls/mtls.go](../../pkg/identity/mtls/mtls.go).
