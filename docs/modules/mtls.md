# `mtls` — Client-certificate / SPIFFE identity

Extracts identity from a TLS peer certificate. Two ingestion paths:
in-process `Request.PeerCerts` (Mode B / native gRPC) and Envoy's
`x-forwarded-client-cert` header (Mode A).

**Source:** [pkg/identity/mtls](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/mtls/mtls.go) — registered as `mtls`.

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
      # XFCC ingestion is OPT-IN. Anything that can reach the auth
      # surface can otherwise forge identity by setting the header
      # itself. Set true only when a verified Envoy/Istio hop strips
      # inbound XFCC and re-emits its own.
      trustForwardedClientCert: true
      header: x-forwarded-client-cert        # default

      # Strongly recommended when trustForwardedClientCert is true:
      # pin the CA roots so a self-signed cert with a forged Issuer DN
      # cannot bypass authentication. Lwauth runs cert.Verify() with
      # this pool as Roots.
      trustedCAFiles:
        - /etc/lwauth/mesh-ca.pem
      # …or inline:
      # trustedCAs: |
      #   -----BEGIN CERTIFICATE-----
      #   ...
      #   -----END CERTIFICATE-----

      # Optional secondary Subject-DN allow-list. NOT a trust check on
      # its own — without trustedCAFiles/trustedCAs an attacker can
      # mint a self-signed cert whose Issuer string matches.
      trustedIssuers:
        - "CN=workload-ca,O=acme"
```

> **Default-deny posture (post-2026-04-28 security review).**
> Without `trustForwardedClientCert: true`, the module ignores the
> XFCC header entirely. Only certificates surfaced via
> `Request.PeerCerts` (i.e. lwauth itself terminated TLS and the Go
> stack verified the peer) are accepted. Supplying `trustedCAFiles` /
> `trustedCAs` without the trust flag is rejected at config compile
> time. **The symmetric mistake is also rejected:**
> `trustForwardedClientCert: true` without **any** anchor — no
> `trustedCAFiles`, no `trustedCAs`, and no `trustedIssuers` — fails
> at compile time so an operator can't accidentally re-enable
> blind-trust XFCC by flipping a single flag.

### Required Envoy / Istio settings

When fronting lwauth with Envoy you must (a) **sanitize** any inbound
XFCC from untrusted clients and (b) **emit** a fresh XFCC from the
verified peer cert. The relevant knobs:

```yaml
# envoy.config.core.v3.HttpConnectionManager
forward_client_cert_details: SANITIZE_SET     # drop inbound, emit ours
set_current_client_cert_details:
  cert: true
  uri:  true
  subject: true
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    grpc_service: { envoy_grpc: { cluster_name: lwauth } }
    include_peer_certificate: true
```

The Helm chart's NetworkPolicy should additionally restrict ingress to
lwauth so the only callers are the trusted Envoy/sidecar peers.

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
- Source: [pkg/identity/mtls/mtls.go](https://github.com/mikeappsec/lightweightauth/blob/main/pkg/identity/mtls/mtls.go).
