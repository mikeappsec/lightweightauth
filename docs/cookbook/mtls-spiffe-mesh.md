# mTLS & SPIFFE service identity

Authenticate workloads via mutual TLS client certificates and SPIFFE
identity documents. Covers both direct mTLS termination and Envoy's
XFCC (X-Forwarded-Client-Cert) header in a service mesh, with policy
decisions based on SPIFFE URI SANs.

## What this recipe assumes

- A SPIFFE-compatible identity provider (SPIRE, Istio Citadel, or
  cert-manager with SPIFFE trust domain).
- Workloads present X.509 SVIDs with SPIFFE URI SANs
  (e.g. `spiffe://cluster.local/ns/payments/sa/billing`).
- Either direct mTLS termination at lwauth, or Envoy/Istio forwarding
  the peer certificate via the XFCC header.
- `lwauthctl` v1.0+ on your workstation.

## 1. Direct mTLS termination

lwauth terminates TLS itself and validates the client certificate
against a trusted CA bundle:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: service-mesh-auth
  namespace: platform
spec:
  identifiers:
    - name: workload-cert
      type: mtls
      config:
        # Trusted CA bundle — hot-reloaded on filesystem change
        caFile: /etc/lwauth/trust-bundle.pem
        # Extract identity from SPIFFE URI SAN
        subjectFrom: spiffe-uri    # "spiffe-uri" | "cn" | "dns-san"
        # Optional: required SPIFFE trust domain
        trustDomain: cluster.local

  authorizers:
    - name: service-rbac
      type: rbac
      config:
        rolesFrom: claim:spiffe-path
        allow:
          - /ns/payments/sa/billing
          - /ns/orders/sa/order-processor
```

The `mtls` identifier extracts:

| Field | Value |
|-------|-------|
| `subject` | Full SPIFFE URI (`spiffe://cluster.local/ns/payments/sa/billing`) |
| `claims.spiffe-path` | Path portion (`/ns/payments/sa/billing`) |
| `claims.spiffe-trust-domain` | Trust domain (`cluster.local`) |
| `claims.serial` | Certificate serial number (hex) |
| `claims.not-after` | Certificate expiry (RFC 3339) |
| `claims.dns-sans` | DNS SANs (array) |

## 2. Envoy XFCC header mode

When Envoy terminates mTLS and forwards the client cert in the
`X-Forwarded-Client-Cert` header:

```yaml
identifiers:
  - name: workload-cert
    type: mtls
    config:
      # Use XFCC instead of direct TLS
      source: xfcc               # "tls" (default) | "xfcc"
      # Still validate the cert chain against a CA
      caFile: /etc/lwauth/trust-bundle.pem
      subjectFrom: spiffe-uri
      trustDomain: cluster.local
      # Only trust XFCC from known proxies (security critical)
      trustedProxyCIDRs:
        - 10.0.0.0/8
        - fd00::/8
```

!!! warning "XFCC trust boundary"
    The `trustedProxyCIDRs` field is **critical**. Without it, any
    client could forge an XFCC header. Only trust the CIDR range
    your Envoy sidecars / gateways use.

Envoy must be configured to set XFCC on the upstream connection:

```yaml
# Envoy cluster config
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
    common_tls_context:
      tls_certificates: [...]
http_connection_manager:
  forward_client_cert_details: SANITIZE_SET
  set_current_client_cert_details:
    uri: true
    cert: true
```

## 3. SPIFFE-aware authorization with CEL

For fine-grained policies beyond simple RBAC, use CEL to match on
SPIFFE path components:

```yaml
authorizers:
  - name: spiffe-policy
    type: cel
    config:
      expressions:
        # Only allow payments namespace to call billing endpoints
        - expr: |
            identity.claims["spiffe-path"].startsWith("/ns/payments/") &&
            request.path.startsWith("/api/billing/")
          deny_message: "workload not authorized for billing API"

        # Block any workload outside the trust domain
        - expr: |
            identity.claims["spiffe-trust-domain"] == "cluster.local"
          deny_message: "untrusted SPIFFE domain"
```

## 4. Certificate revocation

Revoke a compromised workload certificate by its serial number:

```bash
# Get the serial from the certificate
SERIAL=$(openssl x509 -in compromised-cert.pem -serial -noout | cut -d= -f2)

# Revoke it
curl -X POST https://lwauth:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -d "{\"key\": \"serial:${SERIAL}\", \"reason\": \"compromised-workload\", \"ttl\": \"24h\"}"
```

The revocation check runs before identification, so the certificate
is rejected before any policy evaluation.

## 5. Hot-reloading the CA bundle

The `mtls` identifier watches the CA file via `fsnotify`. When the
trust bundle rotates (e.g. cert-manager renews the CA), lwauth picks
up the new bundle without restart:

```yaml
# Mount the trust bundle from a Secret
extraVolumes:
  - name: trust-bundle
    secret:
      secretName: spiffe-trust-bundle
extraVolumeMounts:
  - name: trust-bundle
    mountPath: /etc/lwauth/trust-bundle.pem
    subPath: ca-bundle.pem
    readOnly: true
```

Rotation procedure:

1. Issue a new CA (or intermediate) and add it to the trust bundle.
2. Update the Secret — lwauth hot-reloads within seconds.
3. Workloads gradually get new SVIDs signed by the new CA.
4. Once all old SVIDs have expired, remove the old CA from the bundle.

## 6. Complete Helm example

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: workload-cert
        type: mtls
        config:
          source: xfcc
          caFile: /etc/lwauth/trust-bundle.pem
          subjectFrom: spiffe-uri
          trustDomain: cluster.local
          trustedProxyCIDRs: ["10.0.0.0/8"]
    authorizers:
      - name: service-rbac
        type: rbac
        config:
          rolesFrom: claim:spiffe-path
          allow:
            - /ns/payments/sa/billing
            - /ns/orders/sa/order-processor
            - /ns/frontend/sa/api-gateway
extraVolumes:
  - name: trust-bundle
    secret:
      secretName: spiffe-trust-bundle
extraVolumeMounts:
  - name: trust-bundle
    mountPath: /etc/lwauth
    readOnly: true
```

## 7. Validate

```bash
# Direct mTLS test
curl --cert client.pem --key client-key.pem \
     --cacert server-ca.pem \
     https://lwauth:8443/api/internal/health
# expect: 200

# With XFCC (simulating what Envoy sends)
curl -H 'X-Forwarded-Client-Cert: URI=spiffe://cluster.local/ns/payments/sa/billing;Cert=...' \
     https://gateway/api/billing/invoices
# expect: 200

# Unauthorized workload
curl -H 'X-Forwarded-Client-Cert: URI=spiffe://cluster.local/ns/malicious/sa/attacker' \
     https://gateway/api/billing/invoices
# expect: 403

# Dry-run
lwauthctl explain --config service-mesh-auth.yaml \
    --request '{"method":"GET","path":"/api/billing/invoices","headers":{"x-forwarded-client-cert":"URI=spiffe://cluster.local/ns/payments/sa/billing"}}'
# identify  ✓  mtls  subject=spiffe://cluster.local/ns/payments/sa/billing
# authorize ✓  rbac
```

## Security notes

- **Always validate the chain.** Never trust a client cert without
  verifying it chains to your CA. The `caFile` field is required.
- **Pin the trust domain.** The `trustDomain` field rejects certs
  from other SPIFFE trust domains even if they chain to a valid CA.
- **XFCC is forgeable.** Only trust it from known proxy CIDRs.
  A direct client connection must use `source: tls`, not XFCC.
- **Short-lived SVIDs.** Use 1-hour SVIDs with automatic renewal
  (SPIRE default). This limits the window if a cert is exfiltrated.

## Teardown

```bash
kubectl delete authconfig service-mesh-auth -n platform
kubectl delete secret spiffe-trust-bundle -n platform
```
