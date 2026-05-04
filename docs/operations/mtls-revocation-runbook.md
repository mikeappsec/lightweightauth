# mTLS Certificate Revocation & Replacement Runbook

## Overview

This runbook covers the full lifecycle of revoking a compromised or
expired mTLS client certificate and replacing it with a new one —
without downtime and with immediate denial of the old certificate.

**Applies to**: lwauth deployments using the `mtls` identifier module
with either in-process TLS termination or XFCC header forwarding.

---

## Architecture

```
┌────────────┐  TLS client cert   ┌────────────────┐     ┌───────────────┐
│ API Client │─────────────────────▶ Envoy / Istio  │─────▶  lwauth pod   │
└────────────┘                     │  (terminates)  │XFCC │               │
                                   └────────────────┘     │ 1. Parse XFCC │
                                                          │ 2. Verify CA  │
                                                          │ 3. Check issuer│
                                                          │ 4. Extract subj│
                                                          │ 5. Revocation  │
                                                          └───────────────┘
                                                                  ▲
                                                                  │ hot-reload
                                                           ┌──────┴──────┐
                                                           │  ConfigMap  │
                                                           │  CA bundle  │
                                                           └─────────────┘
```

### Trust Paths

| Mode | How cert reaches lwauth | Trust anchor |
|------|------------------------|--------------|
| In-process TLS | `Request.PeerCerts` (DER from TLS stack) | `--tls-client-ca` flag |
| XFCC header | `X-Forwarded-Client-Cert` header | `trustedCAs` / `trustedCAFiles` in config |

### XFCC Header Format (Envoy)

```
X-Forwarded-Client-Cert: By=...;Hash=...;Cert="<URL-encoded PEM>";Subject="CN=svc-a"
```

---

## Method 1: CA Bundle Rotation (Replace Trust Anchor)

Best for: CA expiry, root compromise, migrating to a new PKI.

### Prerequisites

- lwauth configured with `trustForwardedClientCert: true`
- CA bundle in `trustedCAs` (inline) or `trustedCAFiles` (file path)
- `--watch-config-file` enabled for hot-reload

### Step 1: Generate New CA

```bash
# Generate new CA private key
openssl ecparam -genkey -name prime256v1 -out new-ca.key

# Self-sign new CA certificate (10 years)
openssl req -new -x509 -key new-ca.key -out new-ca.pem -days 3650 \
  -subj "/CN=Corp Root CA v2/O=MyOrg"
```

### Step 2: Issue New Client Cert from New CA

```bash
# Generate client key
openssl ecparam -genkey -name prime256v1 -out client-new.key

# Create CSR
openssl req -new -key client-new.key -out client-new.csr \
  -subj "/CN=svc-payments/O=MyOrg"

# Sign with new CA
openssl x509 -req -in client-new.csr -CA new-ca.pem -CAkey new-ca.key \
  -CAcreateserial -out client-new.pem -days 365 \
  -extfile <(echo "extendedKeyUsage=clientAuth")
```

### Step 3: Deploy Combined CA Bundle (Transition Period)

During transition, trust BOTH old and new CAs:

```yaml
identifiers:
  - name: mtls-auth
    type: mtls
    config:
      trustForwardedClientCert: true
      trustedCAs: |
        -----BEGIN CERTIFICATE-----
        <OLD CA PEM>
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        <NEW CA PEM>
        -----END CERTIFICATE-----
```

Apply ConfigMap → lwauth reloads → certs from both CAs accepted.

### Step 4: Confirm Migration

```bash
# Check which issuer appears in audit logs
kubectl logs deployment/lwauth | grep '"issuer"' | sort | uniq -c
```

### Step 5: Remove Old CA (Revoke All Old Certs)

```yaml
identifiers:
  - name: mtls-auth
    type: mtls
    config:
      trustForwardedClientCert: true
      trustedCAs: |
        -----BEGIN CERTIFICATE-----
        <NEW CA PEM ONLY>
        -----END CERTIFICATE-----
```

Apply → ALL certificates issued by the old CA are immediately rejected.

---

## Method 2: Individual Certificate Revocation (Issuer Allow-List)

Best for: revoking a single service's cert while keeping the CA trusted.

### Using trustedIssuers

The `trustedIssuers` field acts as an allow-list for the cert's Issuer
Distinguished Name. While it doesn't revoke individual certs, it can
restrict which signing CAs are accepted:

```yaml
identifiers:
  - name: mtls-auth
    type: mtls
    config:
      trustForwardedClientCert: true
      trustedCAs: |
        -----BEGIN CERTIFICATE-----
        <CA PEM>
        -----END CERTIFICATE-----
      trustedIssuers:
        - "CN=Corp Intermediate CA,O=MyOrg"
```

To revoke certs from a specific intermediate CA, remove it from
`trustedIssuers`.

---

## Method 3: Admin API Revocation (Runtime — by Serial Number)

Best for: emergency revocation of a specific certificate without
CA rotation.

> **Requires**: `revocation.enabled: true` in config.

### Revoke by Serial Number

```bash
# Find the serial number from access logs or the cert itself:
openssl x509 -in client.pem -serial -noout
# serial=01A2B3C4D5...

curl -X POST http://lwauth:8080/v1/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jti": "serial:01A2B3C4D5", "reason": "compromised", "ttl": "8760h"}'
```

### Revoke by Subject (All Certs for a SPIFFE ID or CN)

```bash
curl -X POST http://lwauth:8080/v1/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject": "spiffe://myorg.example/ns/prod/sa/payments", "reason": "decommissioned"}'
```

### Limitation

Memory-backed revocations are lost on pod restart. Use `backend: valkey`
for durability (or the G19 persistent storage feature when available).

---

## Method 4: CA Bundle Hot-Reload (Zero-Restart)

Best for: automated rotation with no pod restart.

### With CABundleWatcher

lwauth supports file-watching CA bundles via `trustedCAFiles`. When the
file changes on disk (e.g., Kubernetes Secret rotation), the CertPool
is reloaded automatically:

```yaml
identifiers:
  - name: mtls-auth
    type: mtls
    config:
      trustForwardedClientCert: true
      trustedCAFiles: ["/etc/lwauth/tls/ca.pem"]
```

Mount a Kubernetes Secret as a volume:

```yaml
volumes:
  - name: ca-bundle
    secret:
      secretName: lwauth-client-ca
volumeMounts:
  - name: ca-bundle
    mountPath: /etc/lwauth/tls
    readOnly: true
```

Update the Secret → kubelet syncs file → lwauth reloads CertPool.

---

## Method 5: SPIFFE Certificate Rotation

Best for: service mesh environments with automatic cert issuance.

In SPIFFE/SPIRE environments, client certificates are short-lived
(typically 1 hour) and automatically rotated. Revocation is handled by:

1. **Not re-issuing**: The SPIRE agent stops issuing SVIDs for a
   decommissioned workload
2. **CA rotation**: Rotate the trust bundle in lwauth when the SPIFFE
   root CA rotates
3. **Subject revocation**: Revoke the SPIFFE ID via admin API:
   ```bash
   curl -X POST http://lwauth:8080/v1/admin/revoke \
     -d '{"subject": "spiffe://example.org/ns/prod/sa/compromised"}'
   ```

---

## Emergency Revocation Checklist

When a client certificate private key is confirmed compromised:

1. **Immediate**: Remove the issuing CA from `trustedCAs` (nuclear option)
   OR revoke by serial via admin API (surgical)
2. **Apply**: `kubectl apply` the updated ConfigMap or call admin API
3. **Verify**: Test with compromised cert → 401
4. **Re-issue**: Generate new client cert from (possibly new) CA
5. **Distribute**: Deploy new cert to the service
6. **Audit**: Review access logs for serial number during exposure window
7. **Document**: Record incident and remediation

### Decision Matrix

| Scenario | Action |
|----------|--------|
| Single cert compromised, keep CA | Admin API: revoke by serial |
| CA key compromised | Remove CA from bundle immediately |
| Planned CA rotation | Dual-CA bundle → migrate → remove old |
| Service decommissioned | Admin API: revoke by subject |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `xfcc chain verify` error | Cert not signed by trusted CA | Check `trustedCAs` contains correct CA |
| `issuer not trusted` | Issuer DN not in `trustedIssuers` | Add exact issuer string |
| `xfcc Cert is not PEM` | XFCC header malformed | Check URL encoding of cert in header |
| Cert accepted after CA removal | File watcher didn't trigger | Restart pod |
| All certs rejected | CA bundle PEM format error | Validate with `openssl x509 -in ca.pem -text` |

---

## E2E Validation Script

See `lightweightauth-idp/cmd/e2e-mtls-revocation-test/main.go` for an
automated test that exercises:

1. mTLS cert accepted with valid CA trust
2. CA removed from bundle → cert rejected
3. New CA + new cert → accepted
4. Dual-CA transition (both certs accepted)
5. Untrusted CA cert → rejected
