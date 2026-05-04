# Multi-cluster federation & revocation sync

Replicate AuthConfig snapshots and revocation entries across clusters
via HMAC-signed gRPC streams. Each cluster independently evaluates
requests using its local engine, receiving config updates and
revocation broadcasts from configured peers.

## What this recipe assumes

- lwauth deployed in 2+ clusters (regions, availability zones).
- Consistent policy across all clusters is required.
- Token revocations in one cluster must propagate to others within
  seconds.
- Network connectivity between clusters on a dedicated port (9443).
- A shared pre-shared key (32–256 bytes) for HMAC-SHA256 signing.

## 1. Generate the federation pre-shared key

```bash
# Generate a 64-byte key (512 bits — well above the 32-byte minimum)
FEDERATION_PSK=$(openssl rand -base64 64)

# Store in each cluster
for CLUSTER in us-east-1 eu-west-1 ap-south-1; do
  kubectl --context ${CLUSTER} -n lwauth-system \
    create secret generic lwauth-federation \
    --from-literal=psk="${FEDERATION_PSK}" \
    --dry-run=client -o yaml | kubectl --context ${CLUSTER} apply -f -
done
```

!!! warning "Key rotation"
    All clusters must share the same key. During rotation, deploy the
    new key to all clusters simultaneously (rolling update). HMAC
    mismatch rejects the payload — a staggered rollout causes a brief
    sync blackout.

## 2. Configure the control cluster (us-east-1)

The control cluster pushes config to edge clusters and receives
revocation broadcasts from all peers:

```yaml
apiVersion: lightweightauth.io/v1alpha1
kind: AuthConfig
metadata:
  name: platform-api
  namespace: production
spec:
  identifiers:
    - name: bearer
      type: jwt
      config:
        issuerUrl: https://idp.example.com
        audiences: [platform-api]

  authorizers:
    - name: rbac
      type: rbac
      config:
        rolesFrom: claim:roles
        allow: [user, admin]

---
# Federation config (top-level, outside AuthConfig)
# Typically in the Helm values inline config block:
federation:
  enabled: true
  clusterID: "us-east-1"
  federationKey: "${FEDERATION_PSK}"
  syncInterval: "30s"
  revocationTTL: "24h"
  peers:
    - endpoint: "eu-west-1.lwauth.internal:9443"
      tlsCertFile: /etc/lwauth/federation-client.pem
      tlsKeyFile: /etc/lwauth/federation-client-key.pem
      tlsCAFile: /etc/lwauth/federation-ca.pem
      namespaces: ["production"]
    - endpoint: "ap-south-1.lwauth.internal:9443"
      tlsCertFile: /etc/lwauth/federation-client.pem
      tlsKeyFile: /etc/lwauth/federation-client-key.pem
      tlsCAFile: /etc/lwauth/federation-ca.pem
      namespaces: ["production"]
```

## 3. Configure edge clusters

Each edge cluster points back to the control cluster:

```yaml
# eu-west-1 config
federation:
  enabled: true
  clusterID: "eu-west-1"
  federationKey: "${FEDERATION_PSK}"
  syncInterval: "30s"
  revocationTTL: "24h"
  peers:
    - endpoint: "us-east-1.lwauth.internal:9443"
      tlsCertFile: /etc/lwauth/federation-client.pem
      tlsKeyFile: /etc/lwauth/federation-client-key.pem
      tlsCAFile: /etc/lwauth/federation-ca.pem
    - endpoint: "ap-south-1.lwauth.internal:9443"
      tlsCertFile: /etc/lwauth/federation-client.pem
      tlsKeyFile: /etc/lwauth/federation-client-key.pem
      tlsCAFile: /etc/lwauth/federation-ca.pem
```

## 4. Topology options

### Hub-spoke (recommended for most deployments)

One control cluster pushes to all edges. Edges only talk to the hub:

```text
                    ┌─────────────┐
                    │  us-east-1  │
                    │  (control)  │
                    └──────┬──────┘
                   ┌───────┼───────┐
                   ▼       ▼       ▼
            ┌──────────┐ ┌──────────┐ ┌──────────┐
            │ eu-west-1│ │ap-south-1│ │ us-west-2│
            │  (edge)  │ │  (edge)  │ │  (edge)  │
            └──────────┘ └──────────┘ └──────────┘
```

### Full mesh

Every cluster talks to every other. More resilient but more
connections (`N × (N-1)` streams):

```text
    us-east-1 ←──→ eu-west-1
        ↕       ╲       ↕
    ap-south-1 ←──→ us-west-2
```

## 5. Revocation broadcast

A revocation in one cluster propagates to all peers automatically:

```bash
# Revoke a token in us-east-1
curl -X POST https://lwauth.us-east-1:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -d '{
    "key": "jti:compromised-token-abc",
    "reason": "credential-leak",
    "ttl": "1h"
  }'
```

Within one `syncInterval` (30s default), the revocation appears in
all peer clusters. The token is immediately rejected everywhere.

Timeline:

```text
T+0s:   Revoke in us-east-1 → local store updated, request denied immediately
T+0-30s: Broadcast to eu-west-1, ap-south-1 (within syncInterval)
T+30s:  All clusters deny the token
```

## 6. Config snapshot sync

When you update an AuthConfig in the control cluster, the new config
is HMAC-signed and pushed to all peers:

```bash
# Update config in us-east-1
kubectl --context us-east-1 apply -f updated-authconfig.yaml

# Within syncInterval, all edges receive the new config
# Verify in eu-west-1:
kubectl --context eu-west-1 get authconfig platform-api -o jsonpath='{.status.lastSyncVersion}'
```

Version monotonicity ensures stale snapshots (lower version or older
timestamp) are rejected — a delayed packet cannot overwrite a newer
config.

## 7. Security model

| Control | Description |
|---------|-------------|
| HMAC-SHA256 signing | Every payload signed; receiver verifies |
| Constant-time compare | `crypto/subtle` prevents timing attacks |
| Known-peer auth | Only pre-configured endpoints accepted |
| mTLS transport | All peer traffic requires mutual TLS |
| Version monotonicity | Stale snapshots rejected |
| Key never serialized | `federationKey` tagged `json:"-" yaml:"-"` |

## 8. Helm wiring (per cluster)

```yaml
# values.yaml (us-east-1)
config:
  inline: |
    federation:
      enabled: true
      clusterID: "us-east-1"
      federationKey: "${FEDERATION_PSK}"
      syncInterval: 30s
      revocationTTL: 24h
      peers:
        - endpoint: "eu-west-1.lwauth.internal:9443"
          namespaces: ["production"]
        - endpoint: "ap-south-1.lwauth.internal:9443"
          namespaces: ["production"]
    identifiers:
      - name: bearer
        type: jwt
        config:
          issuerUrl: https://idp.example.com
          audiences: [platform-api]
    authorizers:
      - name: rbac
        type: rbac
        config:
          rolesFrom: claim:roles
          allow: [user, admin]
env:
  - name: FEDERATION_PSK
    valueFrom:
      secretKeyRef:
        name: lwauth-federation
        key: psk
extraVolumes:
  - name: federation-tls
    secret:
      secretName: lwauth-federation-tls
extraVolumeMounts:
  - name: federation-tls
    mountPath: /etc/lwauth
    readOnly: true
```

## 9. Failure modes

| Scenario | Behavior |
|----------|----------|
| Peer unreachable | Local engine continues with last config; reconnects on next sync |
| HMAC mismatch | Payload rejected; `lwauth_federation_errors_total{reason="hmac"}` incremented |
| Version regression | Stale snapshot rejected (monotonicity) |
| Network partition | Each cluster operates independently until connectivity restores |
| PSK mismatch during rotation | Sync fails until all clusters have the new key |

## 10. Monitoring

```promql
# Federation sync lag (should be < syncInterval)
lwauth_federation_last_sync_seconds

# Failed sync attempts
rate(lwauth_federation_errors_total[5m])

# Revocation broadcast latency
lwauth_federation_revocation_broadcast_duration_seconds

# Peer connection state
lwauth_federation_peer_connected{peer="eu-west-1"}
```

Alert on `lwauth_federation_last_sync_seconds > 120` — indicates
a peer has been unreachable for > 2 sync intervals.

## 11. Validate

```bash
# Check federation status in each cluster
for CTX in us-east-1 eu-west-1 ap-south-1; do
  echo "=== ${CTX} ==="
  kubectl --context ${CTX} exec deploy/lwauth -- \
    lwauthctl federation status
done
# expect: connected peers, last sync time, version

# Test cross-cluster revocation
# Revoke in us-east-1
curl -X POST https://lwauth.us-east-1:9000/v1/admin/revoke \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -d '{"key":"jti:test-token","reason":"test","ttl":"5m"}'

# Wait for sync
sleep 35

# Verify denied in eu-west-1
curl -H "Authorization: Bearer ${TOKEN_WITH_JTI_test-token}" \
     https://gateway.eu-west-1/api/resource
# expect: 401
```

## Teardown

```bash
for CTX in us-east-1 eu-west-1 ap-south-1; do
  kubectl --context ${CTX} delete secret lwauth-federation -n lwauth-system
  kubectl --context ${CTX} delete secret lwauth-federation-tls -n lwauth-system
done
```
