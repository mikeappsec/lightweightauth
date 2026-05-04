# DPoP Proof Key Rotation Runbook

This runbook covers zero-downtime rotation of DPoP proof-signing keys
in server-side pinning mode. Use this when your services have
pre-registered DPoP keys with lwauth and you need to rotate them.

## Prerequisites

- lwauth deployed with DPoP identifier configured
- `kubectl` access to the cluster
- New key material generated (see [Generating Keys](#generating-keys))

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│  Key Lifecycle Timeline                                         │
│                                                                 │
│  ─────────┬──────────┬──────────────────┬─────────┬──────────  │
│           │          │                  │         │             │
│     notBefore(A)   notBefore(B)      notAfter(A) │             │
│           │          │                  │    grace(A)           │
│           │          │                  │         │             │
│  PENDING  │  ACTIVE  │  OVERLAP WINDOW  │RETIRING │  RETIRED   │
│   Key A   │  Key A   │  A + B active    │ Key A   │  Key A     │
│           │          │  B now primary   │         │  rejected  │
│           │          │                  │         │             │
└────────────────────────────────────────────────────────────────┘
```

During the **overlap window**, both keys are accepted. Clients can
migrate to the new key without coordinated cutover.

## Step 1 — Generate New Key Pair

```bash
# Generate an ES256 key pair for the new DPoP proof-signing key.
openssl ecparam -genkey -name prime256v1 -noout -out dpop-key-v2.pem
openssl ec -in dpop-key-v2.pem -pubout -o dpop-key-v2-pub.pem

# Compute the JWK thumbprint (RFC 7638) for cnf.jkt binding.
# Use step-cli or jose tool:
step crypto key fingerprint --format base64url-raw dpop-key-v2-pub.pem
# Output: e.g. "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
```

## Step 2 — Register the New Key (Pending → Active)

Update your lwauth ConfigMap/values to add the new key with overlap:

```yaml
# values.yaml
config:
  inline: |
    identifiers:
      - name: dpop-bearer
        type: dpop
        config:
          required: true
          skew: 30s
          replayCacheSize: 10000

          # Pinned proof keys with rotation metadata
          pinnedKeys:
            - kid: "dpop-v2"
              thumbprint: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
              notBefore: "2026-05-04T12:00:00Z"    # active immediately (or schedule)
              # No notAfter — stays active until explicitly rotated out

            - kid: "dpop-v1"
              thumbprint: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
              notAfter: "2026-05-05T12:00:00Z"     # retire after 24h overlap
              gracePeriod: "10m"                     # 10min grace for in-flight

          inner:
            type: oauth2-introspection
            name: introspect
            config:
              introspectionUrl: https://idp.example.com/oauth2/introspect
              clientId: lwauth-rs
              clientSecret: ${INTROSPECT_SECRET}
```

Apply:

```bash
kubectl apply -f configmap-lwauth.yaml
# lwauth picks up config changes via fsnotify — no restart needed.
```

## Step 3 — Verify Key States

Check that lwauth recognizes both keys:

```bash
# Via admin API (if enabled):
curl -s http://localhost:9090/admin/key-states | jq .

# Expected output:
# [
#   { "kid": "dpop-v2", "state": "active" },
#   { "kid": "dpop-v1", "state": "active" }    ← still in overlap window
# ]
```

Or via Prometheus metrics:

```promql
lwauth_key_state{module="dpop-bearer"}
# dpop-bearer{state="active"} 2
```

## Step 4 — Roll Clients to New Key

Deploy client services with the new DPoP key. During this window both
keys are accepted, so rollout can be gradual.

```go
// Client code — generate DPoP proof with new key
proof := dpop.NewProof(dpop.ProofParams{
    Method:      "POST",
    URL:         "https://api.example.com/orders",
    AccessToken: accessToken,  // for ath binding
    Key:         newPrivateKey, // dpop-v2
})

req.Header.Set("Authorization", "DPoP "+accessToken)
req.Header.Set("DPoP", proof)
```

## Step 5 — Monitor the Transition

Watch for verification failures during rollout:

```promql
# Alert if old key is still being used after expected migration window:
rate(lwauth_key_verify_total{module="dpop-bearer", kid="dpop-v1"}[5m]) > 0

# Check for unexpected rejections:
rate(lwauth_key_verify_total{module="dpop-bearer", result="expired_key"}[5m])
```

Wait until no traffic uses the old key:

```bash
# Check if any requests still use dpop-v1
kubectl logs -l app=lwauth --since=1h | grep 'kid=dpop-v1' | wc -l
# Should be 0 before proceeding to step 6.
```

## Step 6 — Retire Old Key

Once all clients have migrated:

1. The `notAfter` deadline passes (2026-05-05T12:00:00Z in our example).
2. Key transitions to **Retiring** for `gracePeriod` (10 minutes).
3. After grace period, key is **Retired** — proofs using it are rejected.

No manual action needed if `notAfter` was set correctly. To force
immediate retirement, set `notAfter` to a past time:

```yaml
            - kid: "dpop-v1"
              thumbprint: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
              notAfter: "2026-05-04T00:00:00Z"  # already past → retiring
              gracePeriod: "0s"                   # skip grace → immediate retire
```

## Step 7 — Clean Up (Optional)

Remove the retired key entry from config entirely:

```yaml
          pinnedKeys:
            - kid: "dpop-v2"
              thumbprint: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
              # sole active key
```

Verify:

```bash
curl -s http://localhost:9090/admin/key-states | jq .
# [ { "kid": "dpop-v2", "state": "active" } ]
```

## Emergency: Immediate Revocation

If a key is compromised, skip the overlap window:

```bash
# Set notAfter to now, gracePeriod to 0
kubectl patch configmap lwauth-config --type merge -p '
data:
  config.yaml: |
    ... (set compromised key notAfter to past, gracePeriod: 0s) ...'

# Force restart if fsnotify didn't pick it up:
kubectl rollout restart deployment/lwauth
```

All requests using the compromised key will be rejected immediately.
Clients must use the new key or requests will fail.

## Lifecycle State Machine

```
                ┌──────────┐
    now < notBefore │ PENDING  │
                └────┬─────┘
                     │ notBefore reached
                     ▼
                ┌──────────┐
                │  ACTIVE  │  ← accepts proofs signed by this key
                └────┬─────┘
                     │ notAfter reached
                     ▼
                ┌──────────┐
                │ RETIRING │  ← still accepts (grace period for in-flight)
                └────┬─────┘
                     │ notAfter + gracePeriod elapsed
                     ▼
                ┌──────────┐
                │ RETIRED  │  ← rejects all proofs; removed from KeySet
                └──────────┘
```

## How `rotatableIdentifier` Implements This

1. **`KeySet.Put(meta, value)`** — registers a key with its lifecycle bounds.
2. On each DPoP proof verification, if pinning is enabled, the proof's
   JWK thumbprint is checked against the active/retiring keys in the `KeySet`.
3. **`KeyStates()`** reports all keys (any state) for metrics/admin API.
4. If the inner identifier (e.g., introspection client) is also `Rotatable`,
   its key states are merged — giving a unified view of all rotation state.

## Timing Recommendations

| Scenario | Overlap Window | Grace Period |
|----------|---------------|--------------|
| Routine quarterly rotation | 7 days | 10 minutes |
| Incident response | 0 (immediate) | 0 |
| Canary rollout (gradual) | 24–48 hours | 5 minutes |
| Multi-region with clock skew | ≥ 2× max clock drift | 15 minutes |

## Checklist

- [ ] New key generated and thumbprint computed
- [ ] Config updated with new key + overlap window
- [ ] lwauth loaded new config (check logs/metrics)
- [ ] Both keys show as "active" in key-states
- [ ] Client rollout started
- [ ] Old key traffic dropped to zero
- [ ] `notAfter` passed; old key is "retired"
- [ ] Old key entry removed from config (cleanup)
