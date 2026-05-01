# Disaster Recovery Runbook

This document describes backup, restore, and disaster-recovery procedures for LightWeightAuth deployments.

## Recovery Objectives

| Metric | Target | Notes |
|--------|--------|-------|
| **RPO** (Recovery Point Objective) | ≤ 5 min | Config changes are committed to Git; audit events buffered ≤ batch interval |
| **RTO** (Recovery Time Objective) | ≤ 15 min | Rolling restart with last-known-good config from backup |

## 1. Backup Procedures

### 1.1 Manual Backup

```bash
lwauthctl backup --config /etc/lwauth/authconfig.yaml --out /backups/lwauth-$(date +%s).json
```

The backup envelope includes:
- Full AuthConfig (compiled & validated before export)
- SHA-256 checksum of canonical config JSON
- Creation timestamp

### 1.2 Automated Backup (CronJob)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: lwauth-backup
spec:
  schedule: "*/5 * * * *"   # every 5 minutes — matches RPO target
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: ghcr.io/mikeappsec/lwauthctl:latest
            command:
            - lwauthctl
            - backup
            - --config=/etc/lwauth/authconfig.yaml
            - --out=/backups/lwauth-$(date +%s).json
            volumeMounts:
            - name: config
              mountPath: /etc/lwauth
              readOnly: true
            - name: backups
              mountPath: /backups
          volumes:
          - name: config
            configMap:
              name: lwauth-config
          - name: backups
            persistentVolumeClaim:
              claimName: lwauth-backups
          restartPolicy: OnFailure
```

### 1.3 Backup Retention

Keep at least **72 hours** of backups (≈ 864 snapshots at 5-min intervals). Prune older backups with:

```bash
find /backups -name 'lwauth-*.json' -mtime +3 -delete
```

## 2. Restore Procedures

### 2.1 Verify Backup Integrity

```bash
lwauthctl restore --from /backups/lwauth-1714500000.json --verify-only
# Output: restore: integrity OK (sha256:abc123..., created 2026-05-01T00:00:00Z)
```

### 2.2 Restore Config

```bash
lwauthctl restore --from /backups/lwauth-1714500000.json --out /etc/lwauth/authconfig.yaml
```

The restore command:
1. Verifies SHA-256 checksum (aborts if tampered)
2. Validates the config still compiles (warns if not, writes anyway)
3. Writes the config to `--out` path

### 2.3 Apply Restored Config

After restore, trigger the controller reconcile:

```bash
# If using fsnotify (default):
touch /etc/lwauth/authconfig.yaml

# If using Kubernetes:
kubectl rollout restart deployment/lwauth-proxy -n lwauth
```

## 3. Disaster Scenarios

### 3.1 Bad Config Deployed (Policy Regression)

**Symptoms**: Spike in deny decisions, shadow disagreements, or canary mismatches.

**Steps**:
1. Check current policy version: `kubectl get authconfig -o jsonpath='{.spec.version}'`
2. Rollback to previous version:
   ```bash
   lwauthctl rollback --config authconfig.yaml --to-version <prev>
   kubectl apply -f authconfig.yaml
   ```
3. Alternatively, restore from backup:
   ```bash
   lwauthctl restore --from /backups/lwauth-<timestamp>.json --out authconfig.yaml
   kubectl apply -f authconfig.yaml
   ```

### 3.2 Key Material Compromised

**Steps**:
1. Rotate all signing keys immediately:
   ```bash
   kubectl delete secret lwauth-signing-keys -n lwauth
   # Controller will generate new keys on next reconcile
   ```
2. Invalidate all active sessions (tokens signed with old keys will fail verification after grace period expires)
3. Audit logs: search for `decision=allow` events using the compromised key's `kid`

### 3.3 Total Cluster Loss

**Steps**:
1. Stand up new cluster
2. Restore config from off-cluster backup (S3, GCS, etc.):
   ```bash
   aws s3 cp s3://lwauth-backups/latest.json ./backup.json
   lwauthctl restore --from backup.json --out authconfig.yaml
   ```
3. Deploy LightWeightAuth with restored config
4. Generate new key material (keys are never backed up — they are re-generated)
5. Verify with `lwauthctl validate --config authconfig.yaml`

### 3.4 Audit Sink Failure (Loki/Kafka Down)

**Impact**: Audit events dropped (AsyncSink back-pressure). Auth decisions continue unaffected.

**Steps**:
1. Check metrics: `lwauth_audit_events_dropped_total`
2. Restore Loki/Kafka connectivity
3. Dropped events are unrecoverable — review auth decision metrics for the gap window
4. If compliance-critical: replay traffic using `lwauthctl replay` against restored audit sink

## 4. Testing DR Procedures

Run a DR drill quarterly:

1. **Backup validation**: `lwauthctl restore --verify-only` on latest backup
2. **Config restore**: Restore to a staging namespace, verify compilation
3. **Failover timing**: Measure end-to-end RTO from "config deleted" to "first successful auth"
4. **Key rotation**: Practice emergency key rotation in staging

## 5. Monitoring & Alerts

| Alert | Condition | Action |
|-------|-----------|--------|
| `LwauthBackupStale` | No new backup in 15 min | Check CronJob status |
| `LwauthConfigCompileError` | Compile failures > 0 | Roll back config |
| `LwauthAuditDropRate` | Drops > 100/min for 5 min | Scale audit sink / check connectivity |
| `LwauthKeyExpiringSoon` | Key grace period < 1h | Trigger rotation |
