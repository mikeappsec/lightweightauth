# Local Vault + LightWeightAuth — Setup Runbook

End-to-end guide to test the external secrets resolver (G1) locally
using kind, Vault in dev mode, and LightWeightAuth with a `secretRef`
config.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Docker | 24+ | https://docs.docker.com/get-docker/ |
| kind | 0.20+ | `go install sigs.k8s.io/kind@latest` |
| kubectl | 1.28+ | https://kubernetes.io/docs/tasks/tools/ |
| Helm | 3.14+ | https://helm.sh/docs/intro/install/ |
| Go | 1.26+ | Already installed |

---

## 1. Create a local cluster

```powershell
kind create cluster --name lwauth-dev --wait 60s
kubectl cluster-info --context kind-lwauth-dev
```

---

## 2. Deploy Vault (dev mode)

```powershell
# Add HashiCorp Helm repo
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update

# Install Vault in dev mode (unsealed, root token = "root")
helm install vault hashicorp/vault `
  --set "server.dev.enabled=true" `
  --set "server.dev.devRootToken=root" `
  --set "injector.enabled=false" `
  --wait --timeout 120s
```

Verify Vault is running:

```powershell
kubectl get pods -l app.kubernetes.io/name=vault
# Should show vault-0 Running 1/1
```

---

## 3. Seed Vault with test secrets

```powershell
# Port-forward Vault for local CLI access
kubectl port-forward svc/vault 8200:8200 &

# Set env vars for vault CLI (or use kubectl exec)
$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "root"

# Enable KV v2 (already enabled at secret/ in dev mode)
# Write test secrets
kubectl exec vault-0 -- vault kv put secret/lwauth/hmac-keys `
  svc-a="c3VwZXJzZWNyZXRobWFja2V5MTIzNDU2Nzg=" `
  svc-b="YW5vdGhlcnNlY3JldGtleTk4NzY1NDMyMQ=="

kubectl exec vault-0 -- vault kv put secret/lwauth/cache `
  password="valkey-pass-123"

kubectl exec vault-0 -- vault kv put secret/lwauth/oauth `
  client-secret="oauth-client-secret-value"
```

Verify secrets are readable:

```powershell
kubectl exec vault-0 -- vault kv get -field=svc-a secret/lwauth/hmac-keys
# Should print: c3VwZXJzZWNyZXRobWFja2V5MTIzNDU2Nzg=
```

---

## 4. Configure Vault Kubernetes auth

```powershell
# Enable Kubernetes auth method in Vault
kubectl exec vault-0 -- vault auth enable kubernetes

# Configure it to use the in-cluster SA token reviewer
kubectl exec vault-0 -- sh -c '
  vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" \
    disable_local_ca_jwt=true
'

# Create a policy for lwauth
kubectl exec vault-0 -- vault policy write lwauth - <<'EOF'
path "secret/data/lwauth/*" {
  capabilities = ["read"]
}
EOF

# Bind the lwauth ServiceAccount to the policy
kubectl exec vault-0 -- vault write auth/kubernetes/role/lwauth \
  bound_service_account_names=lightweightauth \
  bound_service_account_namespaces=default \
  policies=lwauth \
  ttl=1h
```

---

## 5. Build and load LightWeightAuth image

```powershell
# Build from the current branch (includes G1 secrets resolver)
cd d:\coding\lightweightauth
docker build -t lightweightauth:dev .

# Load into the kind cluster
kind load docker-image lightweightauth:dev --name lwauth-dev
```

---

## 6. Deploy LightWeightAuth with secretRef config

Create a values override:

```powershell
@"
image:
  repository: lightweightauth
  tag: dev
  pullPolicy: Never

replicaCount: 1

config:
  inline: |
    secrets:
      defaultTtl: "5m"
      backends:
        vault:
          addr: "http://vault.default.svc.cluster.local:8200"
          token: "root"

    identifiers:
      - name: hmac-svc
        type: hmac
        config:
          clockSkew: "5m"
          keys:
            svc-a:
              secret: "vault://secret/data/lwauth/hmac-keys#svc-a"
              subject: "service-a"
              roles:
                - machine

    authorizers:
      - name: allow-all
        type: cel
        config:
          expression: "true"

    response:
      - name: forward-identity
        type: header-add
        config:
          subjectHeader: "X-Auth-Subject"

networkPolicy:
  enabled: false
"@ | Set-Content -Path .\values-dev.yaml
```

> **Note:** For local dev testing, use the static `token: "root"` as
> shown above. For production, remove `token` and use Kubernetes auth
> (see Step 4). The Vault adapter allows plaintext HTTP for
> `*.svc.cluster.local` addresses (in-cluster traffic).

Install the Helm chart:

```powershell
helm install lwauth ./deploy/helm/lightweightauth `
  -f values-dev.yaml `
  --wait --timeout 60s
```

Verify the pod starts (secret resolution happens at startup):

```powershell
kubectl get pods -l app.kubernetes.io/name=lightweightauth
kubectl logs -l app.kubernetes.io/name=lightweightauth --tail=20
```

If the pod is Running, the Vault secret was successfully resolved at
config compile time.

---

## 7. Test end-to-end

Port-forward lwauth:

```powershell
kubectl port-forward svc/lwauth-lightweightauth 8080:8080 &
```

Send a request signed with the HMAC key that was stored in Vault:

```powershell
# The secret "svc-a" in Vault is base64 of "supersecrethmackey12345678"
$secret = [System.Text.Encoding]::UTF8.GetBytes("supersecrethmackey12345678")
$date   = (Get-Date).ToUniversalTime().ToString("r")

# SHA-256 of empty body (downstream request has no body)
$bodySha = [System.Security.Cryptography.SHA256]::Create().ComputeHash([byte[]]@())
$bodyHex = [BitConverter]::ToString($bodySha).Replace("-","").ToLower()

# Build canonical request per pkg/identity/hmac — signed headers: date, host
$canonical = "HMAC-SHA256-V1`nGET`napp.example.com`n/api/data`n`ndate:$date`nhost:app.example.com`ndate,host`n$bodyHex"

$hmacsha     = New-Object System.Security.Cryptography.HMACSHA256
$hmacsha.Key = $secret
$sigBytes    = $hmacsha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
$sig         = [Convert]::ToBase64String($sigBytes)

# Build the /v1/authorize JSON body (downstream request metadata + headers)
$authHeader = 'HMAC-SHA256 keyId=\"svc-a\", signedHeaders=\"date;host\", signature=\"' + $sig + '\"'
$body = '{"method":"GET","host":"app.example.com","path":"/api/data","headers":{"authorization":["' + $authHeader + '"],"date":["' + $date + '"],"host":["app.example.com"]}}'

Invoke-WebRequest -Uri "http://localhost:8080/v1/authorize" `
  -Method POST -Body $body -ContentType 'application/json' -UseBasicParsing
```

Expected: **200 OK** — the HMAC identity was verified and the CEL
authorizer allows all authenticated requests.

Verify failed identity is rejected:

```powershell
# No Authorization header → 401
$noAuth = '{"method":"GET","host":"app.example.com","path":"/api/data","headers":{"host":["app.example.com"]}}'
Invoke-WebRequest -Uri "http://localhost:8080/v1/authorize" `
  -Method POST -Body $noAuth -ContentType 'application/json' -UseBasicParsing
# Expected: 401 Unauthorized

# Invalid signature → 401
$badSig = '{"method":"GET","host":"app.example.com","path":"/api/data","headers":{"authorization":["HMAC-SHA256 keyId=\"svc-a\", signedHeaders=\"date;host\", signature=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\""],"date":["Mon, 01 Jan 2026 00:00:00 GMT"],"host":["app.example.com"]}}'
Invoke-WebRequest -Uri "http://localhost:8080/v1/authorize" `
  -Method POST -Body $badSig -ContentType 'application/json' -UseBasicParsing
# Expected: 401 Unauthorized
```

---

## 8. Test secret rotation

Update the secret in Vault and verify lwauth picks it up on next
config reload (within the `defaultTtl` window):

```powershell
kubectl exec vault-0 -- vault kv put secret/lwauth/hmac-keys `
  svc-a="bmV3c2VjcmV0a2V5YWZ0ZXJyb3RhdGlvbg==" `
  svc-b="YW5vdGhlcnNlY3JldGtleTk4NzY1NDMyMQ=="
```

After the cache TTL expires (5 minutes), the next config reload will
fetch the new value. To force an immediate reload, restart the pod:

```powershell
kubectl rollout restart deployment lwauth-lightweightauth
```

---

## 9. Verify with static token (simpler, no K8s auth)

If Kubernetes auth is problematic, use a static token instead:

```powershell
# Create a Kubernetes secret with the Vault token
kubectl create secret generic vault-token --from-literal=token=root

# Update values-dev.yaml to use static token:
# backends:
#   vault:
#     addr: "http://vault.default.svc.cluster.local:8200"
#     token: "root"
```

---

## 10. Cleanup

```powershell
helm uninstall lwauth
helm uninstall vault
kind delete cluster --name lwauth-dev
Remove-Item values-dev.yaml
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Pod CrashLoopBackOff with "secrets: unknown backend scheme" | Vault adapter not imported | Ensure `_ "pkg/secrets/vault"` import in main |
| "vault: all auth methods failed" | K8s auth not configured | Check Step 4 or use static token (Step 9) |
| "vault: secret/data/... returned 403" | Policy missing | Re-run `vault policy write` in Step 4 |
| "secrets: resolve ... context deadline exceeded" | Vault unreachable | Verify `vault.default.svc.cluster.local:8200` resolves |
| Pod starts but HMAC rejects requests | Wrong secret value | `vault kv get` and compare with signing key |
