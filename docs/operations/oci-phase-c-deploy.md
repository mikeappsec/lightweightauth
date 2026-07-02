# Phase C Deployment Plan — OCI Always Free + ArgoCD

> **Cost principle:** every step targets zero spend. OCI Always Free
> resources are perpetual (not time-limited trial). The plan is structured
> so that a cost-incurring misconfiguration is caught *before* the resource
> is created, and a budget alert fires *immediately* if anything slips
> through.

---

## Tools Required

Install these locally before starting. All are free.

```bash
# OCI CLI
bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)"
oci --version   # verify

# Terraform
# Download from https://developer.hashicorp.com/terraform/downloads (ARM or AMD)
terraform version   # verify ≥ 1.5

# kubectl
# Already installed if you've done local kind work

# ArgoCD CLI
# https://argo-cd.readthedocs.io/en/stable/cli_installation/
argocd version --client

# Git — clone the infra repo once it exists
git clone https://github.com/mikeappsec/lightweightauth-infra
```

---

## Execution Model — GitHub Actions with a manual-approval gate

Terraform is **not** run from a laptop in production. It runs in **GitHub
Actions inside the private `lightweightauth-infra` repo**, with the OCI
credentials stored as repository secrets. To protect against accidental spend,
`apply` is gated behind a **GitHub Environment protection rule** that requires a
human to approve the run after reviewing the plan.

```mermaid
flowchart LR
  PR[Open PR] --> Plan[terraform plan\n+ cost-guard checks]
  Plan --> Review[Human reviews plan\n+ verifies free-tier shapes]
  Review -->|merge to main| Wait[Environment: oci-production\nawaiting approval]
  Wait -->|manual approve| Apply[terraform apply]
  Apply --> Verify[verify-phase-c.sh]
```

**Required GitHub repository secrets** (Settings → Secrets and variables → Actions):

| Secret | Purpose |
|--------|---------|
| `OCI_TENANCY_OCID` | OCI tenancy OCID |
| `OCI_USER_OCID` | OCI user OCID for the Terraform principal |
| `OCI_FINGERPRINT` | API signing-key fingerprint |
| `OCI_PRIVATE_KEY` | PEM contents of the API signing key |
| `OCI_REGION` | e.g. `us-phoenix-1` |
| `OCI_COMPARTMENT_OCID` | Target compartment |
| `TF_VAR_domain` | e.g. `lwauth.example.com` |
| `TF_VAR_admin_email` | Let's Encrypt registration email |
| `TF_VAR_ssh_public_key` | ed25519 public key for the K3s host |
| `CONSOLE_ADMIN_PASSWORD_BCRYPT` | bcrypt hash of the console admin password (see Step 11a) |

> Use OCI **API-key** authentication (the six `OCI_*` secrets above). These are
> the credentials the user is adding to the private repo. The workflow writes
> them into the `~/.oci/config` + key file the OCI provider expects.

**Required GitHub Environment:** create an environment named `oci-production`
with a **required reviewer** (yourself). The `apply` job targets this
environment, so it pauses until approved — nothing is ever created without an
explicit click.

**Workflow** — `lightweightauth-infra/.github/workflows/terraform.yml`:

```yaml
name: terraform
on:
  pull_request:
    paths: ["terraform/**"]
  push:
    branches: [main]
    paths: ["terraform/**"]

permissions:
  contents: read
  pull-requests: write

env:
  TF_IN_AUTOMATION: "true"
  TF_VAR_region: ${{ secrets.OCI_REGION }}
  TF_VAR_compartment_id: ${{ secrets.OCI_COMPARTMENT_OCID }}
  TF_VAR_domain: ${{ secrets.TF_VAR_domain }}
  TF_VAR_admin_email: ${{ secrets.TF_VAR_admin_email }}
  TF_VAR_ssh_public_key: ${{ secrets.TF_VAR_ssh_public_key }}

jobs:
  plan:
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: terraform/oci } }
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Configure OCI credentials
        run: |
          mkdir -p ~/.oci
          printf '%s' "${{ secrets.OCI_PRIVATE_KEY }}" > ~/.oci/key.pem
          chmod 600 ~/.oci/key.pem
          cat > ~/.oci/config <<EOF
          [DEFAULT]
          user=${{ secrets.OCI_USER_OCID }}
          fingerprint=${{ secrets.OCI_FINGERPRINT }}
          tenancy=${{ secrets.OCI_TENANCY_OCID }}
          region=${{ secrets.OCI_REGION }}
          key_file=~/.oci/key.pem
          EOF
      - run: terraform init
      - run: terraform plan -out=tfplan
      # Cost guard: fail the plan if any non-free shape or a classic (billed) LB appears.
      - name: Cost guard
        run: |
          terraform show -json tfplan > plan.json
          if grep -Eo '"shape":"[^"]+"' plan.json | grep -v 'VM.Standard.A1.Flex'; then
            echo "::error::Non-free compute shape detected"; exit 1
          fi
          if grep -q '"oci_load_balancer_load_balancer"' plan.json; then
            echo "::error::Classic (billed) load balancer detected — use network LB"; exit 1
          fi
      - uses: actions/upload-artifact@v4
        with: { name: tfplan, path: terraform/oci/tfplan }

  apply:
    needs: plan
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: oci-production        # <-- requires manual approval
    defaults: { run: { working-directory: terraform/oci } }
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Configure OCI credentials
        run: |
          mkdir -p ~/.oci
          printf '%s' "${{ secrets.OCI_PRIVATE_KEY }}" > ~/.oci/key.pem
          chmod 600 ~/.oci/key.pem
          cat > ~/.oci/config <<EOF
          [DEFAULT]
          user=${{ secrets.OCI_USER_OCID }}
          fingerprint=${{ secrets.OCI_FINGERPRINT }}
          tenancy=${{ secrets.OCI_TENANCY_OCID }}
          region=${{ secrets.OCI_REGION }}
          key_file=~/.oci/key.pem
          EOF
      - uses: actions/download-artifact@v4
        with: { name: tfplan, path: terraform/oci }
      - run: terraform init
      - run: terraform apply -auto-approve tfplan
```

The manual Steps 3–8 below describe exactly what this pipeline does and, more
importantly, **how to verify $0 cost after each stage**. When running via
Actions, perform the same verifications from the job logs (or locally against
the created resources) before approving the next change.

---

## Step 0 — OCI Account Setup (no billable resources)

### 0.1 Verify Always Free eligibility

Log into [cloud.oracle.com](https://cloud.oracle.com), go to
**Billing → Subscriptions**. Confirm the account shows
**"Oracle Cloud Free Tier"** or **"Pay As You Go"** with Always Free
resources available.

> ⚠️ If the account is a **Free Trial** (30-day, $300 credit), the
> Always Free ARM A1 shape may not be available until the trial ends or
> you upgrade to Pay As You Go. Upgrade first (no charge if you stay
> within Always Free limits).

**Verification:**
```bash
oci iam subscription-type list
# Look for: PAYG or FREEMIUM
```

**Cost check:** IAM/account operations are always free. No resources created yet.

---

### 0.2 Configure OCI CLI

```bash
oci setup config
# Follow prompts: user OCID, tenancy OCID, region, API key
oci iam region list   # confirm CLI works
```

Export variables used throughout this plan:
```bash
export TF_VAR_compartment_id="ocid1.compartment.oc1..xxxxxxxx"
export TF_VAR_region="us-phoenix-1"       # Phoenix has best A1 availability
export TF_VAR_domain="lwauth.example.com"
export TF_VAR_admin_email="admin@example.com"
export TF_VAR_github_token="ghp_xxxxx"    # fine-grained PAT, read-only on the infra repo
export TF_VAR_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)"
```

---

## Step 1 — OCI Budget Alert (MUST be first — before any resource)

Create a budget that sends an email the moment any OCI charge appears.
This is the single most important safeguard.

```bash
# Create a $1 budget on the compartment with a 1% alert threshold ($0.01)
oci budgets budget create \
  --compartment-id "$TF_VAR_compartment_id" \
  --display-name "lwauth-zero-spend-guard" \
  --amount 1 \
  --reset-period MONTHLY \
  --budget-processing-period-start-offset 1 \
  --targets '[{"targetType":"COMPARTMENT","values":["'"$TF_VAR_compartment_id"'"]}]' \
  --alert-rules '[{
    "displayName": "any-spend",
    "type": "ACTUAL",
    "threshold": 1,
    "thresholdType": "PERCENTAGE",
    "recipients": "'"$TF_VAR_admin_email"'",
    "message": "Unexpected OCI cost in lwauth compartment"
  }]'
```

**Verification:**
```bash
oci budgets budget list --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[].{"name":"display-name","amount":amount,"alerts":"alert-rule-count"}' \
  --output table
# Expected: lwauth-zero-spend-guard | 1 | 1
```

**Cost check:** Budgets are free. $0 spent.

---

## Step 2 — Terraform State Backend (Object Storage)

Object Storage is free up to 20 GB. We'll use ~1 MB for Terraform state.

```bash
# Create the bucket (free tier)
oci os bucket create \
  --compartment-id "$TF_VAR_compartment_id" \
  --name "lwauth-tf-state" \
  --versioning Enabled \
  --storage-tier Standard

# Verify bucket exists and storage tier is Standard (not Archive, which has retrieval costs)
oci os bucket get --bucket-name "lwauth-tf-state" \
  --query 'data.{"name":name,"tier":"storage-tier","versioning":"versioning"}' \
  --output table
# Expected: lwauth-tf-state | Standard | Enabled
```

**Cost check — storage used so far:**
```bash
oci os ns get-metadata --namespace-name "$(oci os ns get --query 'data' --raw-output)"
# Then check usage:
oci os object list --bucket-name "lwauth-tf-state" --query 'length(data)' --raw-output
# Expected: 0 (empty bucket, 0 objects)
```

**Cost check:** Standard storage ≤ 20 GB is free. No charge.

---

## Step 3 — Terraform Init

```bash
cd lightweightauth-infra/terraform/oci
terraform init \
  -backend-config="bucket=lwauth-tf-state" \
  -backend-config="namespace=$(oci os ns get --query 'data' --raw-output)" \
  -backend-config="region=$TF_VAR_region"
```

**Verification:**
```bash
terraform validate
# Expected: Success! The configuration is valid.

terraform providers
# Should list: hashicorp/oci, hashicorp/random, hashicorp/tls
```

**Cost check:** `terraform init` downloads providers locally. No OCI resources created. $0.

---

## Step 4 — Network (VCN, Subnets, Security Lists)

OCI VCN and subnets are **always free** (no charge for networking primitives).

```bash
# Preview what will be created — no changes applied
terraform plan \
  -target=oci_core_vcn.lwauth \
  -target=oci_core_subnet.public \
  -target=oci_core_subnet.private \
  -target=oci_core_internet_gateway.igw \
  -target=oci_core_route_table.public \
  -target=oci_core_security_list.lwauth \
  -out=tfplan-network

# Inspect the plan: confirm ONLY VCN/subnet/route/security-list resources
terraform show tfplan-network | grep "will be created"
# Must NOT contain: oci_core_instance, oci_network_load_balancer, oci_core_volume
```

Apply:
```bash
terraform apply tfplan-network
```

**Verification:**
```bash
oci network vcn list --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[].{"name":"display-name","cidr":"cidr-block","state":"lifecycle-state"}' \
  --output table
# Expected: lwauth-vcn | 10.0.0.0/16 | AVAILABLE

oci network subnet list --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[].{"name":"display-name","cidr":"cidr-block"}' \
  --output table
# Expected: public (10.0.0.0/24) + private (10.0.1.0/24)
```

**Cost check:**
```bash
oci budgets budget list --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[].{"name":"display-name","spent":"actual-spend"}' \
  --output table
# Expected: actual-spend = 0
```

---

## Step 5 — DNS Zone

OCI DNS zones and queries are **always free**.

```bash
terraform plan -target=oci_dns_zone.lwauth -out=tfplan-dns
terraform show tfplan-dns | grep "will be created"
# Must show: oci_dns_zone.lwauth only
terraform apply tfplan-dns
```

**Verification:**
```bash
oci dns zone list --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[].{"name":name,"type":"zone-type","state":"lifecycle-state"}' \
  --output table
# Expected: lwauth.example.com | PRIMARY | ACTIVE
```

**Cost check:** DNS is free. $0.

---

## Step 6 — Load Balancer ⚠️ Cost-sensitive

The OCI Always Free tier includes **exactly 1 flexible load balancer**
at **10 Mbps maximum bandwidth**. Going above 10 Mbps or creating a
second LB immediately incurs charges.

**Pre-apply check — read the plan carefully:**
```bash
terraform plan -target=oci_network_load_balancer_network_load_balancer.ingress \
  -out=tfplan-lb

terraform show tfplan-lb
```

In the plan output, verify ALL of these before applying:
- `is_private = false` — it must be a public LB
- **No `bandwidth_shape_name` or `bandwidth_in_mbps` field** — flexible LBs
  with 10 Mbps don't need this; if you see `bandwidth_in_mbps = 100`, STOP

```bash
terraform apply tfplan-lb
```

**Post-apply verification:**
```bash
LB_OCID=$(oci nlb network-load-balancer list \
  --compartment-id "$TF_VAR_compartment_id" \
  --query 'data.items[0].id' --raw-output)

oci nlb network-load-balancer get --network-load-balancer-id "$LB_OCID" \
  --query 'data.{"name":"display-name","public-ip":"ip-addresses[0].ip-address","lifecycle-state":"lifecycle-state"}' \
  --output table
# Expected: lwauth-ingress | <public-ip> | ACTIVE

# Verify it is in the free tier — check "is-free-tier" attribute
oci nlb network-load-balancer get --network-load-balancer-id "$LB_OCID" \
  --query 'data."is-free-tier"' --raw-output
# Expected: true
```

Save the LB IP for DNS:
```bash
export LB_IP=$(oci nlb network-load-balancer get \
  --network-load-balancer-id "$LB_OCID" \
  --query 'data."ip-addresses"[0]."ip-address"' --raw-output)
echo "LB IP: $LB_IP"
```

**Cost check:**
```bash
oci budgets budget list --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[].{"name":"display-name","spent":"actual-spend"}' \
  --output table
# Expected: 0 — flexible LBs at ≤10 Mbps are free
```

---

## Step 7 — DNS Records

```bash
terraform plan -target=oci_dns_rrset.apex -target=oci_dns_rrset.wildcard \
  -out=tfplan-dns-records
terraform apply tfplan-dns-records
```

**Verification:**
```bash
# Confirm records point to the LB
dig +short lwauth.example.com @1.1.1.1      # should return $LB_IP (may take a few minutes)
dig +short "*.lwauth.example.com" @1.1.1.1  # should also return $LB_IP
```

If you don't control `lwauth.example.com` DNS globally yet, skip this
test — it will work once the OCI DNS zone is delegated.

---

## Step 8 — Compute Instance (ARM A1) ⚠️ Most critical for cost

The ARM Ampere A1 shape (`VM.Standard.A1.Flex`) is **Always Free** with a
**4 OCPU / 24 GB RAM cap across all A1 instances in the tenancy**. Any A1
instance within this limit is $0. Exceeding it, or choosing any other
shape, is billed immediately.

**Pre-apply check:**
```bash
terraform plan -target=oci_core_instance.k3s -out=tfplan-compute
terraform show tfplan-compute
```

In the plan output, verify ALL of these:
- `shape = "VM.Standard.A1.Flex"` — any other shape (E2, E3, E4, E5, BM) is billed
- `ocpus = 4` and `memory_in_gbs = 24` — exactly the free tier cap
- `source_type = "image"` with an Oracle Linux 9 ARM image OCID
- Boot volume `size_in_gbs ≤ 100` (free tier allows 200 GB total across 2 volumes)

**Check A1 availability in your region before applying:**
```bash
oci compute shape list \
  --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[?name==`VM.Standard.A1.Flex`].{"name":name,"ocpus":"ocpu-options.max","mem":"memory-options.max-in-gbs"}' \
  --output table
# If this returns empty, A1 is not available in this AD — try another AD or region
```

> ⚠️ OCI A1 instances are sometimes capacity-constrained. If the apply
> fails with `Out of host capacity`, try:
> 1. A different Availability Domain (AD) in the same region
> 2. The Phoenix (`us-phoenix-1`) or Ashburn (`us-ashburn-1`) regions
> 3. Wait and retry (capacity is replenished throughout the day)

```bash
terraform apply tfplan-compute
```

**Post-apply verification:**
```bash
INSTANCE_OCID=$(oci compute instance list \
  --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[?contains("display-name", `k3s`)].id | [0]' --raw-output)

oci compute instance get --instance-id "$INSTANCE_OCID" \
  --query 'data.{"shape":shape,"ocpus":"shape-config.ocpus","mem":"shape-config.memory-in-gbs","state":"lifecycle-state"}' \
  --output table
# Expected: VM.Standard.A1.Flex | 4 | 24 | RUNNING

# Verify boot volume size
oci compute boot-volume-attachment list \
  --compartment-id "$TF_VAR_compartment_id" \
  --instance-id "$INSTANCE_OCID" \
  --query 'data[].{"boot-volume-id":"boot-volume-id"}' \
  --output table | xargs -I{} oci bv boot-volume get --boot-volume-id {} \
  --query 'data.{"size":"size-in-gbs"}' --output table
# Expected: ≤ 100 GB
```

**Cost check — immediately after instance creation:**
```bash
oci budgets budget list --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[].{"name":"display-name","spent":"actual-spend"}' \
  --output table
# MUST be 0. If non-zero, terminate the instance immediately:
# oci compute instance terminate --instance-id "$INSTANCE_OCID" --force
```

Also check via Console: **Billing → Cost Analysis** → select "This Month"
→ confirm $0.00.

---

## Step 9 — Wait for Cloud-Init (K3s + ArgoCD bootstrap)

Cloud-init runs on first boot and takes 5–10 minutes.

```bash
# Get the public IP
INSTANCE_IP=$(oci compute instance get --instance-id "$INSTANCE_OCID" \
  --query 'data."public-ip"' --raw-output)

# Watch cloud-init progress
ssh -i ~/.ssh/id_ed25519 opc@$INSTANCE_IP \
  "sudo cloud-init status --wait ; sudo cloud-init status --long"
# Expected: status: done

# Verify K3s
ssh -i ~/.ssh/id_ed25519 opc@$INSTANCE_IP "sudo kubectl get nodes"
# Expected: lwauth-k3s-... Ready  master  Xm  v1.3x.x+k3s1

# Verify ArgoCD pods
ssh -i ~/.ssh/id_ed25519 opc@$INSTANCE_IP \
  "sudo kubectl -n argocd get pods"
# Expected: argocd-server, argocd-repo-server, argocd-application-controller all Running
```

**Fetch the kubeconfig:**
```bash
scp -i ~/.ssh/id_ed25519 opc@$INSTANCE_IP:/etc/rancher/k3s/k3s.yaml ./oci-kubeconfig.yaml
# Replace server address
sed -i "s/127.0.0.1/$INSTANCE_IP/g" ./oci-kubeconfig.yaml
export KUBECONFIG=./oci-kubeconfig.yaml

kubectl get nodes
# Expected: same as above
```

---

## Step 10 — OCI DNS Credentials for cert-manager

cert-manager uses DNS-01 challenge to issue the wildcard Let's Encrypt cert.
It needs OCI credentials to create DNS TXT records.

```bash
# Create an OCI config file for cert-manager (scope to DNS only)
kubectl create secret generic oci-dns-credentials \
  -n cert-manager \
  --from-literal=tenancy="$OCI_TENANCY" \
  --from-literal=user="$OCI_USER_OCID" \
  --from-literal=region="$TF_VAR_region" \
  --from-literal=fingerprint="$OCI_FINGERPRINT" \
  --from-file=privatekey="$HOME/.oci/oci_api_key.pem"
```

---

## Step 11 — ArgoCD App-of-Apps Bootstrap

At this point cloud-init already applied the App-of-Apps manifest. Verify
ArgoCD is syncing everything from `lightweightauth-infra`:

```bash
# Get the initial ArgoCD admin password
ARGOCD_PASS=$(kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath="{.data.password}" | base64 -d)

argocd login $INSTANCE_IP:30080 \
  --username admin --password "$ARGOCD_PASS" \
  --insecure   # HTTPS will work after cert-manager issues the cert

# Check all applications
argocd app list
# Expected (after initial sync completes, ~3 minutes):
# NAME                    STATUS  HEALTH  SYNC
# lwauth-infra            Synced  Healthy Synced
# lwauth-controlplane     Synced  Healthy Synced
# cert-manager            Synced  Healthy Synced
# ingress-nginx           Synced  Healthy Synced
```

**Verification — all ArgoCD apps green:**
```bash
argocd app list --output wide | awk '$3 != "Synced" || $4 != "Healthy" {print "PROBLEM:", $0}'
# Expected: no output (all apps synced and healthy)
```

If any app is OutOfSync:
```bash
argocd app sync <app-name>
argocd app wait <app-name> --health --timeout 120
```

---

## Step 11a — Console Admin Login Secret

The production console requires login (`CP_AUTH_ENABLED=true`). The admin
password is provided as a **bcrypt hash**, never plaintext.

**Generate the hash once** (locally, or it may already be the
`CONSOLE_ADMIN_PASSWORD_BCRYPT` repo secret):

```bash
# Any bcrypt tool works; htpasswd emits a $2y$ hash.
htpasswd -bnBC 12 "" 'YOUR_STRONG_PASSWORD' | tr -d ':\n'
# -> $2y$12$....   (store this as the GitHub secret CONSOLE_ADMIN_PASSWORD_BCRYPT)
```

The hash flows: **GitHub secret → Kubernetes Secret → CP env**. ArgoCD renders
the Secret from the `oci-free` values overlay (or it is applied out-of-band):

```bash
kubectl create secret generic lwauth-console-auth -n lwauth-system \
  --from-literal=password-hash="$CONSOLE_ADMIN_PASSWORD_BCRYPT"
```

The control-plane Deployment consumes it (already in the `oci-free` Helm values):

```yaml
env:
  - name: CP_AUTH_ENABLED
    value: "true"
  - name: CP_AUTH_USERNAME
    value: "admin"
  - name: CP_AUTH_COOKIE_SECURE
    value: "true"            # HTTPS in production
  - name: CP_AUTH_PASSWORD_HASH_FILE
    value: /etc/lwauth/auth/password-hash
volumeMounts:
  - name: console-auth
    mountPath: /etc/lwauth/auth
    readOnly: true
volumes:
  - name: console-auth
    secret:
      secretName: lwauth-console-auth
```

**Verification:**
```bash
# Unauthenticated data request must be rejected.
curl -s -o /dev/null -w "%{http_code}\n" https://lwauth.example.com/v1/controlplane/instances
# Expected: 401

# Login should succeed and set a cookie.
curl -s -c cookies.txt -X POST https://lwauth.example.com/v1/controlplane/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_STRONG_PASSWORD"}'
# Expected: {"authenticated":true,"user":"admin","authEnabled":true}

# Authenticated request now works.
curl -s -b cookies.txt -o /dev/null -w "%{http_code}\n" \
  https://lwauth.example.com/v1/controlplane/instances
# Expected: 200
```

---

## Step 12 — TLS Certificate Issuance

cert-manager will automatically request the Let's Encrypt wildcard cert
once the ClusterIssuer is deployed by ArgoCD.

```bash
# Watch certificate issuance (takes 1–3 minutes after DNS propagates)
kubectl get certificate -n lwauth-system -w
# Expected: lwauth-wildcard ... True  (Ready=True)

# Verify the cert covers the wildcard
kubectl get secret lwauth-wildcard-tls -n lwauth-system \
  -o jsonpath="{.data['tls\.crt']}" | base64 -d | \
  openssl x509 -noout -subject -ext subjectAltName
# Expected: DNS:*.lwauth.example.com, DNS:lwauth.example.com
```

If `READY=False` after 5 minutes:
```bash
kubectl describe certificate -n lwauth-system
kubectl describe certificaterequest -n lwauth-system
kubectl logs -n cert-manager deployment/cert-manager | grep -i "error\|dns"
# Common issue: DNS not yet delegated to OCI. Check NS records.
```

---

## Step 13 — Control Plane Smoke Test

```bash
# CP should be reachable via the ingress
curl -s https://lwauth.example.com/v1/controlplane/health | jq .
# Expected: {"status":"ok"}

# Open the UI
echo "UI: https://lwauth.example.com"
```

---

## Step 14 — End-to-End Validation (§14.5 test matrix)

**Automated:** run the whole-stack verification script once ArgoCD is synced
and the login secret is in place. It is read-only except for one throwaway node
that it creates, verifies, then deletes:

```bash
export CONSOLE_URL=https://lwauth.example.com
export CONSOLE_USER=admin
export CONSOLE_PASSWORD='YOUR_STRONG_PASSWORD'   # or read from your secret store
./scripts/verify-phase-c.sh
# Exits 0 only if every stack component is healthy and the node
# create → verify → delete round-trip succeeds.
```

**Manual matrix** — run every item from the test matrix in the design doc:

Run every item from the test matrix defined in the design doc:

```bash
# 1. Create JWT node with real JWKS URL via UI wizard
#    → verify pod Running, CP shows Healthy

# 2. Create API Key node with inline static keys
curl -s -X POST https://lwauth.example.com/v1/controlplane/instances/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-apikey",
    "namespace": "demo",
    "preset": "internal-tools",
    "identifiers": [{
      "name": "apikey-auth", "type": "apikey",
      "config": {
        "headerName": "X-API-Key",
        "entries": { "key-abc": { "subject": "alice", "roles": ["admin"] } }
      }
    }],
    "authorizers": [{
      "name": "rbac", "type": "rbac",
      "config": { "roles": { "admin": { "permissions": ["read"] } } }
    }],
    "mutators": [{
      "name": "fwd", "type": "header-add",
      "config": { "subjectHeader": "X-Auth-Subject" }
    }]
  }'

# Wait for pod
kubectl rollout status deployment/test-apikey -n demo --timeout=60s

# Auth check
curl -s -X POST https://test-apikey.lwauth.example.com/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/","host":"example.com","headers":{"x-api-key":["key-abc"]}}' | jq .
# Expected: {"allow":true,"subject":"alice"}

# Invalid key
curl -s -o /dev/null -w "%{http_code}" -X POST \
  https://test-apikey.lwauth.example.com/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/","host":"example.com","headers":{"x-api-key":["bad"]}}'
# Expected: 401

# 3. Verify ArgoCD auto-sync after CP image bump (GitOps test):
#    Edit lightweightauth-infra/argocd/values/oci-free/lwauth-controlplane.yaml
#    Bump image.tag to current tag (no-op change)
#    git commit && git push
#    argocd app wait lwauth-controlplane --sync --timeout 300
#    kubectl rollout status deployment -n lwauth-system --timeout=120s
```

---

## Step 15 — Final Cost Verification

After all resources are deployed and validated:

```bash
# 1. OCI Budget check
oci budgets budget list --compartment-id "$TF_VAR_compartment_id" \
  --query 'data[].{"name":"display-name","spent":"actual-spend","forecasted":"forecasted-spend"}' \
  --output table
# Expected: actual-spend = 0, forecasted-spend = 0

# 2. Resource count — verify nothing unexpected was created
oci search resource structured-search \
  --query-text "query all resources where compartmentId = '$TF_VAR_compartment_id'" \
  --query 'data.items[].{"type":"resource-type","name":"display-name","state":"lifecycle-state"}' \
  --output table | sort
# Review the list. Expected resource types:
# - VCN, Subnet (x2), InternetGateway, RouteTable, SecurityList → free
# - NetworkLoadBalancer (x1, flexible) → free
# - Instance (x1, VM.Standard.A1.Flex) → free
# - BootVolume (x1, ≤100 GB) → free
# - Bucket (x1, ≤20 GB) → free
# - DnsZone → free
# Anything else: investigate before proceeding
```

**OCI Console double-check:**
1. Go to **Billing → Cost Analysis**
2. Set date range: "This month" / "All time since account creation"
3. Group by: **Service**
4. Expected: all bars at $0.00

---

## Rollback / Emergency Cleanup

If unexpected charges appear, destroy everything immediately:

```bash
# 1. Terminate the compute instance FIRST (largest ongoing cost risk)
oci compute instance terminate \
  --instance-id "$INSTANCE_OCID" \
  --preserve-boot-volume false \
  --force

# 2. Terraform destroy remaining resources
cd lightweightauth-infra/terraform/oci
terraform destroy -auto-approve

# 3. Delete the Terraform state bucket
oci os object bulk-delete --bucket-name "lwauth-tf-state" --force
oci os bucket delete --bucket-name "lwauth-tf-state" --force

# 4. Verify all resources gone
oci search resource structured-search \
  --query-text "query all resources where compartmentId = '$TF_VAR_compartment_id' && lifecycleState = 'ACTIVE'" \
  --query 'length(data.items)' --raw-output
# Expected: 0 (or only the budget itself)
```

---

## Summary — Free Tier Resource Map

| Resource | Count | Always Free Limit | Our Usage | Billed if exceeded |
|----------|-------|-------------------|-----------|--------------------|
| ARM A1 compute | 1 | 4 OCPU / 24 GB total | 4 OCPU / 24 GB | Immediately |
| Boot volumes | 1 | 200 GB total | 100 GB | $0.0255/GB-month |
| Flexible LB | 1 | 1 LB, 10 Mbps | 1 LB | $0.006/Mbps-hour over |
| Object Storage | 1 bucket | 20 GB | ~1 MB (TF state) | $0.0255/GB-month |
| VCN / Subnets | 1/2 | 2 VCNs | 1 VCN, 2 subnets | Free (VCN itself) |
| DNS Zone | 1 | Unlimited zones | 1 zone | Free |
| Outbound data | — | 10 TB/month | Minimal | $0.0085/GB over |

**The only realistic cost risk is the compute shape.** If `VM.Standard.A1.Flex` is
unavailable and you choose any other shape, you will be charged. The plan's
pre-apply check on Step 8 is the critical gate.
