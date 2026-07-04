#!/usr/bin/env bash
# Copyright 2026 LightweightAuth Contributors
# SPDX-License-Identifier: Apache-2.0
#
# verify-phase-c.sh — whole-stack verification for the OCI Always-Free +
# ArgoCD deployment (Phase C). Run AFTER `terraform apply` and the initial
# ArgoCD sync complete.
#
# It is read-only against the cluster except for a single throwaway lwauth
# node that it creates, verifies, and then deletes (exercising the full-teardown
# delete path). It exits non-zero on the first failed check.
#
# Required environment:
#   CONSOLE_URL       e.g. https://lwauth.example.com
#   CONSOLE_USER      console admin username (default: admin)
#   CONSOLE_PASSWORD  console admin password
# Optional:
#   KUBECONFIG        kubeconfig for the OCI cluster (for kubectl checks)
#   NODE_NAMESPACE    namespace for the throwaway node (default: demo)
#   SKIP_KUBECTL      set to 1 to skip cluster-side (kubectl/argocd) checks
set -euo pipefail

CONSOLE_URL="${CONSOLE_URL:?set CONSOLE_URL, e.g. https://lwauth.example.com}"
CONSOLE_USER="${CONSOLE_USER:-admin}"
CONSOLE_PASSWORD="${CONSOLE_PASSWORD:?set CONSOLE_PASSWORD}"
NODE_NAMESPACE="${NODE_NAMESPACE:-demo}"
NODE_NAME="verify-$(date +%s)"
COOKIES="$(mktemp)"
API="${CONSOLE_URL%/}/v1/controlplane"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$1"; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  # Best-effort teardown of the throwaway node + temp files.
  curl -s -b "$COOKIES" -X DELETE "$API/instances/local/$NODE_NAME" >/dev/null 2>&1 || true
  rm -f "$COOKIES"
}
trap cleanup EXIT

# ── 1. Cluster + ArgoCD + cert-manager (skippable) ──────────────────────────
if [[ "${SKIP_KUBECTL:-0}" != "1" ]] && command -v kubectl >/dev/null 2>&1; then
  step "1. Cluster / ArgoCD / cert-manager"

  if kubectl get nodes --no-headers 2>/dev/null | grep -q ' Ready '; then
    pass "K3s node Ready"
  else
    fail "no Ready node found"
  fi

  not_running=$(kubectl get pods -A --no-headers 2>/dev/null \
    | awk '$4 != "Running" && $4 != "Completed" {print}' | wc -l | tr -d ' ')
  [[ "$not_running" == "0" ]] && pass "all pods Running/Completed" \
    || fail "$not_running pod(s) not Running (kubectl get pods -A)"

  if command -v argocd >/dev/null 2>&1; then
    if argocd app list -o wide 2>/dev/null | awk 'NR>1 && ($2!="Synced" || $3!="Healthy")' | grep -q .; then
      fail "one or more ArgoCD apps not Synced/Healthy (argocd app list)"
    else
      pass "all ArgoCD apps Synced + Healthy"
    fi
  fi

  if kubectl get certificate -A --no-headers 2>/dev/null | grep -qi 'true'; then
    pass "at least one TLS Certificate is Ready"
  else
    printf '  \033[33m! no Ready Certificate found (check cert-manager)\033[0m\n'
  fi
else
  printf '\n(skipping kubectl/argocd checks)\n'
fi

# ── 2. Control-plane health ─────────────────────────────────────────────────
step "2. Control-plane health"
health=$(curl -sf "$API/health" || true)
echo "$health" | grep -q '"status":"ok"' && pass "GET /health = ok" \
  || fail "control-plane /health did not return ok (got: $health)"

# ── 3. Login enforcement ────────────────────────────────────────────────────
step "3. Login enforcement"
code=$(curl -s -o /dev/null -w '%{http_code}' "$API/instances")
[[ "$code" == "401" ]] && pass "unauthenticated request rejected (401)" \
  || fail "expected 401 for unauthenticated request, got $code (is CP_AUTH_ENABLED=true?)"

login=$(curl -s -c "$COOKIES" -X POST "$API/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$CONSOLE_USER\",\"password\":\"$CONSOLE_PASSWORD\"}")
echo "$login" | grep -q '"authenticated":true' && pass "login succeeded" \
  || fail "login failed (got: $login)"

code=$(curl -s -b "$COOKIES" -o /dev/null -w '%{http_code}' "$API/instances")
[[ "$code" == "200" ]] && pass "authenticated request accepted (200)" \
  || fail "expected 200 after login, got $code"

# ── 4. Node create → verify → delete round-trip ─────────────────────────────
step "4. Node create → verify → delete"
create=$(curl -s -b "$COOKIES" -X POST "$API/instances/create" \
  -H 'Content-Type: application/json' \
  -d "{
    \"name\": \"$NODE_NAME\",
    \"namespace\": \"$NODE_NAMESPACE\",
    \"preset\": \"internal-tools\",
    \"identifiers\": [{\"name\":\"apikey-auth\",\"type\":\"apikey\",
      \"config\":{\"headerName\":\"X-API-Key\",
      \"entries\":{\"verify-key\":{\"subject\":\"verifier\",\"roles\":[\"admin\"]}}}}],
    \"authorizers\": [{\"name\":\"rbac\",\"type\":\"rbac\",
      \"config\":{\"roles\":{\"admin\":{\"permissions\":[\"read\"]}}}}]
  }")
echo "$create" | grep -q '"status":"deploying"' && pass "create accepted" \
  || fail "create failed (got: $create)"

if [[ "${SKIP_KUBECTL:-0}" != "1" ]] && command -v kubectl >/dev/null 2>&1; then
  if kubectl rollout status "deployment/$NODE_NAME" -n "$NODE_NAMESPACE" --timeout=90s >/dev/null 2>&1; then
    pass "node deployment became Ready"
  else
    fail "node deployment did not become Ready in 90s"
  fi
fi

# Delete and confirm teardown.
code=$(curl -s -b "$COOKIES" -o /dev/null -w '%{http_code}' \
  -X DELETE "$API/instances/local/$NODE_NAME")
[[ "$code" == "204" ]] && pass "delete returned 204" \
  || fail "expected 204 on delete, got $code"

if [[ "${SKIP_KUBECTL:-0}" != "1" ]] && command -v kubectl >/dev/null 2>&1; then
  sleep 3
  if kubectl get deployment "$NODE_NAME" -n "$NODE_NAMESPACE" >/dev/null 2>&1; then
    fail "deployment still exists after delete — teardown incomplete"
  else
    pass "deployment removed from cluster"
  fi
fi

printf '\n\033[32mAll Phase C checks passed.\033[0m\n'
