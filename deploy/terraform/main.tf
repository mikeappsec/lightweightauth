# Copyright 2026 LightweightAuth Contributors
# SPDX-License-Identifier: Apache-2.0
#
# INSTALL-TF-1 (F5): Terraform / OpenTofu module that installs the
# LightweightAuth Helm chart with production-safe defaults.

resource "helm_release" "lwauth" {
  name             = var.release_name
  namespace        = var.namespace
  create_namespace = var.create_namespace

  repository = var.chart_repository
  chart      = "lightweightauth"
  version    = var.chart_version

  # Wait for the Deployment to become ready before marking the release
  # as successful. Catches config errors at apply-time rather than
  # leaving a half-deployed release.
  wait    = true
  timeout = 300

  # ---------------------------------------------------------------------------
  # Core values
  # ---------------------------------------------------------------------------

  set {
    name  = "replicaCount"
    value = var.replica_count
  }

  # Image overrides (air-gap support)
  dynamic "set" {
    for_each = var.image_repository != "" ? [var.image_repository] : []
    content {
      name  = "image.repository"
      value = set.value
    }
  }

  dynamic "set" {
    for_each = var.image_tag != "" ? [var.image_tag] : []
    content {
      name  = "image.tag"
      value = set.value
    }
  }

  # ---------------------------------------------------------------------------
  # Controller (CRD-mode)
  # ---------------------------------------------------------------------------

  set {
    name  = "controller.enabled"
    value = var.controller_enabled
  }

  dynamic "set" {
    for_each = var.controller_namespace != "" ? [var.controller_namespace] : []
    content {
      name  = "controller.watchNamespace"
      value = set.value
    }
  }

  # ---------------------------------------------------------------------------
  # NetworkPolicy
  # ---------------------------------------------------------------------------

  set {
    name  = "networkPolicy.enabled"
    value = var.network_policy_enabled
  }

  dynamic "set" {
    for_each = var.network_policy_namespace_selectors
    content {
      name  = "networkPolicy.allowedFrom.namespaceSelectors[${set.key}]"
      value = yamlencode(set.value)
    }
  }

  dynamic "set" {
    for_each = var.network_policy_pod_selectors
    content {
      name  = "networkPolicy.allowedFrom.podSelectors[${set.key}]"
      value = yamlencode(set.value)
    }
  }

  # ---------------------------------------------------------------------------
  # Observability
  # ---------------------------------------------------------------------------

  set {
    name  = "metrics.enabled"
    value = var.metrics_enabled
  }

  set {
    name  = "metrics.serviceMonitor"
    value = var.service_monitor_enabled
  }

  # ---------------------------------------------------------------------------
  # Availability
  # ---------------------------------------------------------------------------

  set {
    name  = "podDisruptionBudget.enabled"
    value = var.pdb_enabled
  }

  set {
    name  = "podDisruptionBudget.minAvailable"
    value = var.pdb_min_available
  }

  set {
    name  = "autoscaling.enabled"
    value = var.autoscaling_enabled
  }

  set {
    name  = "autoscaling.minReplicas"
    value = var.autoscaling_min_replicas
  }

  set {
    name  = "autoscaling.maxReplicas"
    value = var.autoscaling_max_replicas
  }

  set {
    name  = "autoscaling.targetCPUUtilizationPercentage"
    value = var.autoscaling_target_cpu
  }

  # ---------------------------------------------------------------------------
  # Escape hatch: raw YAML values merged last
  # ---------------------------------------------------------------------------

  values = var.values_override != "" ? [var.values_override] : []
}
