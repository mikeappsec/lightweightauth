# Copyright 2026 LightweightAuth Contributors
# SPDX-License-Identifier: Apache-2.0

# ---------------------------------------------------------------------------
# Required
# ---------------------------------------------------------------------------

variable "chart_version" {
  description = "LightweightAuth Helm chart version (semver, e.g. '1.2.0')."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+", var.chart_version))
    error_message = "chart_version must be a valid semver string (e.g. '1.2.0')."
  }
}

# ---------------------------------------------------------------------------
# Optional — general
# ---------------------------------------------------------------------------

variable "namespace" {
  description = "Kubernetes namespace to deploy LightweightAuth into."
  type        = string
  default     = "lwauth"
}

variable "create_namespace" {
  description = "Create the namespace if it does not already exist."
  type        = bool
  default     = true
}

variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "lwauth"
}

variable "chart_repository" {
  description = "OCI registry URL for the LightweightAuth Helm chart."
  type        = string
  default     = "oci://ghcr.io/mikeappsec/charts"
}

variable "replica_count" {
  description = "Number of lwauth pod replicas."
  type        = number
  default     = 2
}

# ---------------------------------------------------------------------------
# Optional — image overrides (air-gap)
# ---------------------------------------------------------------------------

variable "image_repository" {
  description = "Override the container image repository (for air-gapped registries)."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Override the container image tag."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Optional — controller (CRD-mode)
# ---------------------------------------------------------------------------

variable "controller_enabled" {
  description = "Enable the CRD-mode controller (watches AuthConfig CRs)."
  type        = bool
  default     = false
}

variable "controller_namespace" {
  description = "Namespace the controller watches for AuthConfig CRs. Empty = release namespace."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Optional — NetworkPolicy
# ---------------------------------------------------------------------------

variable "network_policy_enabled" {
  description = "Enable the default-deny NetworkPolicy."
  type        = bool
  default     = true
}

variable "network_policy_namespace_selectors" {
  description = "Namespace selectors to allow ingress from (list of label maps)."
  type        = list(map(string))
  default     = []
}

variable "network_policy_pod_selectors" {
  description = "Pod selectors to allow ingress from (list of label maps)."
  type        = list(map(string))
  default     = []
}

# ---------------------------------------------------------------------------
# Optional — observability
# ---------------------------------------------------------------------------

variable "service_monitor_enabled" {
  description = "Create a Prometheus Operator ServiceMonitor."
  type        = bool
  default     = false
}

variable "metrics_enabled" {
  description = "Enable the /metrics endpoint on the lwauth pods."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Optional — availability
# ---------------------------------------------------------------------------

variable "pdb_enabled" {
  description = "Enable PodDisruptionBudget."
  type        = bool
  default     = true
}

variable "pdb_min_available" {
  description = "PDB minAvailable value."
  type        = number
  default     = 1
}

variable "autoscaling_enabled" {
  description = "Enable HorizontalPodAutoscaler."
  type        = bool
  default     = false
}

variable "autoscaling_min_replicas" {
  description = "HPA minimum replicas."
  type        = number
  default     = 2
}

variable "autoscaling_max_replicas" {
  description = "HPA maximum replicas."
  type        = number
  default     = 10
}

variable "autoscaling_target_cpu" {
  description = "HPA target CPU utilization percentage."
  type        = number
  default     = 70
}

# ---------------------------------------------------------------------------
# Optional — escape hatch
# ---------------------------------------------------------------------------

variable "values_override" {
  description = "Raw YAML string merged last into Helm values (escape hatch for advanced config)."
  type        = string
  default     = ""
}
