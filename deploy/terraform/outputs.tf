# Copyright 2026 LightweightAuth Contributors
# SPDX-License-Identifier: Apache-2.0

output "namespace" {
  description = "Namespace where LightweightAuth is installed."
  value       = helm_release.lwauth.namespace
}

output "release_name" {
  description = "Helm release name."
  value       = helm_release.lwauth.name
}

output "service_name" {
  description = "ClusterIP Service name for lwauth."
  value       = var.release_name
}

output "grpc_port" {
  description = "gRPC port for the ext_authz endpoint."
  value       = 9001
}

output "http_port" {
  description = "HTTP port for health checks and metrics."
  value       = 8080
}

output "chart_version" {
  description = "Deployed Helm chart version."
  value       = helm_release.lwauth.version
}
