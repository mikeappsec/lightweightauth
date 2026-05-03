# LightweightAuth Terraform Module

Terraform / OpenTofu module that installs the LightweightAuth Helm chart
from the OCI registry, with production-safe defaults for networking,
monitoring, and scaling.

## Usage

```hcl
module "lwauth" {
  source = "github.com/mikeappsec/lightweightauth//deploy/terraform"

  namespace        = "lwauth"
  chart_version    = "1.2.0"
  replica_count    = 3

  # CRD-mode (recommended for production)
  controller_enabled   = true
  controller_namespace = "lwauth"

  # NetworkPolicy: allow traffic from the istio-system namespace
  network_policy_namespace_selectors = [
    { "kubernetes.io/metadata.name" = "istio-system" }
  ]

  # ServiceMonitor for Prometheus Operator
  service_monitor_enabled = true
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform / opentofu | >= 1.5 |
| helm provider | >= 2.12 |
| kubernetes provider | >= 2.25 |

## Inputs

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `namespace` | Kubernetes namespace to deploy into | `string` | `"lwauth"` |
| `create_namespace` | Create the namespace if it doesn't exist | `bool` | `true` |
| `chart_version` | Helm chart version (from OCI registry) | `string` | n/a (required) |
| `chart_repository` | OCI registry URL for the Helm chart | `string` | `"oci://ghcr.io/mikeappsec/charts"` |
| `release_name` | Helm release name | `string` | `"lwauth"` |
| `replica_count` | Number of lwauth replicas | `number` | `2` |
| `image_repository` | Override image repository (for air-gap) | `string` | `""` |
| `image_tag` | Override image tag | `string` | `""` |
| `controller_enabled` | Enable CRD-mode controller | `bool` | `false` |
| `controller_namespace` | Namespace for CRD-mode watch | `string` | `""` |
| `network_policy_enabled` | Enable NetworkPolicy | `bool` | `true` |
| `network_policy_namespace_selectors` | Namespace selectors for ingress | `list(map(string))` | `[]` |
| `network_policy_pod_selectors` | Pod selectors for ingress | `list(map(string))` | `[]` |
| `service_monitor_enabled` | Create a ServiceMonitor for Prometheus Operator | `bool` | `false` |
| `pdb_enabled` | Enable PodDisruptionBudget | `bool` | `true` |
| `pdb_min_available` | PDB minAvailable | `number` | `1` |
| `autoscaling_enabled` | Enable HPA | `bool` | `false` |
| `autoscaling_min_replicas` | HPA min replicas | `number` | `2` |
| `autoscaling_max_replicas` | HPA max replicas | `number` | `10` |
| `values_override` | Raw YAML string merged last into Helm values | `string` | `""` |

## Outputs

| Name | Description |
|------|-------------|
| `namespace` | Namespace where lwauth is installed |
| `release_name` | Helm release name |
| `service_name` | ClusterIP Service name for lwauth |
| `grpc_port` | gRPC port (ext_authz endpoint) |
