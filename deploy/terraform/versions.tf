# Copyright 2026 LightweightAuth Contributors
# SPDX-License-Identifier: Apache-2.0

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.0, < 4.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0, < 4.0.0"
    }
  }
}
