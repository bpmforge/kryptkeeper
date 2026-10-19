terraform {
  required_providers {
    kryptkeeper = {
      source = "registry.terraform.io/kryptkeeper/kryptkeeper"
    }
  }
}

variable "kryptkeeper_hub_url" {
  type = string
}

variable "kryptkeeper_token" {
  type      = string
  sensitive = true
}

provider "kryptkeeper" {
  hub_url = var.kryptkeeper_hub_url
  token   = var.kryptkeeper_token
}

resource "kryptkeeper_ca" "root" {
  name          = "corp-root"
  common_name   = "Corp Root CA"
  algorithm     = "ECDSA-P384"
  validity_days = 3650
}

output "ca_id" {
  value = kryptkeeper_ca.root.id
}
