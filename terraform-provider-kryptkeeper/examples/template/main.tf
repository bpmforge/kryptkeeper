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

resource "kryptkeeper_template" "web" {
  name               = "web-server"
  display_name       = "Web server"
  validity_period    = "P90D"
  key_usage          = ["digitalSignature"]
  extended_key_usage = ["serverAuth"]
  allowed_algorithms = ["ECDSA-P256"]
}

output "template_id" {
  value = kryptkeeper_template.web.id
}
