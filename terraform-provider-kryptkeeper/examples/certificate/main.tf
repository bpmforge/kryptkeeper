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

# The provider never generates keys: bring your own CSR.
resource "kryptkeeper_certificate" "web" {
  ca_id       = data.kryptkeeper_ca.root.id
  template_id = data.kryptkeeper_template.web.id
  csr_pem     = file("${path.module}/server.csr")
}

data "kryptkeeper_ca" "root" {
  name = "corp-root"
}

data "kryptkeeper_template" "web" {
  name = "web-server"
}

output "certificate_pem" {
  value = kryptkeeper_certificate.web.certificate_pem
}
