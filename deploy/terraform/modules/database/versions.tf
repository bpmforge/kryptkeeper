# Mirrors the root constraints so tflint's terraform_required_version and
# terraform_required_providers rules hold for each module on its own.
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
