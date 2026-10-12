variable "name_prefix" {
  description = "Prefix applied to all resource names/tags created by this module."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for the public subnets (one per AZ) that hold the Hub instance."
  type        = list(string)
  default     = ["10.20.0.0/24", "10.20.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for the private subnets (one per AZ) that hold the database."
  type        = list(string)
  default     = ["10.20.10.0/24", "10.20.11.0/24"]
}

variable "app_port" {
  description = "TCP port the kryptkeeper Hub listens on."
  type        = number
  default     = 8080
}

variable "db_port" {
  description = "TCP port the database listens on."
  type        = number
  default     = 5432
}

variable "allowed_app_ingress_cidr_blocks" {
  description = <<-EOT
    CIDR blocks allowed to reach the Hub on var.app_port. No default on purpose:
    this is a PKI product and "open to the internet" must be a conscious choice,
    not a fallback.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.allowed_app_ingress_cidr_blocks) > 0
    error_message = "allowed_app_ingress_cidr_blocks must name at least one CIDR block; there is no open-by-default fallback."
  }
}

variable "tags" {
  description = "Tags merged onto every resource this module creates."
  type        = map(string)
  default     = {}
}
