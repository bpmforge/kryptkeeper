variable "region" {
  description = "AWS region to provision into."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name/tag this module creates."
  type        = string
  default     = "kryptkeeper"
}

# --- Networking -------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for the public subnets (Hub instance), one per AZ."
  type        = list(string)
  default     = ["10.20.0.0/24", "10.20.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for the private subnets (database), one per AZ."
  type        = list(string)
  default     = ["10.20.10.0/24", "10.20.11.0/24"]
}

variable "app_port" {
  description = "TCP port the kryptkeeper Hub listens on."
  type        = number
  default     = 8080
}

variable "allowed_app_ingress_cidr_blocks" {
  description = <<-EOT
    CIDR blocks allowed to reach the Hub on var.app_port. Required, no
    default: this is a PKI product and "open to the internet" must be a
    conscious operator choice.
  EOT
  type        = list(string)
}

# --- Compute -----------------------------------------------------------------

variable "instance_type" {
  description = "EC2 instance type for the Hub."
  type        = string
  default     = "t3.small"
}

variable "root_volume_size_gb" {
  description = "Root (OS) volume size in GiB."
  type        = number
  default     = 20
}

variable "data_volume_size_gb" {
  description = "Size of the dedicated /var/kryptkeeper volume (keystore + local data)."
  type        = number
  default     = 20
}

variable "image_repository" {
  description = "kryptkeeper Hub container image repository."
  type        = string
  default     = "ghcr.io/bpmforge/kryptkeeper"
}

variable "image_digest" {
  description = "Immutable digest of the kryptkeeper Hub image, e.g. sha256:<64 hex>. Required: mutable tags such as latest are refused (IAC-004). Verify the signature with cosign first; see packaging/SIGNING.md."
  type        = string

  validation {
    condition     = can(regex("^sha256:[a-f0-9]{64}$", var.image_digest))
    error_message = "image_digest must be a full image digest of the form sha256:<64 lowercase hex characters>. Tags (including latest) are not accepted."
  }
}

variable "tls_extra_sans" {
  description = "Additional DNS names or IPs for the Hub's self-issued TLS listener certificate (the Elastic IP, localhost and 127.0.0.1 are always included). Add the DNS name clients dial."
  type        = list(string)
  default     = []
}

variable "tls_cert_secret_arn" {
  description = "Optional Secrets Manager ARN of an operator-supplied TLS certificate (JSON keys certificate_pem, private_key_pem), created outside Terraform. When set the Hub serves it instead of self-issuing."
  type        = string
  default     = ""
}

# --- Database ------------------------------------------------------------

variable "db_engine_version" {
  description = "PostgreSQL engine version."
  type        = string
  default     = "16"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GiB."
  type        = number
  default     = 20
}

variable "db_name" {
  description = "Database name."
  type        = string
  default     = "kryptkeeper"
}

variable "db_username" {
  description = "Database master username. The master password is never set here — see database module's manage_master_user_password."
  type        = string
  default     = "kryptkeeper"
}

variable "db_multi_az" {
  description = "Whether to deploy a standby database replica in a second AZ."
  type        = bool
  default     = false
}

variable "db_backup_retention_period" {
  description = "Automated backup retention, in days."
  type        = number
  default     = 7
}

variable "db_deletion_protection" {
  description = "Refuse destruction of the database until this is turned off. Defaults on (D-092: disk loss here is permanent CA data loss)."
  type        = bool
  default     = true
}

variable "db_skip_final_snapshot" {
  description = "Skip the final snapshot on database deletion."
  type        = bool
  default     = false
}

# --- Tagging -----------------------------------------------------------------

variable "tags" {
  description = "Tags merged onto every resource this module creates."
  type        = map(string)
  default     = {}
}
