variable "name_prefix" {
  description = "Prefix applied to all resource names/tags created by this module."
  type        = string
}

variable "region" {
  description = "AWS region (passed through to the instance's AWS CLI calls in user_data)."
  type        = string
}

variable "subnet_id" {
  description = "Public subnet the Hub instance is launched into."
  type        = string
}

variable "availability_zone" {
  description = "AZ of var.subnet_id. Passed explicitly (not read off the instance) so the data volume can be created before the instance and its ID baked into user_data."
  type        = string
}

variable "security_group_ids" {
  description = "Security groups attached to the instance."
  type        = list(string)
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.small"
}

variable "root_volume_size_gb" {
  description = "Root (OS) volume size in GiB."
  type        = number
  default     = 20
}

variable "data_volume_size_gb" {
  description = "Size of the dedicated, encrypted EBS volume mounted at /var/kryptkeeper (keystore + local data). Kept separate from the root volume so it survives an instance replacement (D-092: disk loss must not mean permanent CA loss)."
  type        = number
  default     = 20
}

variable "image_repository" {
  description = "kryptkeeper Hub container image repository."
  type        = string
  default     = "ghcr.io/bpmforge/kryptkeeper"
}

variable "image_digest" {
  description = "Immutable digest of the kryptkeeper Hub image to run, e.g. sha256:<64 hex>. Required, no default: mutable tags such as latest are refused (IAC-004). Verify the signature with cosign before applying; see packaging/SIGNING.md."
  type        = string

  validation {
    condition     = can(regex("^sha256:[a-f0-9]{64}$", var.image_digest))
    error_message = "image_digest must be a full image digest of the form sha256:<64 lowercase hex characters>. Tags (including latest) are not accepted."
  }
}

variable "app_port" {
  description = "TCP port the Hub listens on (published 1:1 from the container)."
  type        = number
  default     = 8080
}

variable "tls_extra_sans" {
  description = "Additional DNS names or IPs to put in the Hub's self-issued TLS listener certificate (the Elastic IP, localhost and 127.0.0.1 are always included). Add the DNS name clients dial."
  type        = list(string)
  default     = []
}

variable "tls_cert_secret_arn" {
  description = "Optional Secrets Manager ARN of an operator-supplied TLS certificate: a JSON secret with keys certificate_pem (full chain) and private_key_pem. When set, the Hub serves that pair instead of self-issuing. Create it outside Terraform."
  type        = string
  default     = ""
}

variable "db_secret_arn" {
  description = "Secrets Manager ARN of the RDS-managed master password (database module's master_user_secret_arn output). The instance role is granted read-only access to this ARN only."
  type        = string
}

variable "db_endpoint" {
  description = "Database host:port."
  type        = string
}

variable "db_name" {
  description = "Database name."
  type        = string
}

variable "db_username" {
  description = "Database master username."
  type        = string
}

variable "tags" {
  description = "Tags merged onto every resource this module creates."
  type        = map(string)
  default     = {}
}
