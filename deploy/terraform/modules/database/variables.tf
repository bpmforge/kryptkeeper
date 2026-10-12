variable "name_prefix" {
  description = "Prefix applied to all resource names/tags created by this module."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet IDs the DB subnet group spans (2+ AZs)."
  type        = list(string)
}

variable "vpc_security_group_ids" {
  description = "Security groups attached to the database instance."
  type        = list(string)
}

variable "engine_version" {
  description = "PostgreSQL engine version."
  type        = string
  default     = "16"
}

variable "instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage" {
  description = "Allocated storage in GiB."
  type        = number
  default     = 20
}

variable "db_name" {
  description = "Database name created inside the instance."
  type        = string
  default     = "kryptkeeper"
}

variable "username" {
  description = "Master username. The master password is never set by this module — manage_master_user_password delegates it to AWS Secrets Manager, so it never enters Terraform state."
  type        = string
  default     = "kryptkeeper"
}

variable "multi_az" {
  description = "Whether to deploy a standby replica in a second AZ."
  type        = bool
  default     = false
}

variable "backup_retention_period" {
  description = "Automated backup retention, in days."
  type        = number
  default     = 7
}

variable "deletion_protection" {
  description = "Refuse `terraform destroy`/console deletion of the instance until this is turned off. Defaults on: disk loss here is permanent CA data loss (D-092)."
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  description = "Skip the final snapshot on deletion. Defaults off, matching deletion_protection's default posture."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags merged onto every resource this module creates."
  type        = map(string)
  default     = {}
}
