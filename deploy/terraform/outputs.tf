output "app_url" {
  description = "URL the kryptkeeper Hub dashboard/API is reachable at (TLS; self-issued unless tls_cert_secret_arn is set, so clients must trust the Hub CA)."
  value       = "https://${module.compute.public_ip}:${var.app_port}"
}

output "vpc_id" {
  description = "ID of the created VPC."
  value       = module.networking.vpc_id
}

output "instance_id" {
  description = "EC2 instance ID running the Hub."
  value       = module.compute.instance_id
}

output "db_endpoint" {
  description = "Database host:port."
  value       = module.database.endpoint
}

output "db_master_user_secret_arn" {
  description = "Secrets Manager ARN holding the database master password."
  value       = module.database.master_user_secret_arn
}

output "app_secret_arn" {
  description = "Secrets Manager ARN of the secret you must populate out of band with app_bootstrap_token and keystore_passphrase (Terraform never holds the values)."
  value       = module.compute.app_secret_arn
}
