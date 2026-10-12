output "instance_id" {
  description = "EC2 instance ID running the Hub."
  value       = aws_instance.this.id
}

output "public_ip" {
  description = "Elastic IP the Hub is reachable on."
  value       = aws_eip.this.public_ip
}

output "private_ip" {
  description = "Instance private IP (VPC-internal)."
  value       = aws_instance.this.private_ip
}

output "app_secret_arn" {
  description = "Secrets Manager ARN of the (initially empty) secret the operator must populate with app_bootstrap_token and keystore_passphrase."
  value       = aws_secretsmanager_secret.app_secrets.arn
}
