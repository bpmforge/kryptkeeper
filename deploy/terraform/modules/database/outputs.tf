output "address" {
  description = "Database host (no port)."
  value       = aws_db_instance.this.address
}

output "endpoint" {
  description = "Database host:port."
  value       = aws_db_instance.this.endpoint
}

output "port" {
  description = "Database port."
  value       = aws_db_instance.this.port
}

output "db_name" {
  description = "Database name."
  value       = aws_db_instance.this.db_name
}

output "username" {
  description = "Master username."
  value       = aws_db_instance.this.username
}

output "master_user_secret_arn" {
  description = "Secrets Manager ARN holding the AWS-managed master password. Nothing in this module ever sees the password value itself."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}
