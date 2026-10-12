output "vpc_id" {
  description = "ID of the created VPC."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets (Hub instance)."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets (database)."
  value       = aws_subnet.private[*].id
}

output "availability_zones" {
  description = "Availability zones actually used, one per subnet pair."
  value       = local.azs
}

output "app_security_group_id" {
  description = "Security group attached to the Hub instance."
  value       = aws_security_group.app.id
}

output "db_security_group_id" {
  description = "Security group attached to the database."
  value       = aws_security_group.db.id
}
