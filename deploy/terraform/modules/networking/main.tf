# Networking for a runnable kryptkeeper environment: one VPC, public subnets
# for the Hub instance, private subnets for the database, and the two
# security groups that gate traffic between them. No NAT gateway: the
# database's private subnets never need outbound internet, so one isn't
# provisioned (avoids the recurring NAT cost/complexity for a self-hosted
# deploy target).

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  az_count = min(length(var.public_subnet_cidrs), length(var.private_subnet_cidrs), length(data.aws_availability_zones.available.names))
  azs      = slice(data.aws_availability_zones.available.names, 0, local.az_count)
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpc"
  })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-igw"
  })
}

resource "aws_subnet" "public" {
  count                   = local.az_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-public-${local.azs[count.index]}"
  })
}

resource "aws_subnet" "private" {
  count             = local.az_count
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-private-${local.azs[count.index]}"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-public-rt"
  })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-private-rt"
  })
}

resource "aws_route_table_association" "private" {
  count          = local.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# App security group: the Hub instance. Ingress is operator-specified
# (var.allowed_app_ingress_cidr_blocks has no default — see variables.tf).
# Egress is left open: the Hub needs to reach the database, pull its own
# container image, and call out to notification channels (SMTP/Slack/
# PagerDuty) and cloud KMS, none of which are known ahead of time.
resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-app"
  description = "kryptkeeper Hub instance"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-app"
  })
}

resource "aws_vpc_security_group_ingress_rule" "app_from_operator" {
  count             = length(var.allowed_app_ingress_cidr_blocks)
  security_group_id = aws_security_group.app.id
  description       = "kryptkeeper Hub API + dashboard"
  cidr_ipv4         = var.allowed_app_ingress_cidr_blocks[count.index]
  ip_protocol       = "tcp"
  from_port         = var.app_port
  to_port           = var.app_port
}

resource "aws_vpc_security_group_egress_rule" "app_all" {
  security_group_id = aws_security_group.app.id
  description       = "unrestricted egress (DB, image registry, notification channels, cloud KMS)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# DB security group: only the app security group may reach the database
# port. No egress rules are attached here — RDS itself never needs to
# originate outbound connections for this deployment.
resource "aws_security_group" "db" {
  name        = "${var.name_prefix}-db"
  description = "kryptkeeper database"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-db"
  })
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "database access from the Hub instance only"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
}
