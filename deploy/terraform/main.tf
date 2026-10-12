# Stands up a runnable kryptkeeper environment on AWS: networking (VPC,
# public+private subnets, security groups), a database (RDS Postgres), and
# compute (one EC2 instance running the Hub container). See README.md for
# how this differs from ../../terraform-provider-kryptkeeper.

module "networking" {
  source = "./modules/networking"

  name_prefix                     = var.name_prefix
  vpc_cidr                        = var.vpc_cidr
  public_subnet_cidrs             = var.public_subnet_cidrs
  private_subnet_cidrs            = var.private_subnet_cidrs
  app_port                        = var.app_port
  allowed_app_ingress_cidr_blocks = var.allowed_app_ingress_cidr_blocks
  tags                            = var.tags
}

module "database" {
  source = "./modules/database"

  name_prefix             = var.name_prefix
  subnet_ids              = module.networking.private_subnet_ids
  vpc_security_group_ids  = [module.networking.db_security_group_id]
  engine_version          = var.db_engine_version
  instance_class          = var.db_instance_class
  allocated_storage       = var.db_allocated_storage
  db_name                 = var.db_name
  username                = var.db_username
  multi_az                = var.db_multi_az
  backup_retention_period = var.db_backup_retention_period
  deletion_protection     = var.db_deletion_protection
  skip_final_snapshot     = var.db_skip_final_snapshot
  tags                    = var.tags
}

module "compute" {
  source = "./modules/compute"

  name_prefix         = var.name_prefix
  region              = var.region
  subnet_id           = module.networking.public_subnet_ids[0]
  availability_zone   = module.networking.availability_zones[0]
  security_group_ids  = [module.networking.app_security_group_id]
  instance_type       = var.instance_type
  root_volume_size_gb = var.root_volume_size_gb
  data_volume_size_gb = var.data_volume_size_gb
  image_repository    = var.image_repository
  image_digest        = var.image_digest
  app_port            = var.app_port
  tls_extra_sans      = var.tls_extra_sans
  tls_cert_secret_arn = var.tls_cert_secret_arn
  db_secret_arn       = module.database.master_user_secret_arn
  db_endpoint         = module.database.endpoint
  db_name             = module.database.db_name
  db_username         = module.database.username
  tags                = var.tags
}
