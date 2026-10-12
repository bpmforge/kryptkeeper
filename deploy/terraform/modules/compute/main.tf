# The Hub itself: one EC2 instance running the kryptkeeper container image
# over Docker, fronted by an Elastic IP. No SSH: the instance role only
# grants SSM (Session Manager), so there is no inbound port 22 to manage or
# leak a key for.

data "aws_ami" "this" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name_prefix}-hub"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "read_db_secret" {
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.db_secret_arn]
  }
}

resource "aws_iam_role_policy" "read_db_secret" {
  name   = "${var.name_prefix}-read-db-secret"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.read_db_secret.json
}

# app_bootstrap_token and keystore_passphrase never enter user_data (EC2 user
# data is readable in plaintext by any IAM principal with
# ec2:DescribeInstanceAttribute on the instance) and, deliberately, never
# enter Terraform state either (IAC-002): Terraform creates only this empty
# secret container. The operator writes the value out of band with
# `aws secretsmanager put-secret-value` (see deploy/terraform/README.md) and
# the instance reads it at boot via a role scoped to this one secret ARN.
# There is intentionally no aws_secretsmanager_secret_version here: any
# value Terraform writes is stored in plaintext in state.
resource "aws_secretsmanager_secret" "app_secrets" {
  name        = "${var.name_prefix}-hub-app-secrets"
  description = "kryptkeeper Hub bootstrap token + keystore passphrase (JSON keys app_bootstrap_token, keystore_passphrase). Value is written out of band, never by Terraform."

  tags = var.tags
}

data "aws_iam_policy_document" "read_app_secrets" {
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.app_secrets.arn]
  }
}

resource "aws_iam_role_policy" "read_app_secrets" {
  name   = "${var.name_prefix}-read-app-secrets"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.read_app_secrets.json
}

data "aws_iam_policy_document" "read_tls_secret" {
  count = var.tls_cert_secret_arn == "" ? 0 : 1

  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.tls_cert_secret_arn]
  }
}

resource "aws_iam_role_policy" "read_tls_secret" {
  count = var.tls_cert_secret_arn == "" ? 0 : 1

  name   = "${var.name_prefix}-read-tls-secret"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.read_tls_secret[0].json
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name_prefix}-hub"
  role = aws_iam_role.this.name
}

# Created ahead of the instance (fixed AZ from var.availability_zone, not
# read off aws_instance.this) so its volume ID can be baked into user_data
# and looked up by /dev/disk/by-id/ instead of guessing a kernel device
# name — Nitro instances (every current-generation type, including the
# t3 default) expose EBS volumes as NVMe block devices, not /dev/xvdf.
resource "aws_ebs_volume" "data" {
  availability_zone = var.availability_zone
  size              = var.data_volume_size_gb
  type              = "gp3"
  encrypted         = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-hub-data"
  })
}

resource "aws_instance" "this" {
  ami                    = data.aws_ami.this.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = var.security_group_ids
  iam_instance_profile   = aws_iam_instance_profile.this.name

  # All reachable through aws_iam_role.this only by reference, not
  # guaranteed to exist before boot — user_data needs the SSM agent
  # registered and the secret read permissions live the moment it runs.
  # The app secret's value is written out of band, so user_data polls for it
  # (see the retry loop there) rather than Terraform ordering it.
  depends_on = [
    aws_iam_role_policy.read_db_secret,
    aws_iam_role_policy.read_app_secrets,
    aws_iam_role_policy.read_tls_secret,
    aws_iam_role_policy_attachment.ssm,
  ]

  associate_public_ip_address = true

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = var.root_volume_size_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/templates/user_data.sh.tpl", {
    region           = var.region
    db_secret_arn    = var.db_secret_arn
    db_endpoint      = var.db_endpoint
    db_name          = var.db_name
    db_username      = var.db_username
    app_secret_arn   = aws_secretsmanager_secret.app_secrets.arn
    image_repository = var.image_repository
    image_digest     = var.image_digest
    data_volume_id   = replace(aws_ebs_volume.data.id, "vol-", "vol")
    app_port         = var.app_port
    tls_sans         = join(",", concat([aws_eip.this.public_ip], var.tls_extra_sans, ["localhost", "127.0.0.1"]))
    base_url         = "https://${aws_eip.this.public_ip}:${var.app_port}"
    tls_secret_arn   = var.tls_cert_secret_arn
  })

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-hub"
  })
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.this.id
}

# Allocated before the instance (and associated after it) so the address is
# known when user_data is rendered: it becomes a SAN of the Hub's TLS
# listener certificate and the base URL clients are told to use (IAC-001).
resource "aws_eip" "this" {
  domain = "vpc"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-hub"
  })
}

resource "aws_eip_association" "this" {
  allocation_id = aws_eip.this.id
  instance_id   = aws_instance.this.id
}
