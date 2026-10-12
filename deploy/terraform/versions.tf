terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# State holds resource IDs/ARNs and is sensitive. Use an encrypted remote
# backend for anything beyond a first try (IAC-002). Uncomment and fill in;
# the bucket needs versioning, SSE-KMS and a public-access block, and the
# lock table needs a string hash key named LockID.
#
# terraform {
#   backend "s3" {
#     bucket         = "my-org-tfstate"
#     key            = "kryptkeeper/hub/terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     kms_key_id     = "alias/my-org-tfstate"
#     dynamodb_table = "my-org-tfstate-lock"
#   }
# }
