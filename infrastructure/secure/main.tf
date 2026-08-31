############################################
# CloudGuard - SECURE (remediated) baseline
# Same environment, controls SEC-001..SEC-005
# applied. Analyzed statically only.
############################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

# SEC-004: dedicated logging bucket, receives access logs
resource "aws_s3_bucket" "logs" {
  bucket = "cloudguard-demo-logs"

  tags = {
    Environment = "demo"
    Owner       = "platform-security"
    Project     = "cloudguard"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# SEC-001: private storage, all public access blocked
resource "aws_s3_bucket" "data" {
  bucket = "cloudguard-demo-data"

  tags = {
    Environment = "demo"
    Owner       = "platform-security"
    Project     = "cloudguard"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}

# SEC-003: encryption required
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# SEC-004: access logging enabled, points at logs bucket
resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "expire-noncurrent"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# SEC-002: no administrative ports open to the internet
resource "aws_security_group" "app" {
  name        = "cloudguard-app-sg"
  description = "Application security group - restricted ingress"

  ingress {
    description = "HTTPS from corporate CIDR only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Restricted egress to VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = {
    Environment = "demo"
    Owner       = "platform-security"
    Project     = "cloudguard"
  }
}

# SEC-005: least-privilege IAM policy, scoped resource + actions
resource "aws_iam_policy" "app_policy" {
  name = "cloudguard-app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadWriteScopedDataBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })
}

# Encrypted storage volume
resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true

  tags = {
    Environment = "demo"
    Owner       = "platform-security"
    Project     = "cloudguard"
  }
}
