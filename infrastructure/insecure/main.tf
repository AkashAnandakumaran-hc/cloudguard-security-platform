############################################
# CloudGuard - INSECURE baseline
# Intentional misconfigurations for scan demo.
# This code is never applied to a real AWS
# account - it is analyzed statically only.
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

# SEC-001: Public storage prohibited (VIOLATION)
resource "aws_s3_bucket" "data" {
  bucket = "cloudguard-demo-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# SEC-003: Encryption required (VIOLATION - no encryption block)
# (intentionally omitted server-side encryption configuration)

# SEC-004: Logging must be enabled (VIOLATION - no logging resource / no access logging)

# SEC-002: Administrative ports cannot be internet exposed (VIOLATION)
resource "aws_security_group" "app" {
  name        = "cloudguard-app-sg"
  description = "Application security group"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SEC-005: Wildcard IAM privileges prohibited (VIOLATION)
resource "aws_iam_policy" "app_policy" {
  name = "cloudguard-app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Unencrypted storage volume (VIOLATION)
resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

# Missing resource tags (VIOLATION - no tags block anywhere above)
