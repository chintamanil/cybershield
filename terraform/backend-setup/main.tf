# Terraform Backend Setup for CyberShield
# Creates S3 buckets and DynamoDB tables for remote state management

terraform {
  required_version = ">= 1.5, < 1.13"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project   = "cybershield"
      Purpose   = "terraform-backend"
      ManagedBy = "terraform"
    }
  }
}

# Random suffix for unique bucket names
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# S3 Bucket for Development State
resource "aws_s3_bucket" "terraform_state_dev" {
  bucket        = "cybershield-terraform-state-dev-${random_string.bucket_suffix.result}"
  force_destroy = false
  
  tags = {
    Name        = "cybershield-terraform-state-dev"
    Environment = "dev"
    Purpose     = "terraform-backend"
  }
}

# S3 Bucket for Staging State
resource "aws_s3_bucket" "terraform_state_staging" {
  bucket        = "cybershield-terraform-state-staging-${random_string.bucket_suffix.result}"
  force_destroy = false
  
  tags = {
    Name        = "cybershield-terraform-state-staging"
    Environment = "staging"
    Purpose     = "terraform-backend"
  }
}

# S3 Bucket for Production State
resource "aws_s3_bucket" "terraform_state_prod" {
  bucket        = "cybershield-terraform-state-prod-${random_string.bucket_suffix.result}"
  force_destroy = false
  
  tags = {
    Name        = "cybershield-terraform-state-prod"
    Environment = "prod"
    Purpose     = "terraform-backend"
  }
}

# Enable versioning for all state buckets
resource "aws_s3_bucket_versioning" "terraform_state_dev" {
  bucket = aws_s3_bucket.terraform_state_dev.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state_staging" {
  bucket = aws_s3_bucket.terraform_state_staging.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state_prod" {
  bucket = aws_s3_bucket.terraform_state_prod.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for all state buckets
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_dev" {
  bucket = aws_s3_bucket.terraform_state_dev.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_staging" {
  bucket = aws_s3_bucket.terraform_state_staging.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_prod" {
  bucket = aws_s3_bucket.terraform_state_prod.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access for all state buckets
resource "aws_s3_bucket_public_access_block" "terraform_state_dev" {
  bucket = aws_s3_bucket.terraform_state_dev.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "terraform_state_staging" {
  bucket = aws_s3_bucket.terraform_state_staging.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "terraform_state_prod" {
  bucket = aws_s3_bucket.terraform_state_prod.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle configuration for state buckets
resource "aws_s3_bucket_lifecycle_configuration" "terraform_state_dev" {
  bucket = aws_s3_bucket.terraform_state_dev.id
  
  rule {
    id     = "state_lifecycle"
    status = "Enabled"
    
    filter {
      prefix = ""
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90  # Keep old versions for 90 days
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "terraform_state_staging" {
  bucket = aws_s3_bucket.terraform_state_staging.id
  
  rule {
    id     = "state_lifecycle"
    status = "Enabled"
    
    filter {
      prefix = ""
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "terraform_state_prod" {
  bucket = aws_s3_bucket.terraform_state_prod.id
  
  rule {
    id     = "state_lifecycle"
    status = "Enabled"
    
    filter {
      prefix = ""
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 365  # Keep production versions longer
    }
  }
}

# DynamoDB Tables for State Locking
resource "aws_dynamodb_table" "terraform_locks_dev" {
  name           = "cybershield-terraform-locks-dev"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  tags = {
    Name        = "cybershield-terraform-locks-dev"
    Environment = "dev"
    Purpose     = "terraform-state-locking"
  }
}

resource "aws_dynamodb_table" "terraform_locks_staging" {
  name           = "cybershield-terraform-locks-staging"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  tags = {
    Name        = "cybershield-terraform-locks-staging"
    Environment = "staging"
    Purpose     = "terraform-state-locking"
  }
}

resource "aws_dynamodb_table" "terraform_locks_prod" {
  name           = "cybershield-terraform-locks-prod"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  tags = {
    Name        = "cybershield-terraform-locks-prod"
    Environment = "prod"
    Purpose     = "terraform-state-locking"
  }
}