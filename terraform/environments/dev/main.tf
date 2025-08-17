# Development Environment Configuration for CyberShield
# Optimized for cost and development workflows

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

  # Backend configuration for dev environment
  backend "s3" {
    bucket         = "cybershield-terraform-state-dev-nazqkk52"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "cybershield-terraform-locks-dev"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "cybershield"
      Environment = "dev"
      ManagedBy   = "terraform"
      Owner       = "cybershield-dev-team"
    }
  }
}

# Random string for unique resource naming
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Call the main CyberShield module
module "cybershield" {
  source = "../.."
  
  # Basic Configuration
  project_name = "cybershield"
  environment  = "dev"
  aws_region   = var.aws_region
  
  # Domain Configuration
  domain_name = var.domain_name
  
  # Network Configuration
  vpc_cidr = "10.1.0.0/16"  # Different CIDR for dev
  
  # Database Configuration (Cost Optimized)
  db_instance_class    = "db.t3.micro"
  db_allocated_storage = 20
  db_engine_version    = "15.4"
  db_name              = "cybershield_dev"
  db_username          = "cybershield_dev"
  
  # Redis Configuration (Cost Optimized)
  redis_node_type               = "cache.t3.micro"
  redis_engine_version          = "7.0"
  redis_parameter_group_family  = "redis7"
  
  # OpenSearch Configuration (Minimal for dev)
  enable_opensearch         = true
  opensearch_instance_type  = "t3.small.search"
  opensearch_instance_count = 1
  opensearch_volume_size    = 20
  
  # Container Configuration (Right-sized for dev)
  backend_cpu         = 512   # Reduced from production
  backend_memory      = 1024  # Reduced from production
  backend_min_capacity = 1
  backend_max_capacity = 2
  
  frontend_cpu         = 256   # Reduced from production
  frontend_memory      = 512   # Reduced from production
  frontend_min_capacity = 1
  frontend_max_capacity = 2
  
  # Cost Optimization
  enable_spot_instances     = true  # Use spot instances for cost savings
  enable_deletion_protection = false # Allow easy cleanup in dev
  
  # Logging (shorter retention for dev)
  cloudwatch_log_retention_days = 7
  enable_logging = true
  
  # Environment Variables
  environment_variables = {
    DEBUG                      = "True"
    ENVIRONMENT                = "development"
    LOG_LEVEL                 = "DEBUG"
    REDIS_HOST                = ""  # Will be populated by module
    POSTGRES_HOST             = ""  # Will be populated by module
    OPENSEARCH_HOST           = ""  # Will be populated by module
    APPLE_SILICON_ACCELERATION = "true"
    REACT_LOG_FORMAT           = "console"  # Console format for dev
  }
  
  # Security (more permissive for dev)
  certificate_validation_method = "DNS"
  enable_backup               = false   # Disable backups in dev
}

# Data sources
data "aws_caller_identity" "current" {}

# Development-specific S3 bucket for uploads
resource "aws_s3_bucket" "dev_uploads" {
  bucket        = "cybershield-dev-uploads-${random_string.bucket_suffix.result}"
  force_destroy = true  # Allow deletion in dev
  
  tags = {
    Name        = "cybershield-dev-uploads"
    Environment = "dev"
    Purpose     = "development-file-uploads"
  }
}

# Block public access to dev uploads bucket
resource "aws_s3_bucket_public_access_block" "dev_uploads" {
  bucket = aws_s3_bucket.dev_uploads.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}