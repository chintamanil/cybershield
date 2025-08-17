# Production Environment Configuration for CyberShield
# Optimized for reliability, security, and performance

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

  # Backend configuration for prod environment
  backend "s3" {
    bucket         = "cybershield-terraform-state-prod-nazqkk52"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "cybershield-terraform-locks-prod"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "cybershield"
      Environment = "prod"
      ManagedBy   = "terraform"
      Owner       = "cybershield-prod-team"
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
  environment  = "prod"
  aws_region   = var.aws_region
  
  # Domain Configuration
  domain_name = var.domain_name
  
  # Network Configuration
  vpc_cidr = "10.0.0.0/16"  # Production CIDR
  
  # Database Configuration (Production Ready)
  db_instance_class    = "db.t3.small"   # Larger instance for prod
  db_allocated_storage = 100             # More storage for prod
  db_engine_version    = "15.4"
  db_name              = "cybershield"
  db_username          = "cybershield_admin"
  
  # Redis Configuration (Production Ready)
  redis_node_type               = "cache.t3.small"   # Larger instance for prod
  redis_engine_version          = "7.0"
  redis_parameter_group_family  = "redis7"
  
  # OpenSearch Configuration (Production Ready)
  enable_opensearch         = true
  opensearch_instance_type  = "t3.medium.search"    # Larger instance for prod
  opensearch_instance_count = 2                     # Multi-AZ for reliability
  opensearch_volume_size    = 50                    # More storage for prod
  enable_zone_awareness     = true                  # Multi-AZ deployment
  
  # Container Configuration (Production Sizing)
  backend_cpu         = 1024  # Production sizing
  backend_memory      = 2048  # Production sizing
  backend_min_capacity = 2    # Always have 2 instances
  backend_max_capacity = 10   # Scale up to 10 for traffic
  
  frontend_cpu         = 512   # Production sizing
  frontend_memory      = 1024  # Production sizing
  frontend_min_capacity = 2    # Always have 2 instances
  frontend_max_capacity = 5    # Scale up to 5 for traffic
  
  # Production Security and Reliability
  enable_spot_instances      = false # No spot instances in production
  enable_deletion_protection = true  # Protect production resources
  
  # Logging (longer retention for production)
  cloudwatch_log_retention_days = 30
  enable_logging = true
  
  # Environment Variables
  environment_variables = {
    DEBUG                      = "False"
    ENVIRONMENT                = "production"
    LOG_LEVEL                 = "INFO"
    REDIS_HOST                = ""  # Will be populated by module
    POSTGRES_HOST             = ""  # Will be populated by module
    OPENSEARCH_HOST           = ""  # Will be populated by module
    APPLE_SILICON_ACCELERATION = "true"
    REACT_LOG_FORMAT           = "json"  # JSON format for production
  }
  
  # Security (maximum security)
  certificate_validation_method = "DNS"
  enable_backup               = true    # Full backup strategy
  backup_retention_days       = 30      # Extended retention
}

# Data sources
data "aws_caller_identity" "current" {}

# Production-specific S3 bucket for uploads
resource "aws_s3_bucket" "prod_uploads" {
  bucket        = "cybershield-prod-uploads-${random_string.bucket_suffix.result}"
  force_destroy = false  # Protect production data
  
  tags = {
    Name        = "cybershield-prod-uploads"
    Environment = "prod"
    Purpose     = "production-file-uploads"
  }
}

# Versioning for production uploads bucket
resource "aws_s3_bucket_versioning" "prod_uploads" {
  bucket = aws_s3_bucket.prod_uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption for production uploads bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "prod_uploads" {
  bucket = aws_s3_bucket.prod_uploads.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lifecycle configuration for production uploads bucket
resource "aws_s3_bucket_lifecycle_configuration" "prod_uploads" {
  bucket = aws_s3_bucket.prod_uploads.id
  
  rule {
    id     = "prod_archiving"
    status = "Enabled"
    
    filter {
      prefix = ""
    }
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 365  # Keep files for 1 year
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Block public access to production uploads bucket
resource "aws_s3_bucket_public_access_block" "prod_uploads" {
  bucket = aws_s3_bucket.prod_uploads.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Production backup S3 bucket
resource "aws_s3_bucket" "prod_backups" {
  bucket        = "cybershield-prod-backups-${random_string.bucket_suffix.result}"
  force_destroy = false
  
  tags = {
    Name        = "cybershield-prod-backups"
    Environment = "prod"
    Purpose     = "production-backups"
  }
}

# CloudWatch Dashboard for production monitoring
resource "aws_cloudwatch_dashboard" "prod_overview" {
  dashboard_name = "cybershield-prod-overview"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ServiceName", module.cybershield.backend_service_name],
            [".", "MemoryUtilization", ".", "."]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "ECS Service Metrics"
        }
      }
    ]
  })
}