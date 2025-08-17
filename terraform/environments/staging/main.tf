# Staging Environment Configuration for CyberShield
# Balanced between dev cost optimization and prod reliability

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

  # Backend configuration for staging environment
  backend "s3" {
    bucket         = "cybershield-terraform-state-staging-nazqkk52"
    key            = "staging/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "cybershield-terraform-locks-staging"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "cybershield"
      Environment = "staging"
      ManagedBy   = "terraform"
      Owner       = "cybershield-staging-team"
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
  environment  = "staging"
  aws_region   = var.aws_region
  
  # Domain Configuration
  domain_name = var.domain_name
  
  # Network Configuration
  vpc_cidr = "10.1.0.0/16"  # Staging CIDR
  
  # Database Configuration (Staging Ready)
  db_instance_class    = "db.t3.small"   # Same as prod for testing
  db_allocated_storage = 50              # Moderate storage
  db_engine_version    = "15.4"
  db_name              = "cybershield_staging"
  db_username          = "cybershield_admin"
  
  # Redis Configuration (Staging Ready)
  redis_node_type               = "cache.t3.small"
  redis_engine_version          = "7.0"
  redis_parameter_group_family  = "redis7"
  
  # OpenSearch Configuration (Staging Ready)
  enable_opensearch         = true
  opensearch_instance_type  = "t3.small.search"
  opensearch_instance_count = 1                     # Single instance for staging
  opensearch_volume_size    = 20                    # Smaller storage
  enable_zone_awareness     = false                 # Single AZ for cost savings
  
  # Container Configuration (Staging Sizing)
  backend_cpu         = 512   # Moderate sizing
  backend_memory      = 1024  # Moderate sizing
  backend_min_capacity = 1    # Single instance minimum
  backend_max_capacity = 5    # Scale up to 5 for load testing
  
  frontend_cpu         = 256   # Smaller sizing
  frontend_memory      = 512   # Smaller sizing
  frontend_min_capacity = 1    # Single instance minimum
  frontend_max_capacity = 3    # Scale up to 3 for testing
  
  # Staging Cost Optimization
  enable_spot_instances      = true  # Use spot instances for cost savings
  enable_deletion_protection = false # Allow easier resource cleanup
  
  # Logging (shorter retention for staging)
  cloudwatch_log_retention_days = 14
  enable_logging = true
  
  # Environment Variables
  environment_variables = {
    DEBUG                      = "False"
    ENVIRONMENT                = "staging"
    LOG_LEVEL                 = "INFO"
    REDIS_HOST                = ""  # Will be populated by module
    POSTGRES_HOST             = ""  # Will be populated by module
    OPENSEARCH_HOST           = ""  # Will be populated by module
    APPLE_SILICON_ACCELERATION = "true"
    REACT_LOG_FORMAT           = "json"
  }
  
  # Security (balanced security)
  certificate_validation_method = "DNS"
  enable_backup               = true    # Enable backups
  backup_retention_days       = 14      # Shorter retention
}

# Data sources
data "aws_caller_identity" "current" {}

# Staging-specific S3 bucket for uploads
resource "aws_s3_bucket" "staging_uploads" {
  bucket        = "cybershield-staging-uploads-${random_string.bucket_suffix.result}"
  force_destroy = true  # Allow easier cleanup in staging
  
  tags = {
    Name        = "cybershield-staging-uploads"
    Environment = "staging"
    Purpose     = "staging-file-uploads"
  }
}

# Server-side encryption for staging uploads bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "staging_uploads" {
  bucket = aws_s3_bucket.staging_uploads.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lifecycle configuration for staging uploads bucket (shorter retention)
resource "aws_s3_bucket_lifecycle_configuration" "staging_uploads" {
  bucket = aws_s3_bucket.staging_uploads.id
  
  rule {
    id     = "staging_cleanup"
    status = "Enabled"
    
    filter {
      prefix = ""
    }
    
    expiration {
      days = 30  # Clean up files after 30 days
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 7  # Clean up old versions quickly
    }
  }
}

# Block public access to staging uploads bucket
resource "aws_s3_bucket_public_access_block" "staging_uploads" {
  bucket = aws_s3_bucket.staging_uploads.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudWatch Dashboard for staging monitoring
resource "aws_cloudwatch_dashboard" "staging_overview" {
  dashboard_name = "cybershield-staging-overview"
  
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
            [".", "MemoryUtilization", ".", "."],
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", module.cybershield.alb_arn_suffix]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Staging Performance Metrics"
        }
      }
    ]
  })
}