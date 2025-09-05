# Production Environment Configuration for CyberShield
# Cost-optimized configuration for low-traffic application

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

  # Backend configuration for prod environment - temporarily disabled for testing
  # backend "s3" {
  #   bucket         = "cybershield-terraform-state-prod-nazqkk52"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "cybershield-terraform-locks-prod"
  # }
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
  
  # Network Configuration (Ultra Cost-optimized - Public Subnets)
  vpc_cidr = "10.0.0.0/16"  # Production CIDR
  enable_nat_gateway = false  # Disabled - ECS tasks use public subnets for direct ECR access
  
  # Database Configuration (Ultra Cost-optimized)
  db_instance_class    = "db.t3.micro"   # Free tier eligible
  db_allocated_storage = 20              # Free tier 20GB
  db_engine_version    = "15.7"
  db_name              = "cybershield"
  db_username          = var.db_username
  # Disable multi-AZ for cost savings (single AZ only)
  # Use gp2 storage instead of gp3 for lower cost
  
  # Redis Configuration (Cost-optimized)
  redis_node_type               = "cache.t3.micro"   # Smallest instance
  redis_engine_version          = "7.0"
  redis_parameter_group_family  = "redis7"
  
  # Vector Database Configuration (Cost-optimized)
  enable_opensearch         = false  # Disabled - using containerized Milvus instead
  enable_efs_for_milvus     = true   # Enable EFS for persistent Milvus storage
  # Cost: ~$3-5/month for EFS vs ~$15-25/month for OpenSearch
  # Milvus will run as a sidecar container in ECS with EFS persistence
  opensearch_instance_type  = "t3.small.search"     # Not used when disabled
  opensearch_instance_count = 1                     # Not used when disabled
  opensearch_volume_size    = 10                    # Not used when disabled
  enable_zone_awareness     = false                 # Not used when disabled
  
  # Container Configuration (Ultra Cost-optimized)
  backend_cpu         = 256   # Minimal CPU for low traffic
  backend_memory      = 512   # Minimal memory
  backend_min_capacity = 1    # Minimum required by ECS validation
  backend_max_capacity = 2    # Lower max for cost control
  
  frontend_cpu         = 256   # Minimal CPU
  frontend_memory      = 512   # Minimal memory
  frontend_min_capacity = 1    # Minimum required by ECS validation
  frontend_max_capacity = 1    # Single instance max
  
  # Cost Optimization (Maximum Savings)
  enable_spot_instances      = true  # Enable spot instances for cost savings
  enable_deletion_protection = false # Allow deletion to save costs
  enable_monitoring          = false # Disable enhanced RDS monitoring (~$5/month)
  enable_performance_insights = false # Disable RDS performance insights
  enable_access_logs         = false # Disable ALB access logs (saves S3 costs)
  
  # Logging (ultra cost-optimized retention)
  cloudwatch_log_retention_days = 1   # Minimal retention (1 day) to save costs
  enable_logging = true
  
  # Environment Variables - Use variables from terraform.tfvars
  environment_variables = var.environment_variables
  
  # Security (cost-optimized)
  certificate_validation_method = "DNS"
  enable_backup               = true    # Keep backups but shorter retention
  backup_retention_days       = 7       # Shorter retention for cost
  enable_health_checks        = false   # Disable health checks for cost savings
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