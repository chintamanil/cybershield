# CyberShield Terraform Variables
# Define input variables for infrastructure configuration

# Basic Configuration
variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "cybershield"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

# Domain Configuration
variable "domain_name" {
  description = "Domain name for the application"
  type        = string
}

variable "certificate_validation_method" {
  description = "Method to use for certificate validation"
  type        = string
  default     = "DNS"
  
  validation {
    condition     = contains(["DNS", "EMAIL"], var.certificate_validation_method)
    error_message = "Certificate validation method must be DNS or EMAIL."
  }
}

# Networking Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "enable_vpn_gateway" {
  description = "Enable VPN Gateway"
  type        = bool
  default     = false
}

# Database Configuration
variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "db_allocated_storage" {
  description = "Allocated storage for RDS instance (GB)"
  type        = number
  default     = 20
}

variable "db_engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "15.4"
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "cybershield"
}

variable "db_username" {
  description = "Database username"
  type        = string
  default     = "cybershield_admin"
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "backup_window" {
  description = "Backup window"
  type        = string
  default     = "03:00-04:00"
}

variable "maintenance_window" {
  description = "Maintenance window"
  type        = string
  default     = "sun:04:00-sun:05:00"
}

# Redis Configuration
variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "redis_engine_version" {
  description = "Redis engine version"
  type        = string
  default     = "7.0"
}

variable "redis_parameter_group_family" {
  description = "Redis parameter group family"
  type        = string
  default     = "redis7"
}

variable "enable_auth_token" {
  description = "Enable Redis AUTH token"
  type        = bool
  default     = true
}

variable "enable_transit_encryption" {
  description = "Enable Redis transit encryption"
  type        = bool
  default     = true
}

variable "enable_at_rest_encryption" {
  description = "Enable Redis at-rest encryption"
  type        = bool
  default     = true
}

# OpenSearch Configuration
variable "enable_opensearch" {
  description = "Enable OpenSearch domain"
  type        = bool
  default     = true
}

variable "opensearch_instance_type" {
  description = "OpenSearch instance type"
  type        = string
  default     = "t3.small.search"
}

variable "opensearch_instance_count" {
  description = "Number of OpenSearch instances"
  type        = number
  default     = 1
}

variable "opensearch_volume_size" {
  description = "EBS volume size for OpenSearch (GB)"
  type        = number
  default     = 20
}

variable "opensearch_version" {
  description = "OpenSearch version"
  type        = string
  default     = "OpenSearch_2.11"
}

variable "enable_zone_awareness" {
  description = "Enable zone awareness for OpenSearch"
  type        = bool
  default     = false
}

variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for OpenSearch"
  type        = bool
  default     = true
}

variable "enable_node_to_node_encryption" {
  description = "Enable node-to-node encryption for OpenSearch"
  type        = bool
  default     = true
}

# ECS Configuration
variable "backend_cpu" {
  description = "CPU units for backend container"
  type        = number
  default     = 1024
}

variable "backend_memory" {
  description = "Memory (MB) for backend container"
  type        = number
  default     = 2048
}

variable "backend_min_capacity" {
  description = "Minimum number of backend tasks"
  type        = number
  default     = 1
}

variable "backend_max_capacity" {
  description = "Maximum number of backend tasks"
  type        = number
  default     = 10
}

variable "frontend_cpu" {
  description = "CPU units for frontend container"
  type        = number
  default     = 512
}

variable "frontend_memory" {
  description = "Memory (MB) for frontend container"
  type        = number
  default     = 1024
}

variable "frontend_min_capacity" {
  description = "Minimum number of frontend tasks"
  type        = number
  default     = 1
}

variable "frontend_max_capacity" {
  description = "Maximum number of frontend tasks"
  type        = number
  default     = 5
}

# Application Configuration
variable "environment_variables" {
  description = "Environment variables for the application"
  type        = map(string)
  default = {
    DEBUG                      = "False"
    ENVIRONMENT                = "production"
    LOG_LEVEL                 = "INFO"
    REDIS_HOST                = ""  # Will be populated from ElastiCache
    POSTGRES_HOST             = ""  # Will be populated from RDS
    OPENSEARCH_HOST           = ""  # Will be populated from OpenSearch
    APPLE_SILICON_ACCELERATION = "true"
  }
}

# Feature Flags
variable "enable_spot_instances" {
  description = "Enable spot instances for ECS tasks"
  type        = bool
  default     = false
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for critical resources"
  type        = bool
  default     = true
}

variable "enable_backup" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "enable_monitoring" {
  description = "Enable enhanced monitoring"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable application logging"
  type        = bool
  default     = true
}

variable "enable_ecs_exec" {
  description = "Enable ECS Exec for debugging"
  type        = bool
  default     = false
}

variable "enable_access_logs" {
  description = "Enable ALB access logs"
  type        = bool
  default     = true
}

variable "enable_health_checks" {
  description = "Enable Route53 health checks"
  type        = bool
  default     = true
}

variable "enable_performance_insights" {
  description = "Enable RDS Performance Insights"
  type        = bool
  default     = false
}

# Monitoring Configuration
variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 14
}

variable "monitoring_interval" {
  description = "Enhanced monitoring interval for RDS (seconds)"
  type        = number
  default     = 60
  
  validation {
    condition     = contains([0, 1, 5, 10, 15, 30, 60], var.monitoring_interval)
    error_message = "Monitoring interval must be one of: 0, 1, 5, 10, 15, 30, 60."
  }
}

# Health Check Configuration
variable "backend_health_check_path" {
  description = "Health check path for backend"
  type        = string
  default     = "/health"
}

variable "frontend_health_check_path" {
  description = "Health check path for frontend"
  type        = string
  default     = "/"
}

# Bedrock Configuration
variable "enable_bedrock_finetuning" {
  description = "Enable Bedrock fine-tuning capabilities"
  type        = bool
  default     = false
}

variable "enable_bedrock_vpc_endpoint" {
  description = "Enable VPC endpoint for Bedrock (private connectivity)"
  type        = bool
  default     = false
}

variable "bedrock_training_data_retention_days" {
  description = "Number of days to retain training data in S3"
  type        = number
  default     = 365
  
  validation {
    condition     = var.bedrock_training_data_retention_days >= 30
    error_message = "Training data retention must be at least 30 days."
  }
}

variable "bedrock_model_artifacts_retention_days" {
  description = "Number of days to retain model artifacts in S3"
  type        = number
  default     = 730
  
  validation {
    condition     = var.bedrock_model_artifacts_retention_days >= 90
    error_message = "Model artifacts retention must be at least 90 days."
  }
}