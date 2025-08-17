# CyberShield Terraform Configuration
# Main entry point for infrastructure deployment

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

  # Backend configuration - uncomment and configure for remote state
  # backend "s3" {
  #   bucket         = "cybershield-terraform-state"
  #   key            = "terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "cybershield-terraform-locks"
  # }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "${var.project_name}-${var.environment}-team"
    }
  }
}

# Random string for unique resource naming
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Data sources for current AWS account and region
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# Local values for computed configurations
locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 2)
  
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "${var.project_name}-${var.environment}-team"
  }
}

# Networking Module
module "networking" {
  source = "./modules/networking"
  
  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region
  
  vpc_cidr             = var.vpc_cidr
  availability_zones   = local.azs
  
  enable_nat_gateway   = var.enable_nat_gateway
  enable_vpn_gateway   = var.enable_vpn_gateway
  
  common_tags = local.common_tags
}

# IAM Module
module "iam" {
  source = "./modules/iam"
  
  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region
  
  enable_ecs_exec = var.enable_ecs_exec
  
  common_tags = local.common_tags
}

# Application Load Balancer Module
module "alb" {
  source = "./modules/alb"
  
  project_name = var.project_name
  environment  = var.environment
  
  vpc_id                    = module.networking.vpc_id
  public_subnet_ids         = module.networking.public_subnet_ids
  alb_security_group_id     = module.networking.alb_security_group_id
  
  domain_name               = var.domain_name
  certificate_arn           = module.route53.certificate_arn
  
  enable_deletion_protection = var.enable_deletion_protection
  enable_access_logs        = var.enable_access_logs
  log_retention_days        = var.cloudwatch_log_retention_days
  
  backend_health_check_path  = var.backend_health_check_path
  frontend_health_check_path = var.frontend_health_check_path
  
  common_tags = local.common_tags
}

# Route53 Module
module "route53" {
  source = "./modules/route53"
  
  project_name = var.project_name
  environment  = var.environment
  
  domain_name        = var.domain_name
  validation_method  = var.certificate_validation_method
  create_health_check = var.enable_health_checks
  
  alb_dns_name    = module.alb.alb_dns_name
  alb_zone_id     = module.alb.alb_zone_id
  
  common_tags = local.common_tags
}

# RDS Module
module "rds" {
  source = "./modules/rds"
  
  project_name = var.project_name
  environment  = var.environment
  
  vpc_id               = module.networking.vpc_id
  database_subnet_ids  = module.networking.database_subnet_ids
  rds_security_group_id = module.networking.rds_security_group_id
  
  db_instance_class    = var.db_instance_class
  db_allocated_storage = var.db_allocated_storage
  db_engine_version    = var.db_engine_version
  db_name              = var.db_name
  db_username          = var.db_username
  
  backup_retention_period = var.backup_retention_days
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window
  
  enable_monitoring      = var.enable_monitoring
  monitoring_interval    = var.monitoring_interval
  enable_performance_insights = var.enable_performance_insights
  
  enable_backup = var.enable_backup
  
  common_tags = local.common_tags
}

# ElastiCache Module
module "elasticache" {
  source = "./modules/elasticache"
  
  project_name = var.project_name
  environment  = var.environment
  
  vpc_id                    = module.networking.vpc_id
  cache_subnet_ids          = module.networking.cache_subnet_ids
  redis_security_group_id   = module.networking.redis_security_group_id
  
  redis_node_type           = var.redis_node_type
  redis_engine_version      = var.redis_engine_version
  redis_parameter_group_family = var.redis_parameter_group_family
  
  enable_auth_token         = var.enable_auth_token
  enable_transit_encryption = var.enable_transit_encryption
  enable_at_rest_encryption = var.enable_at_rest_encryption
  
  common_tags = local.common_tags
}

# OpenSearch Module (Optional)
module "opensearch" {
  source = "./modules/opensearch"
  count  = var.enable_opensearch ? 1 : 0
  
  project_name = var.project_name
  environment  = var.environment
  
  vpc_id                      = module.networking.vpc_id
  opensearch_subnet_ids       = module.networking.private_subnet_ids
  opensearch_security_group_id = module.networking.opensearch_security_group_id
  
  opensearch_instance_type    = var.opensearch_instance_type
  opensearch_instance_count   = var.opensearch_instance_count
  opensearch_volume_size      = var.opensearch_volume_size
  opensearch_version          = var.opensearch_version
  
  enable_zone_awareness       = var.enable_zone_awareness
  enable_encryption_at_rest   = var.enable_encryption_at_rest
  enable_node_to_node_encryption = var.enable_node_to_node_encryption
  
  common_tags = local.common_tags
}

# ECS Module
module "ecs" {
  source = "./modules/ecs"
  
  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region
  
  vpc_id                = module.networking.vpc_id
  private_subnet_ids    = module.networking.private_subnet_ids
  ecs_security_group_id = module.networking.ecs_security_group_id
  
  backend_target_group_arn  = module.alb.backend_target_group_arn
  frontend_target_group_arn = module.alb.frontend_target_group_arn
  
  ecs_execution_role_arn = module.iam.ecs_execution_role_arn
  ecs_task_role_arn      = module.iam.ecs_task_role_arn
  
  # Container Configuration
  backend_cpu         = var.backend_cpu
  backend_memory      = var.backend_memory
  backend_min_capacity = var.backend_min_capacity
  backend_max_capacity = var.backend_max_capacity
  
  frontend_cpu         = var.frontend_cpu
  frontend_memory      = var.frontend_memory
  frontend_min_capacity = var.frontend_min_capacity
  frontend_max_capacity = var.frontend_max_capacity
  
  # Application Configuration
  environment_variables = var.environment_variables
  
  # Feature Flags
  enable_spot_instances = var.enable_spot_instances
  enable_logging       = var.enable_logging
  enable_monitoring    = var.enable_monitoring
  
  common_tags = local.common_tags
}

# Bedrock Module for Fine-tuning
module "bedrock" {
  count  = var.enable_bedrock_finetuning ? 1 : 0
  source = "./modules/bedrock"
  
  project_name = var.project_name
  environment  = var.environment
  
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  private_subnet_ids = module.networking.private_subnet_ids
  
  enable_vpc_endpoint = var.enable_bedrock_vpc_endpoint
  enable_fine_tuning  = var.enable_bedrock_finetuning
  
  log_retention_days = var.cloudwatch_log_retention_days
  
  tags = local.common_tags
}

# DNS Records for the main domain
resource "aws_route53_record" "main" {
  zone_id = module.route53.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  
  alias {
    name                   = module.alb.alb_dns_name
    zone_id                = module.alb.alb_zone_id
    evaluate_target_health = false
  }
}

# DNS Records for www subdomain
resource "aws_route53_record" "www" {
  zone_id = module.route53.hosted_zone_id
  name    = "www.${var.domain_name}"
  type    = "A"
  
  alias {
    name                   = module.alb.alb_dns_name
    zone_id                = module.alb.alb_zone_id
    evaluate_target_health = false
  }
}