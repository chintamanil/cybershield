# CyberShield Terraform Outputs
# Define outputs for key infrastructure resources

# General Information
output "account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS region"
  value       = var.aws_region
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

# Networking Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.networking.vpc_id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = module.networking.vpc_cidr
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.networking.public_subnet_ids
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.networking.private_subnet_ids
}

output "database_subnet_ids" {
  description = "IDs of the database subnets"
  value       = module.networking.database_subnet_ids
}

output "cache_subnet_ids" {
  description = "IDs of the cache subnets"
  value       = module.networking.cache_subnet_ids
}

output "availability_zones" {
  description = "Availability zones used"
  value       = local.azs
}

# Security Groups
output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = module.networking.alb_security_group_id
}

output "ecs_security_group_id" {
  description = "ID of the ECS security group"
  value       = module.networking.ecs_security_group_id
}

output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = module.networking.rds_security_group_id
}

output "redis_security_group_id" {
  description = "ID of the Redis security group"
  value       = module.networking.redis_security_group_id
}

output "opensearch_security_group_id" {
  description = "ID of the OpenSearch security group"
  value       = var.enable_opensearch ? module.networking.opensearch_security_group_id : null
}

# Load Balancer Outputs
output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.alb.alb_dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = module.alb.alb_zone_id
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = module.alb.alb_arn
}

output "backend_target_group_arn" {
  description = "ARN of the backend target group"
  value       = module.alb.backend_target_group_arn
}

output "frontend_target_group_arn" {
  description = "ARN of the frontend target group"
  value       = module.alb.frontend_target_group_arn
}

# Domain and SSL Outputs
output "domain_name" {
  description = "Domain name of the application"
  value       = var.domain_name
}

output "hosted_zone_id" {
  description = "Route53 hosted zone ID"
  value       = module.route53.hosted_zone_id
}

output "certificate_arn" {
  description = "ARN of the SSL certificate"
  value       = module.route53.certificate_arn
}

output "name_servers" {
  description = "Name servers for the hosted zone"
  value       = module.route53.name_servers
}

# Bedrock Outputs
output "bedrock_training_bucket" {
  description = "S3 bucket for Bedrock training data"
  value       = var.enable_bedrock_finetuning ? module.bedrock[0].training_data_bucket_name : null
}

output "bedrock_artifacts_bucket" {
  description = "S3 bucket for Bedrock model artifacts"
  value       = var.enable_bedrock_finetuning ? module.bedrock[0].model_artifacts_bucket_name : null
}

output "bedrock_finetuning_role_arn" {
  description = "IAM role ARN for Bedrock fine-tuning"
  value       = var.enable_bedrock_finetuning ? module.bedrock[0].bedrock_finetuning_role_arn : null
}

output "bedrock_application_role_arn" {
  description = "IAM role ARN for Bedrock application access"
  value       = var.enable_bedrock_finetuning ? module.bedrock[0].bedrock_application_role_arn : null
}

output "bedrock_vpc_endpoint_id" {
  description = "VPC endpoint ID for Bedrock"
  value       = var.enable_bedrock_finetuning && var.enable_bedrock_vpc_endpoint ? module.bedrock[0].bedrock_vpc_endpoint_id : null
}

# ECS Outputs
output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = module.ecs.cluster_name
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = module.ecs.cluster_arn
}

output "backend_service_name" {
  description = "Name of the backend ECS service"
  value       = module.ecs.backend_service_name
}

output "frontend_service_name" {
  description = "Name of the frontend ECS service"
  value       = module.ecs.frontend_service_name
}

output "backend_task_definition_arn" {
  description = "ARN of the backend task definition"
  value       = module.ecs.backend_task_definition_arn
}

output "frontend_task_definition_arn" {
  description = "ARN of the frontend task definition"
  value       = module.ecs.frontend_task_definition_arn
}

output "backend_log_group_name" {
  description = "Name of the backend CloudWatch log group"
  value       = module.ecs.backend_log_group_name
}

output "frontend_log_group_name" {
  description = "Name of the frontend CloudWatch log group"
  value       = module.ecs.frontend_log_group_name
}

# IAM Outputs
output "ecs_execution_role_arn" {
  description = "ARN of the ECS execution role"
  value       = module.iam.ecs_execution_role_arn
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task role"
  value       = module.iam.ecs_task_role_arn
}

# Database Outputs
output "rds_endpoint" {
  description = "RDS database endpoint"
  value       = module.rds.db_instance_endpoint
}

output "rds_port" {
  description = "RDS database port"
  value       = module.rds.db_instance_port
}

output "rds_instance_id" {
  description = "RDS instance ID"
  value       = module.rds.db_instance_id
}

output "database_name" {
  description = "Database name"
  value       = var.db_name
}

output "database_username" {
  description = "Database username"
  value       = var.db_username
  sensitive   = true
}

# Redis Outputs
output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = module.elasticache.primary_endpoint_address
}

output "redis_port" {
  description = "Redis port"
  value       = module.elasticache.port
}

output "redis_cluster_id" {
  description = "Redis cluster ID"
  value       = module.elasticache.cluster_id
}

# OpenSearch Outputs
output "opensearch_endpoint" {
  description = "OpenSearch domain endpoint"
  value       = var.enable_opensearch ? module.opensearch[0].endpoint : null
}

output "opensearch_domain_name" {
  description = "OpenSearch domain name"
  value       = var.enable_opensearch ? module.opensearch[0].domain_name : null
}

output "opensearch_kibana_endpoint" {
  description = "OpenSearch Dashboards endpoint"
  value       = var.enable_opensearch ? module.opensearch[0].kibana_endpoint : null
}

# Container Registry Outputs
output "ecr_repository_urls" {
  description = "ECR repository URLs"
  value = {
    backend  = module.ecs.backend_ecr_repository_url
    frontend = module.ecs.frontend_ecr_repository_url
  }
}

# Application URLs
output "application_url" {
  description = "Primary application URL"
  value       = "https://${var.domain_name}"
}

output "www_application_url" {
  description = "WWW application URL"
  value       = "https://www.${var.domain_name}"
}

output "backend_health_check_url" {
  description = "Backend health check URL"
  value       = "https://${var.domain_name}/health"
}

output "backend_status_url" {
  description = "Backend status URL"
  value       = "https://${var.domain_name}/status"
}

# API Endpoints
output "api_endpoints" {
  description = "List of API endpoints"
  value = {
    analyze           = "https://${var.domain_name}/analyze"
    analyze_with_image = "https://${var.domain_name}/analyze-with-image"
    batch_analyze     = "https://${var.domain_name}/batch-analyze"
    upload_image      = "https://${var.domain_name}/upload-image"
    health           = "https://${var.domain_name}/health"
    status           = "https://${var.domain_name}/status"
    environment      = "https://${var.domain_name}/environment"
    tools_abuseipdb  = "https://${var.domain_name}/tools/abuseipdb/check"
    tools_shodan     = "https://${var.domain_name}/tools/shodan/lookup"
    tools_virustotal = "https://${var.domain_name}/tools/virustotal/lookup"
    tools_regex      = "https://${var.domain_name}/tools/regex/extract"
  }
}

# Resource Summary
output "resource_summary" {
  description = "Summary of created resources"
  value = {
    vpc = {
      id   = module.networking.vpc_id
      cidr = module.networking.vpc_cidr
    }
    ecs = {
      cluster_name = module.ecs.cluster_name
      backend_service = module.ecs.backend_service_name
      frontend_service = module.ecs.frontend_service_name
    }
    database = {
      rds_endpoint = module.rds.db_instance_endpoint
      redis_endpoint = module.elasticache.primary_endpoint_address
      opensearch_endpoint = var.enable_opensearch ? module.opensearch[0].endpoint : null
    }
    domain = {
      name = var.domain_name
      alb_dns = module.alb.alb_dns_name
      certificate_arn = module.route53.certificate_arn
    }
    security = {
      alb_sg_id = module.networking.alb_security_group_id
      ecs_sg_id = module.networking.ecs_security_group_id
      rds_sg_id = module.networking.rds_security_group_id
      redis_sg_id = module.networking.redis_security_group_id
    }
  }
}

# Deployment Information
output "deployment_info" {
  description = "Information needed for deployment"
  value = {
    account_id = data.aws_caller_identity.current.account_id
    region     = var.aws_region
    environment = var.environment
    
    # ECR login command
    ecr_login_command = "aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
    
    # Docker build and push commands
    backend_docker_commands = [
      "docker build -f deployment/Dockerfile.aws -t ${var.project_name}-backend .",
      "docker tag ${var.project_name}-backend:latest ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.project_name}-backend:latest",
      "docker push ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.project_name}-backend:latest"
    ]
    
    frontend_docker_commands = [
      "docker build -f deployment/Dockerfile.frontend -t ${var.project_name}-frontend .",
      "docker tag ${var.project_name}-frontend:latest ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.project_name}-frontend:latest",
      "docker push ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.project_name}-frontend:latest"
    ]
    
    # Database connection information
    database_connection = {
      host     = module.rds.db_instance_endpoint
      port     = module.rds.db_instance_port
      database = var.db_name
      username = var.db_username
    }
    
    # Redis connection information
    redis_connection = {
      host = module.elasticache.primary_endpoint_address
      port = module.elasticache.port
    }
    
    # OpenSearch connection information
    opensearch_connection = var.enable_opensearch ? {
      endpoint = module.opensearch[0].endpoint
      dashboards = module.opensearch[0].kibana_endpoint
    } : null
  }
}

# Environment Variables for Application
output "application_environment_variables" {
  description = "Environment variables to set for the application"
  value = merge(var.environment_variables, {
    POSTGRES_HOST = module.rds.db_instance_endpoint
    POSTGRES_PORT = tostring(module.rds.db_instance_port)
    POSTGRES_DB   = var.db_name
    POSTGRES_USER = var.db_username
    REDIS_HOST    = module.elasticache.primary_endpoint_address
    REDIS_PORT    = tostring(module.elasticache.port)
    OPENSEARCH_HOST = var.enable_opensearch ? module.opensearch[0].endpoint : ""
    AWS_REGION    = var.aws_region
    ENVIRONMENT   = var.environment
  })
  sensitive = true
}