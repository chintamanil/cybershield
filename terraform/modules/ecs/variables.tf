# Variables for ECS Module

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where ECS will be deployed"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "Security group ID of the Application Load Balancer"
  type        = string
}

variable "task_execution_role_arn" {
  description = "ARN of the ECS task execution role"
  type        = string
}

variable "task_role_arn" {
  description = "ARN of the ECS task role"
  type        = string
}

variable "backend_target_group_arn" {
  description = "ARN of the backend target group"
  type        = string
}

variable "frontend_target_group_arn" {
  description = "ARN of the frontend target group"
  type        = string
  default     = null
}

variable "ecr_repository_url" {
  description = "URL of the ECR repository"
  type        = string
}

variable "backend_image_tag" {
  description = "Docker image tag for backend service"
  type        = string
  default     = "latest"
}

variable "frontend_image_tag" {
  description = "Docker image tag for frontend service"
  type        = string
  default     = "latest"
}

variable "enable_frontend" {
  description = "Enable frontend service deployment"
  type        = bool
  default     = true
}

variable "enable_opensearch" {
  description = "Enable OpenSearch connectivity"
  type        = bool
  default     = false
}

variable "backend_cpu" {
  description = "CPU units for backend container (1024 = 1 vCPU)"
  type        = number
  default     = 512
  
  validation {
    condition = contains([
      256, 512, 1024, 2048, 4096
    ], var.backend_cpu)
    error_message = "Backend CPU must be one of: 256, 512, 1024, 2048, 4096."
  }
}

variable "backend_memory" {
  description = "Memory (MiB) for backend container"
  type        = number
  default     = 1024
  
  validation {
    condition     = var.backend_memory >= 512 && var.backend_memory <= 30720
    error_message = "Backend memory must be between 512 MiB and 30720 MiB."
  }
}

variable "frontend_cpu" {
  description = "CPU units for frontend container (1024 = 1 vCPU)"
  type        = number
  default     = 256
  
  validation {
    condition = contains([
      256, 512, 1024, 2048, 4096
    ], var.frontend_cpu)
    error_message = "Frontend CPU must be one of: 256, 512, 1024, 2048, 4096."
  }
}

variable "frontend_memory" {
  description = "Memory (MiB) for frontend container"
  type        = number
  default     = 512
  
  validation {
    condition     = var.frontend_memory >= 512 && var.frontend_memory <= 30720
    error_message = "Frontend memory must be between 512 MiB and 30720 MiB."
  }
}

variable "backend_container_port" {
  description = "Port exposed by backend container"
  type        = number
  default     = 8000
  
  validation {
    condition     = var.backend_container_port >= 1 && var.backend_container_port <= 65535
    error_message = "Backend container port must be between 1 and 65535."
  }
}

variable "frontend_container_port" {
  description = "Port exposed by frontend container"
  type        = number
  default     = 8501
  
  validation {
    condition     = var.frontend_container_port >= 1 && var.frontend_container_port <= 65535
    error_message = "Frontend container port must be between 1 and 65535."
  }
}

variable "backend_desired_count" {
  description = "Desired number of backend tasks"
  type        = number
  default     = 1
  
  validation {
    condition     = var.backend_desired_count >= 0 && var.backend_desired_count <= 100
    error_message = "Backend desired count must be between 0 and 100."
  }
}

variable "frontend_desired_count" {
  description = "Desired number of frontend tasks"
  type        = number
  default     = 1
  
  validation {
    condition     = var.frontend_desired_count >= 0 && var.frontend_desired_count <= 100
    error_message = "Frontend desired count must be between 0 and 100."
  }
}

variable "backend_environment_variables" {
  description = "Environment variables for backend container"
  type        = map(string)
  default     = {}
}

variable "frontend_environment_variables" {
  description = "Environment variables for frontend container"
  type        = map(string)
  default     = {}
}

variable "backend_secrets" {
  description = "Secrets from Parameter Store or Secrets Manager for backend"
  type        = map(string)
  default     = {}
}

variable "frontend_secrets" {
  description = "Secrets from Parameter Store or Secrets Manager for frontend"
  type        = map(string)
  default     = {}
}

variable "backend_health_check_path" {
  description = "Health check path for backend container"
  type        = string
  default     = "/health"
}

variable "frontend_health_check_path" {
  description = "Health check path for frontend container"
  type        = string
  default     = "/"
}

variable "health_check_interval" {
  description = "Health check interval in seconds"
  type        = number
  default     = 30
  
  validation {
    condition     = var.health_check_interval >= 5 && var.health_check_interval <= 300
    error_message = "Health check interval must be between 5 and 300 seconds."
  }
}

variable "health_check_timeout" {
  description = "Health check timeout in seconds"
  type        = number
  default     = 5
  
  validation {
    condition     = var.health_check_timeout >= 2 && var.health_check_timeout <= 60
    error_message = "Health check timeout must be between 2 and 60 seconds."
  }
}

variable "health_check_retries" {
  description = "Number of health check retries"
  type        = number
  default     = 3
  
  validation {
    condition     = var.health_check_retries >= 1 && var.health_check_retries <= 10
    error_message = "Health check retries must be between 1 and 10."
  }
}

variable "health_check_start_period" {
  description = "Health check start period in seconds"
  type        = number
  default     = 60
  
  validation {
    condition     = var.health_check_start_period >= 0 && var.health_check_start_period <= 300
    error_message = "Health check start period must be between 0 and 300 seconds."
  }
}

variable "stop_timeout" {
  description = "Container stop timeout in seconds"
  type        = number
  default     = 30
  
  validation {
    condition     = var.stop_timeout >= 1 && var.stop_timeout <= 120
    error_message = "Stop timeout must be between 1 and 120 seconds."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "enable_container_insights" {
  description = "Enable Container Insights for the ECS cluster"
  type        = bool
  default     = true
}

variable "enable_exec_command" {
  description = "Enable ECS Exec for debugging"
  type        = bool
  default     = false
}

variable "exec_command_log_encryption" {
  description = "Enable encryption for ECS Exec logs"
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS key ID for ECS Exec encryption"
  type        = string
  default     = null
}

variable "enable_fargate_spot" {
  description = "Enable Fargate Spot capacity provider"
  type        = bool
  default     = false
}

variable "fargate_base_capacity" {
  description = "Base capacity for Fargate capacity provider"
  type        = number
  default     = 1
  
  validation {
    condition     = var.fargate_base_capacity >= 0 && var.fargate_base_capacity <= 10000
    error_message = "Fargate base capacity must be between 0 and 10000."
  }
}

variable "fargate_weight" {
  description = "Weight for Fargate capacity provider"
  type        = number
  default     = 1
  
  validation {
    condition     = var.fargate_weight >= 0 && var.fargate_weight <= 1000
    error_message = "Fargate weight must be between 0 and 1000."
  }
}

variable "fargate_spot_base_capacity" {
  description = "Base capacity for Fargate Spot capacity provider"
  type        = number
  default     = 0
  
  validation {
    condition     = var.fargate_spot_base_capacity >= 0 && var.fargate_spot_base_capacity <= 10000
    error_message = "Fargate Spot base capacity must be between 0 and 10000."
  }
}

variable "fargate_spot_weight" {
  description = "Weight for Fargate Spot capacity provider"
  type        = number
  default     = 4
  
  validation {
    condition     = var.fargate_spot_weight >= 0 && var.fargate_spot_weight <= 1000
    error_message = "Fargate Spot weight must be between 0 and 1000."
  }
}

variable "deployment_maximum_percent" {
  description = "Maximum percentage of tasks that can run during deployment"
  type        = number
  default     = 200
  
  validation {
    condition     = var.deployment_maximum_percent >= 100 && var.deployment_maximum_percent <= 200
    error_message = "Deployment maximum percent must be between 100 and 200."
  }
}

variable "deployment_minimum_healthy_percent" {
  description = "Minimum percentage of healthy tasks during deployment"
  type        = number
  default     = 50
  
  validation {
    condition     = var.deployment_minimum_healthy_percent >= 0 && var.deployment_minimum_healthy_percent <= 100
    error_message = "Deployment minimum healthy percent must be between 0 and 100."
  }
}

variable "enable_deployment_circuit_breaker" {
  description = "Enable deployment circuit breaker"
  type        = bool
  default     = true
}

variable "enable_deployment_rollback" {
  description = "Enable automatic rollback on deployment failure"
  type        = bool
  default     = true
}

variable "enable_auto_scaling" {
  description = "Enable auto scaling for ECS services"
  type        = bool
  default     = true
}

variable "backend_min_capacity" {
  description = "Minimum number of backend tasks for auto scaling"
  type        = number
  default     = 1
  
  validation {
    condition     = var.backend_min_capacity >= 1 && var.backend_min_capacity <= 100
    error_message = "Backend min capacity must be between 1 and 100."
  }
}

variable "backend_max_capacity" {
  description = "Maximum number of backend tasks for auto scaling"
  type        = number
  default     = 10
  
  validation {
    condition     = var.backend_max_capacity >= 1 && var.backend_max_capacity <= 1000
    error_message = "Backend max capacity must be between 1 and 1000."
  }
}

variable "frontend_min_capacity" {
  description = "Minimum number of frontend tasks for auto scaling"
  type        = number
  default     = 1
  
  validation {
    condition     = var.frontend_min_capacity >= 1 && var.frontend_min_capacity <= 100
    error_message = "Frontend min capacity must be between 1 and 100."
  }
}

variable "frontend_max_capacity" {
  description = "Maximum number of frontend tasks for auto scaling"
  type        = number
  default     = 5
  
  validation {
    condition     = var.frontend_max_capacity >= 1 && var.frontend_max_capacity <= 1000
    error_message = "Frontend max capacity must be between 1 and 1000."
  }
}

variable "cpu_target_value" {
  description = "Target CPU utilization percentage for auto scaling"
  type        = number
  default     = 70
  
  validation {
    condition     = var.cpu_target_value >= 10 && var.cpu_target_value <= 90
    error_message = "CPU target value must be between 10 and 90."
  }
}

variable "memory_target_value" {
  description = "Target memory utilization percentage for auto scaling"
  type        = number
  default     = 80
  
  validation {
    condition     = var.memory_target_value >= 10 && var.memory_target_value <= 90
    error_message = "Memory target value must be between 10 and 90."
  }
}

variable "scale_in_cooldown" {
  description = "Cooldown period for scale in actions (seconds)"
  type        = number
  default     = 300
  
  validation {
    condition     = var.scale_in_cooldown >= 0 && var.scale_in_cooldown <= 3600
    error_message = "Scale in cooldown must be between 0 and 3600 seconds."
  }
}

variable "scale_out_cooldown" {
  description = "Cooldown period for scale out actions (seconds)"
  type        = number
  default     = 300
  
  validation {
    condition     = var.scale_out_cooldown >= 0 && var.scale_out_cooldown <= 3600
    error_message = "Scale out cooldown must be between 0 and 3600 seconds."
  }
}

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring and alarms"
  type        = bool
  default     = true
}

variable "cpu_alarm_threshold" {
  description = "CPU utilization threshold for CloudWatch alarm"
  type        = number
  default     = 80
  
  validation {
    condition     = var.cpu_alarm_threshold >= 1 && var.cpu_alarm_threshold <= 100
    error_message = "CPU alarm threshold must be between 1 and 100."
  }
}

variable "memory_alarm_threshold" {
  description = "Memory utilization threshold for CloudWatch alarm"
  type        = number
  default     = 85
  
  validation {
    condition     = var.memory_alarm_threshold >= 1 && var.memory_alarm_threshold <= 100
    error_message = "Memory alarm threshold must be between 1 and 100."
  }
}

variable "alarm_actions" {
  description = "List of ARNs to notify when alarms trigger"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}