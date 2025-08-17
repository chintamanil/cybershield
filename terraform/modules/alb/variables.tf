# Variables for ALB Module

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where ALB will be deployed"
  type        = string
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs for ALB"
  type        = list(string)
}

variable "domain_name" {
  description = "Domain name for SSL certificate and Route53 record"
  type        = string
  default     = null
}

variable "subject_alternative_names" {
  description = "Additional domain names for SSL certificate"
  type        = list(string)
  default     = []
}

variable "certificate_validation_method" {
  description = "Method to validate SSL certificate"
  type        = string
  default     = "DNS"
  
  validation {
    condition     = contains(["DNS", "EMAIL"], var.certificate_validation_method)
    error_message = "Certificate validation method must be either 'DNS' or 'EMAIL'."
  }
}

variable "ssl_policy" {
  description = "SSL policy for HTTPS listener"
  type        = string
  default     = "ELBSecurityPolicy-TLS-1-2-2017-01"
  
  validation {
    condition = contains([
      "ELBSecurityPolicy-TLS-1-0-2015-04",
      "ELBSecurityPolicy-TLS-1-1-2017-01", 
      "ELBSecurityPolicy-TLS-1-2-2017-01",
      "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
      "ELBSecurityPolicy-FS-2018-06",
      "ELBSecurityPolicy-FS-1-1-2019-08",
      "ELBSecurityPolicy-FS-1-2-2019-08",
      "ELBSecurityPolicy-FS-1-2-Res-2019-08",
      "ELBSecurityPolicy-FS-1-2-Res-2020-10"
    ], var.ssl_policy)
    error_message = "SSL policy must be a valid ELB security policy."
  }
}

variable "backend_port" {
  description = "Port for backend service"
  type        = number
  default     = 8000
  
  validation {
    condition     = var.backend_port >= 1 && var.backend_port <= 65535
    error_message = "Backend port must be between 1 and 65535."
  }
}

variable "frontend_port" {
  description = "Port for frontend service"
  type        = number
  default     = 8501
  
  validation {
    condition     = var.frontend_port >= 1 && var.frontend_port <= 65535
    error_message = "Frontend port must be between 1 and 65535."
  }
}

variable "backend_health_check_path" {
  description = "Health check path for backend service"
  type        = string
  default     = "/health"
}

variable "frontend_health_check_path" {
  description = "Health check path for frontend service"
  type        = string
  default     = "/"
}

variable "health_check_healthy_threshold" {
  description = "Number of consecutive health checks successes required"
  type        = number
  default     = 2
  
  validation {
    condition     = var.health_check_healthy_threshold >= 2 && var.health_check_healthy_threshold <= 10
    error_message = "Health check healthy threshold must be between 2 and 10."
  }
}

variable "health_check_unhealthy_threshold" {
  description = "Number of consecutive health check failures required"
  type        = number
  default     = 3
  
  validation {
    condition     = var.health_check_unhealthy_threshold >= 2 && var.health_check_unhealthy_threshold <= 10
    error_message = "Health check unhealthy threshold must be between 2 and 10."
  }
}

variable "health_check_timeout" {
  description = "Health check timeout in seconds"
  type        = number
  default     = 5
  
  validation {
    condition     = var.health_check_timeout >= 2 && var.health_check_timeout <= 120
    error_message = "Health check timeout must be between 2 and 120 seconds."
  }
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

variable "health_check_matcher" {
  description = "HTTP status codes to consider healthy"
  type        = string
  default     = "200"
}

variable "enable_frontend_target_group" {
  description = "Enable separate target group for frontend service"
  type        = bool
  default     = true
}

variable "backend_path_patterns" {
  description = "Path patterns that should route to backend service"
  type        = list(string)
  default     = [
    "/analyze*",
    "/upload*",
    "/tools/*",
    "/health*",
    "/status*",
    "/docs*",
    "/openapi.json"
  ]
}

variable "enable_stickiness" {
  description = "Enable session stickiness"
  type        = bool
  default     = false
}

variable "stickiness_duration" {
  description = "Duration of session stickiness in seconds"
  type        = number
  default     = 86400
  
  validation {
    condition     = var.stickiness_duration >= 1 && var.stickiness_duration <= 604800
    error_message = "Stickiness duration must be between 1 second and 7 days (604800 seconds)."
  }
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for ALB"
  type        = bool
  default     = false
}

variable "enable_access_logs" {
  description = "Enable ALB access logs"
  type        = bool
  default     = false
}

variable "access_logs_bucket" {
  description = "S3 bucket for ALB access logs"
  type        = string
  default     = null
}

variable "access_logs_prefix" {
  description = "Prefix for ALB access logs in S3"
  type        = string
  default     = "alb-logs"
}

variable "enable_ipv6" {
  description = "Enable IPv6 support"
  type        = bool
  default     = false
}

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring and alarms"
  type        = bool
  default     = true
}

variable "response_time_alarm_threshold" {
  description = "Response time alarm threshold in seconds"
  type        = number
  default     = 1.0
  
  validation {
    condition     = var.response_time_alarm_threshold > 0
    error_message = "Response time alarm threshold must be greater than 0."
  }
}

variable "unhealthy_host_alarm_threshold" {
  description = "Unhealthy host count alarm threshold"
  type        = number
  default     = 0
  
  validation {
    condition     = var.unhealthy_host_alarm_threshold >= 0
    error_message = "Unhealthy host alarm threshold must be >= 0."
  }
}

variable "http_5xx_alarm_threshold" {
  description = "HTTP 5xx error count alarm threshold"
  type        = number
  default     = 10
  
  validation {
    condition     = var.http_5xx_alarm_threshold >= 0
    error_message = "HTTP 5xx alarm threshold must be >= 0."
  }
}

variable "alarm_actions" {
  description = "List of ARNs to notify when alarms trigger"
  type        = list(string)
  default     = []
}

variable "waf_web_acl_arn" {
  description = "ARN of WAF Web ACL to associate with ALB"
  type        = string
  default     = null
}

variable "enable_shield_advanced" {
  description = "Enable AWS Shield Advanced protection"
  type        = bool
  default     = false
}

variable "custom_response_headers" {
  description = "Custom response headers to add"
  type = map(object({
    header_name  = string
    header_value = string
    override     = bool
  }))
  default = {}
}

variable "drop_invalid_header_fields" {
  description = "Drop invalid header fields"
  type        = bool
  default     = true
}

variable "enable_waf_fail_open" {
  description = "Enable WAF fail open behavior"
  type        = bool
  default     = false
}

variable "desync_mitigation_mode" {
  description = "Desync mitigation mode for ALB"
  type        = string
  default     = "defensive"
  
  validation {
    condition     = contains(["monitor", "defensive", "strictest"], var.desync_mitigation_mode)
    error_message = "Desync mitigation mode must be one of: monitor, defensive, strictest."
  }
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}