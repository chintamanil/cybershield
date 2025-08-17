# Variables for Bedrock Module

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for Bedrock VPC endpoint"
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for VPC endpoint"
  type        = list(string)
  default     = []
}

variable "enable_vpc_endpoint" {
  description = "Enable VPC endpoint for Bedrock (private connectivity)"
  type        = bool
  default     = false
}

variable "kms_key_id" {
  description = "KMS key ID for S3 bucket encryption"
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 14
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "enable_fine_tuning" {
  description = "Enable fine-tuning capabilities"
  type        = bool
  default     = true
}

variable "training_data_bucket_lifecycle_days" {
  description = "Number of days to retain training data in S3"
  type        = number
  default     = 365
  
  validation {
    condition     = var.training_data_bucket_lifecycle_days >= 30
    error_message = "Training data retention must be at least 30 days."
  }
}

variable "model_artifacts_lifecycle_days" {
  description = "Number of days to retain model artifacts in S3"
  type        = number
  default     = 730
  
  validation {
    condition     = var.model_artifacts_lifecycle_days >= 90
    error_message = "Model artifacts retention must be at least 90 days."
  }
}

variable "allowed_foundation_models" {
  description = "List of foundation models allowed for fine-tuning"
  type        = list(string)
  default = [
    "anthropic.claude-3-haiku-20240307-v1:0",
    "amazon.titan-text-express-v1",
    "amazon.titan-text-lite-v1",
    "meta.llama2-13b-chat-v1",
    "meta.llama2-70b-chat-v1"
  ]
}

variable "enable_model_monitoring" {
  description = "Enable CloudWatch monitoring for custom models"
  type        = bool
  default     = true
}

variable "max_training_jobs" {
  description = "Maximum number of concurrent training jobs"
  type        = number
  default     = 2
  
  validation {
    condition     = var.max_training_jobs >= 1 && var.max_training_jobs <= 10
    error_message = "Max training jobs must be between 1 and 10."
  }
}

variable "training_job_timeout_hours" {
  description = "Timeout for training jobs in hours"
  type        = number
  default     = 24
  
  validation {
    condition     = var.training_job_timeout_hours >= 1 && var.training_job_timeout_hours <= 168
    error_message = "Training job timeout must be between 1 and 168 hours (7 days)."
  }
}

variable "enable_data_validation" {
  description = "Enable training data validation"
  type        = bool
  default     = true
}

variable "notification_topic_arn" {
  description = "SNS topic ARN for training job notifications"
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}