# Variables for IAM Module

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "enable_scheduled_tasks" {
  description = "Enable CloudWatch Events role for scheduled ECS tasks"
  type        = bool
  default     = false
}

variable "enable_lambda_functions" {
  description = "Enable Lambda execution role and policies"
  type        = bool
  default     = false
}

variable "enable_ec2_role" {
  description = "Enable EC2 instance role for debugging/management"
  type        = bool
  default     = false
}

variable "additional_task_policies" {
  description = "List of additional policy ARNs to attach to ECS task role"
  type        = list(string)
  default     = []
}

variable "additional_execution_policies" {
  description = "List of additional policy ARNs to attach to ECS task execution role"
  type        = list(string)
  default     = []
}

variable "custom_task_policy_statements" {
  description = "Additional custom policy statements for ECS task role"
  type = list(object({
    effect    = string
    actions   = list(string)
    resources = list(string)
    condition = optional(map(any))
  }))
  default = []
}

variable "s3_bucket_arns" {
  description = "List of S3 bucket ARNs that the application needs access to"
  type        = list(string)
  default     = []
}

variable "parameter_store_paths" {
  description = "List of Parameter Store paths that the application needs access to"
  type        = list(string)
  default     = []
}

variable "secrets_manager_arns" {
  description = "List of Secrets Manager ARNs that the application needs access to"
  type        = list(string)
  default     = []
}

variable "cloudwatch_log_group_arns" {
  description = "List of CloudWatch log group ARNs for logging permissions"
  type        = list(string)
  default     = []
}

variable "enable_xray_tracing" {
  description = "Enable AWS X-Ray tracing permissions"
  type        = bool
  default     = false
}

variable "enable_application_insights" {
  description = "Enable Application Insights permissions"
  type        = bool
  default     = false
}

variable "enable_container_insights" {
  description = "Enable Container Insights permissions"
  type        = bool
  default     = true
}

variable "opensearch_domain_arn" {
  description = "ARN of OpenSearch domain for application access"
  type        = string
  default     = null
}

variable "rds_instance_arns" {
  description = "List of RDS instance ARNs for enhanced monitoring"
  type        = list(string)
  default     = []
}

variable "elasticache_cluster_arns" {
  description = "List of ElastiCache cluster ARNs for monitoring"
  type        = list(string)
  default     = []
}

variable "enable_ecr_lifecycle_policy" {
  description = "Enable ECR lifecycle policy management permissions"
  type        = bool
  default     = false
}

variable "enable_backup_permissions" {
  description = "Enable AWS Backup service permissions"
  type        = bool
  default     = false
}

variable "enable_sns_publishing" {
  description = "Enable SNS topic publishing permissions"
  type        = bool
  default     = false
}

variable "sns_topic_arns" {
  description = "List of SNS topic ARNs for publishing notifications"
  type        = list(string)
  default     = []
}

variable "enable_sqs_access" {
  description = "Enable SQS queue access permissions"
  type        = bool
  default     = false
}

variable "sqs_queue_arns" {
  description = "List of SQS queue ARNs for message processing"
  type        = list(string)
  default     = []
}

variable "enable_kinesis_access" {
  description = "Enable Kinesis stream access permissions"
  type        = bool
  default     = false
}

variable "kinesis_stream_arns" {
  description = "List of Kinesis stream ARNs for data streaming"
  type        = list(string)
  default     = []
}

variable "enable_dynamodb_access" {
  description = "Enable DynamoDB table access permissions"
  type        = bool
  default     = false
}

variable "dynamodb_table_arns" {
  description = "List of DynamoDB table ARNs for data access"
  type        = list(string)
  default     = []
}

variable "lambda_function_arns" {
  description = "List of Lambda function ARNs that can invoke ECS tasks"
  type        = list(string)
  default     = []
}

variable "enable_api_gateway_logging" {
  description = "Enable API Gateway CloudWatch logging permissions"
  type        = bool
  default     = false
}

variable "enable_cost_explorer_access" {
  description = "Enable Cost Explorer API access for cost monitoring"
  type        = bool
  default     = false
}

variable "enable_resource_groups_access" {
  description = "Enable Resource Groups and Tag Editor access"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}