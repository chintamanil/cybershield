# Variables for OpenSearch Module

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where OpenSearch will be deployed"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for OpenSearch cluster"
  type        = list(string)
}

variable "opensearch_version" {
  description = "OpenSearch version"
  type        = string
  default     = "2.11"
  
  validation {
    condition = can(regex("^[0-9]+\\.[0-9]+$", var.opensearch_version))
    error_message = "OpenSearch version must be in format 'X.Y' (e.g., '2.11')."
  }
}

variable "instance_type" {
  description = "Instance type for OpenSearch data nodes"
  type        = string
  default     = "t3.small.search"
  
  validation {
    condition = can(regex("\\.search$", var.instance_type))
    error_message = "Instance type must be a valid OpenSearch instance type ending with '.search'."
  }
}

variable "instance_count" {
  description = "Number of data nodes in the cluster"
  type        = number
  default     = 1
  
  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 80
    error_message = "Instance count must be between 1 and 80."
  }
}

variable "dedicated_master_enabled" {
  description = "Enable dedicated master nodes"
  type        = bool
  default     = false
}

variable "master_instance_type" {
  description = "Instance type for dedicated master nodes"
  type        = string
  default     = "t3.small.search"
}

variable "master_instance_count" {
  description = "Number of dedicated master nodes"
  type        = number
  default     = 3
  
  validation {
    condition     = contains([3, 5], var.master_instance_count)
    error_message = "Master instance count must be 3 or 5."
  }
}

variable "zone_awareness_enabled" {
  description = "Enable zone awareness (multi-AZ deployment)"
  type        = bool
  default     = false
}

variable "availability_zone_count" {
  description = "Number of availability zones for zone awareness"
  type        = number
  default     = 2
  
  validation {
    condition     = contains([2, 3], var.availability_zone_count)
    error_message = "Availability zone count must be 2 or 3."
  }
}

variable "warm_enabled" {
  description = "Enable warm storage tier"
  type        = bool
  default     = false
}

variable "warm_instance_type" {
  description = "Instance type for warm nodes"
  type        = string
  default     = "ultrawarm1.medium.search"
}

variable "warm_instance_count" {
  description = "Number of warm nodes"
  type        = number
  default     = 2
}

variable "cold_storage_enabled" {
  description = "Enable cold storage"
  type        = bool
  default     = false
}

variable "volume_type" {
  description = "EBS volume type"
  type        = string
  default     = "gp3"
  
  validation {
    condition     = contains(["gp2", "gp3", "io1", "io2"], var.volume_type)
    error_message = "Volume type must be one of: gp2, gp3, io1, io2."
  }
}

variable "volume_size" {
  description = "Size of EBS volume in GB"
  type        = number
  default     = 20
  
  validation {
    condition     = var.volume_size >= 10 && var.volume_size <= 16384
    error_message = "Volume size must be between 10 GB and 16,384 GB."
  }
}

variable "iops" {
  description = "IOPS for gp3, io1, or io2 volumes"
  type        = number
  default     = 3000
}

variable "throughput" {
  description = "Throughput for gp3 volumes (MB/s)"
  type        = number
  default     = 125
  
  validation {
    condition     = var.throughput >= 125 && var.throughput <= 1000
    error_message = "Throughput must be between 125 and 1000 MB/s."
  }
}

variable "encrypt_at_rest" {
  description = "Enable encryption at rest"
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS key ID for encryption (optional)"
  type        = string
  default     = null
}

variable "node_to_node_encryption" {
  description = "Enable node-to-node encryption"
  type        = bool
  default     = true
}

variable "tls_security_policy" {
  description = "TLS security policy"
  type        = string
  default     = "Policy-Min-TLS-1-2-2019-07"
  
  validation {
    condition = contains([
      "Policy-Min-TLS-1-0-2019-07",
      "Policy-Min-TLS-1-2-2019-07",
      "Policy-Min-TLS-1-2-PFS-2023-10"
    ], var.tls_security_policy)
    error_message = "TLS security policy must be a valid AWS OpenSearch TLS policy."
  }
}

variable "advanced_security_enabled" {
  description = "Enable advanced security options"
  type        = bool
  default     = true
}

variable "internal_user_database_enabled" {
  description = "Enable internal user database for authentication"
  type        = bool
  default     = true
}

variable "master_user_name" {
  description = "Master username for OpenSearch"
  type        = string
  default     = "admin"
  sensitive   = true
}

variable "master_user_password" {
  description = "Master password for OpenSearch"
  type        = string
  default     = null
  sensitive   = true
}

variable "automated_snapshot_start_hour" {
  description = "Hour to start automated snapshots (0-23 UTC)"
  type        = number
  default     = 23
  
  validation {
    condition     = var.automated_snapshot_start_hour >= 0 && var.automated_snapshot_start_hour <= 23
    error_message = "Snapshot start hour must be between 0 and 23."
  }
}

variable "log_publishing_options" {
  description = "Log publishing options for OpenSearch"
  type = list(object({
    cloudwatch_log_group_arn = string
    log_type                 = string
    enabled                  = bool
  }))
  default = []
}

variable "advanced_options" {
  description = "Advanced configuration options"
  type        = map(string)
  default = {
    "rest.action.multi.allow_explicit_index" = "true"
    "indices.fielddata.cache.size"           = "20"
    "indices.query.bool.max_clause_count"    = "1024"
  }
}

variable "allowed_security_group_ids" {
  description = "List of security group IDs allowed to access OpenSearch"
  type        = list(string)
  default     = []
}

variable "create_service_linked_role" {
  description = "Create service-linked role for OpenSearch"
  type        = bool
  default     = true
}

variable "enable_slow_logs" {
  description = "Enable slow log publishing"
  type        = bool
  default     = true
}

variable "enable_application_logs" {
  description = "Enable application log publishing"
  type        = bool
  default     = true
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

variable "create_access_policy" {
  description = "Create IAM policy for OpenSearch access"
  type        = bool
  default     = true
}

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring and alarms"
  type        = bool
  default     = true
}

variable "cpu_alarm_threshold" {
  description = "CPU utilization threshold for CloudWatch alarm (%)"
  type        = number
  default     = 80
  
  validation {
    condition     = var.cpu_alarm_threshold >= 1 && var.cpu_alarm_threshold <= 100
    error_message = "CPU alarm threshold must be between 1 and 100."
  }
}

variable "storage_alarm_threshold" {
  description = "Storage utilization threshold for CloudWatch alarm (%)"
  type        = number
  default     = 85
  
  validation {
    condition     = var.storage_alarm_threshold >= 1 && var.storage_alarm_threshold <= 100
    error_message = "Storage alarm threshold must be between 1 and 100."
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