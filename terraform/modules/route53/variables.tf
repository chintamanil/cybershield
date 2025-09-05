# Route53 Module Variables
variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "domain_name" {
  description = "Domain name for the hosted zone"
  type        = string
}

variable "validation_method" {
  description = "Validation method for SSL certificate"
  type        = string
  default     = "DNS"
}

variable "create_health_check" {
  description = "Whether to create Route53 health checks"
  type        = bool
  default     = false
}

variable "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  type        = string
  default     = null
}

variable "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  type        = string
  default     = null
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}