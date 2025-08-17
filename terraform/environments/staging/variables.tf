# Variables for Staging Environment

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Domain name for the staging environment"
  type        = string
  default     = "staging.cybershield-ai.com"
}