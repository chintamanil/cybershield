# Variables for Development Environment

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Domain name for the development environment"
  type        = string
  default     = "dev.cybershield-ai.com"
}