# Variables for Production Environment

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Domain name for the production environment"
  type        = string
  default     = "cybershield-ai.com"
}