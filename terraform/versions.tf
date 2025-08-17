# Terraform Version Constraints
# Define minimum versions for Terraform and providers

terraform {
  required_version = ">= 1.5, < 1.13"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.100"
      configuration_aliases = [aws.us_east_1]
    }
    
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
    
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
    
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

# Provider configuration aliases for multi-region resources
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "${var.project_name}-${var.environment}-team"
    }
  }
}