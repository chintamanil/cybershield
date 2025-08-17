# Outputs for Backend Setup

output "terraform_state_bucket_dev" {
  description = "S3 bucket name for dev Terraform state"
  value       = aws_s3_bucket.terraform_state_dev.bucket
}

output "terraform_state_bucket_staging" {
  description = "S3 bucket name for staging Terraform state"
  value       = aws_s3_bucket.terraform_state_staging.bucket
}

output "terraform_state_bucket_prod" {
  description = "S3 bucket name for prod Terraform state"
  value       = aws_s3_bucket.terraform_state_prod.bucket
}

output "dynamodb_lock_table_dev" {
  description = "DynamoDB table name for dev state locking"
  value       = aws_dynamodb_table.terraform_locks_dev.name
}

output "dynamodb_lock_table_staging" {
  description = "DynamoDB table name for staging state locking"
  value       = aws_dynamodb_table.terraform_locks_staging.name
}

output "dynamodb_lock_table_prod" {
  description = "DynamoDB table name for prod state locking"
  value       = aws_dynamodb_table.terraform_locks_prod.name
}

output "backend_configuration" {
  description = "Backend configuration for environments"
  value = {
    dev = {
      bucket         = aws_s3_bucket.terraform_state_dev.bucket
      key            = "dev/terraform.tfstate"
      region         = var.aws_region
      encrypt        = true
      dynamodb_table = aws_dynamodb_table.terraform_locks_dev.name
    }
    staging = {
      bucket         = aws_s3_bucket.terraform_state_staging.bucket
      key            = "staging/terraform.tfstate"
      region         = var.aws_region
      encrypt        = true
      dynamodb_table = aws_dynamodb_table.terraform_locks_staging.name
    }
    prod = {
      bucket         = aws_s3_bucket.terraform_state_prod.bucket
      key            = "prod/terraform.tfstate"
      region         = var.aws_region
      encrypt        = true
      dynamodb_table = aws_dynamodb_table.terraform_locks_prod.name
    }
  }
}

output "bucket_suffix" {
  description = "Random suffix used for bucket names"
  value       = random_string.bucket_suffix.result
  sensitive   = false
}