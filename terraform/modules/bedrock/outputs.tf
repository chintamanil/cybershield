# Outputs for Bedrock Module

output "training_data_bucket_name" {
  description = "Name of the S3 bucket for training data"
  value       = aws_s3_bucket.bedrock_training_data.bucket
}

output "training_data_bucket_arn" {
  description = "ARN of the S3 bucket for training data"
  value       = aws_s3_bucket.bedrock_training_data.arn
}

output "model_artifacts_bucket_name" {
  description = "Name of the S3 bucket for model artifacts"
  value       = aws_s3_bucket.bedrock_model_artifacts.bucket
}

output "model_artifacts_bucket_arn" {
  description = "ARN of the S3 bucket for model artifacts"
  value       = aws_s3_bucket.bedrock_model_artifacts.arn
}

output "bedrock_finetuning_role_arn" {
  description = "ARN of the Bedrock fine-tuning IAM role"
  value       = aws_iam_role.bedrock_finetuning_role.arn
}

output "bedrock_finetuning_role_name" {
  description = "Name of the Bedrock fine-tuning IAM role"
  value       = aws_iam_role.bedrock_finetuning_role.name
}

output "bedrock_application_role_arn" {
  description = "ARN of the Bedrock application IAM role"
  value       = aws_iam_role.bedrock_application_role.arn
}

output "bedrock_application_role_name" {
  description = "Name of the Bedrock application IAM role"
  value       = aws_iam_role.bedrock_application_role.name
}

output "bedrock_vpc_endpoint_id" {
  description = "ID of the Bedrock VPC endpoint"
  value       = var.enable_vpc_endpoint ? aws_vpc_endpoint.bedrock[0].id : null
}

output "bedrock_vpc_endpoint_dns_names" {
  description = "DNS names of the Bedrock VPC endpoint"
  value       = var.enable_vpc_endpoint ? aws_vpc_endpoint.bedrock[0].dns_entry : null
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Bedrock fine-tuning"
  value       = aws_cloudwatch_log_group.bedrock_finetuning.name
}

output "bedrock_configuration" {
  description = "Bedrock configuration details"
  value = {
    training_bucket     = aws_s3_bucket.bedrock_training_data.bucket
    artifacts_bucket    = aws_s3_bucket.bedrock_model_artifacts.bucket
    finetuning_role     = aws_iam_role.bedrock_finetuning_role.arn
    application_role    = aws_iam_role.bedrock_application_role.arn
    log_group          = aws_cloudwatch_log_group.bedrock_finetuning.name
    vpc_endpoint       = var.enable_vpc_endpoint ? aws_vpc_endpoint.bedrock[0].id : null
  }
}

output "s3_bucket_urls" {
  description = "S3 bucket URLs for data upload"
  value = {
    training_data    = "s3://${aws_s3_bucket.bedrock_training_data.bucket}"
    model_artifacts  = "s3://${aws_s3_bucket.bedrock_model_artifacts.bucket}"
  }
}

output "iam_policies" {
  description = "IAM policy ARNs"
  value = {
    finetuning_policy  = aws_iam_policy.bedrock_finetuning_policy.arn
    application_policy = aws_iam_policy.bedrock_application_policy.arn
  }
}

output "bedrock_endpoints" {
  description = "Bedrock service endpoints"
  value = {
    runtime_endpoint = "https://bedrock-runtime.${data.aws_region.current.name}.amazonaws.com"
    management_endpoint = "https://bedrock.${data.aws_region.current.name}.amazonaws.com"
    vpc_endpoint = var.enable_vpc_endpoint ? aws_vpc_endpoint.bedrock[0].dns_entry[0]["dns_name"] : null
  }
}