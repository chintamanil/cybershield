# Outputs for Development Environment

output "application_url" {
  description = "Development application URL"
  value       = module.cybershield.application_url
}

output "api_endpoints" {
  description = "Development API endpoints"
  value       = module.cybershield.api_endpoints
}

output "deployment_info" {
  description = "Development deployment information"
  value       = module.cybershield.deployment_info
}

output "dev_uploads_bucket" {
  description = "Development uploads S3 bucket"
  value       = aws_s3_bucket.dev_uploads.bucket
}

output "quick_access" {
  description = "Quick access information for developers"
  value = {
    app_url         = module.cybershield.application_url
    health_check    = "${module.cybershield.application_url}/health"
    status_endpoint = "${module.cybershield.application_url}/status"
    logs_command    = "aws logs tail ${module.cybershield.backend_log_group_name} --follow"
    ecs_exec_backend = "aws ecs execute-command --cluster ${module.cybershield.ecs_cluster_name} --task $(aws ecs list-tasks --cluster ${module.cybershield.ecs_cluster_name} --service-name ${module.cybershield.backend_service_name} --query 'taskArns[0]' --output text | cut -d'/' -f3) --container backend --interactive --command '/bin/bash'"
  }
}