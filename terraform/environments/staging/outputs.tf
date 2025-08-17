# Outputs for Staging Environment

output "application_url" {
  description = "Staging application URL"
  value       = module.cybershield.application_url
}

output "api_endpoints" {
  description = "Staging API endpoints"
  value       = module.cybershield.api_endpoints
}

output "deployment_info" {
  description = "Staging deployment information"
  value       = module.cybershield.deployment_info
}

output "staging_uploads_bucket" {
  description = "Staging uploads S3 bucket"
  value       = aws_s3_bucket.staging_uploads.bucket
}

output "monitoring_dashboard" {
  description = "CloudWatch monitoring dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.staging_overview.dashboard_name}"
}

output "staging_summary" {
  description = "Staging environment summary"
  value = {
    app_url              = module.cybershield.application_url
    health_check         = "${module.cybershield.application_url}/health"
    status_endpoint      = "${module.cybershield.application_url}/status"
    uploads_bucket       = aws_s3_bucket.staging_uploads.bucket
    ecs_cluster          = module.cybershield.ecs_cluster_name
    load_balancer_dns    = module.cybershield.alb_dns_name
    ssl_certificate      = module.cybershield.certificate_arn
    cloudwatch_dashboard = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.staging_overview.dashboard_name}"
    cloudwatch_logs      = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#logsV2:log-groups"
  }
}