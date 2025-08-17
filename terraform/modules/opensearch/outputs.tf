# Outputs for OpenSearch Module

output "opensearch_domain_id" {
  description = "Unique identifier for the OpenSearch domain"
  value       = aws_opensearch_domain.main.domain_id
}

output "opensearch_domain_name" {
  description = "Name of the OpenSearch domain"
  value       = aws_opensearch_domain.main.domain_name
}

output "opensearch_arn" {
  description = "ARN of the OpenSearch domain"
  value       = aws_opensearch_domain.main.arn
}

output "opensearch_endpoint" {
  description = "Domain-specific endpoint used to submit index, search, and data upload requests"
  value       = aws_opensearch_domain.main.endpoint
}

output "opensearch_dashboard_endpoint" {
  description = "Domain-specific endpoint for OpenSearch Dashboards"
  value       = aws_opensearch_domain.main.dashboard_endpoint
}

output "opensearch_kibana_endpoint" {
  description = "Domain-specific endpoint for Kibana (deprecated, use dashboard_endpoint)"
  value       = aws_opensearch_domain.main.kibana_endpoint
}

output "opensearch_domain_url" {
  description = "Full HTTPS URL for the OpenSearch domain"
  value       = "https://${aws_opensearch_domain.main.endpoint}"
}

output "opensearch_dashboard_url" {
  description = "Full HTTPS URL for OpenSearch Dashboards"
  value       = "https://${aws_opensearch_domain.main.dashboard_endpoint}"
}

output "opensearch_security_group_id" {
  description = "ID of the security group created for OpenSearch"
  value       = aws_security_group.opensearch.id
}

output "opensearch_engine_version" {
  description = "OpenSearch engine version"
  value       = aws_opensearch_domain.main.engine_version
}

output "opensearch_cluster_config" {
  description = "Cluster configuration of the OpenSearch domain"
  value = {
    instance_type            = aws_opensearch_domain.main.cluster_config[0].instance_type
    instance_count           = aws_opensearch_domain.main.cluster_config[0].instance_count
    dedicated_master_enabled = aws_opensearch_domain.main.cluster_config[0].dedicated_master_enabled
    master_instance_type     = aws_opensearch_domain.main.cluster_config[0].master_instance_type
    master_instance_count    = aws_opensearch_domain.main.cluster_config[0].master_instance_count
    zone_awareness_enabled   = aws_opensearch_domain.main.cluster_config[0].zone_awareness_enabled
    warm_enabled             = aws_opensearch_domain.main.cluster_config[0].warm_enabled
  }
}

output "opensearch_ebs_options" {
  description = "EBS configuration of the OpenSearch domain"
  value = {
    ebs_enabled = aws_opensearch_domain.main.ebs_options[0].ebs_enabled
    volume_type = aws_opensearch_domain.main.ebs_options[0].volume_type
    volume_size = aws_opensearch_domain.main.ebs_options[0].volume_size
    iops        = aws_opensearch_domain.main.ebs_options[0].iops
    throughput  = aws_opensearch_domain.main.ebs_options[0].throughput
  }
}

output "opensearch_vpc_options" {
  description = "VPC configuration of the OpenSearch domain"
  value = {
    vpc_id             = aws_opensearch_domain.main.vpc_options[0].vpc_id
    subnet_ids         = aws_opensearch_domain.main.vpc_options[0].subnet_ids
    security_group_ids = aws_opensearch_domain.main.vpc_options[0].security_group_ids
    availability_zones = aws_opensearch_domain.main.vpc_options[0].availability_zones
  }
}

output "opensearch_encryption_config" {
  description = "Encryption configuration of the OpenSearch domain"
  value = {
    encrypt_at_rest         = aws_opensearch_domain.main.encrypt_at_rest[0].enabled
    node_to_node_encryption = aws_opensearch_domain.main.node_to_node_encryption[0].enabled
    enforce_https           = aws_opensearch_domain.main.domain_endpoint_options[0].enforce_https
    tls_security_policy     = aws_opensearch_domain.main.domain_endpoint_options[0].tls_security_policy
  }
}

output "opensearch_advanced_security_options" {
  description = "Advanced security options of the OpenSearch domain"
  value = {
    enabled                        = aws_opensearch_domain.main.advanced_security_options[0].enabled
    internal_user_database_enabled = aws_opensearch_domain.main.advanced_security_options[0].internal_user_database_enabled
    anonymous_auth_enabled         = aws_opensearch_domain.main.advanced_security_options[0].anonymous_auth_enabled
  }
}

output "opensearch_snapshot_options" {
  description = "Snapshot configuration of the OpenSearch domain"
  value = {
    automated_snapshot_start_hour = aws_opensearch_domain.main.snapshot_options[0].automated_snapshot_start_hour
  }
}

output "opensearch_access_policy_arn" {
  description = "ARN of the IAM policy for OpenSearch access"
  value       = var.create_access_policy ? aws_iam_policy.opensearch_access[0].arn : null
}

output "opensearch_log_groups" {
  description = "CloudWatch log groups for OpenSearch"
  value = {
    index_slow_logs    = var.enable_slow_logs ? aws_cloudwatch_log_group.opensearch_index_slow_logs[0].name : null
    search_slow_logs   = var.enable_slow_logs ? aws_cloudwatch_log_group.opensearch_search_slow_logs[0].name : null
    application_logs   = var.enable_application_logs ? aws_cloudwatch_log_group.opensearch_application_logs[0].name : null
  }
}

output "opensearch_monitoring" {
  description = "Monitoring and alarm information"
  value = {
    cluster_red_alarm     = var.enable_monitoring ? aws_cloudwatch_metric_alarm.cluster_status_red[0].arn : null
    cluster_yellow_alarm  = var.enable_monitoring ? aws_cloudwatch_metric_alarm.cluster_status_yellow[0].arn : null
    cpu_alarm            = var.enable_monitoring ? aws_cloudwatch_metric_alarm.cpu_utilization[0].arn : null
    storage_alarm        = var.enable_monitoring ? aws_cloudwatch_metric_alarm.storage_utilization[0].arn : null
  }
}

output "opensearch_connection_info" {
  description = "Connection information for applications"
  value = {
    endpoint          = aws_opensearch_domain.main.endpoint
    dashboard_endpoint = aws_opensearch_domain.main.dashboard_endpoint
    port             = 443
    protocol         = "https"
    domain_name      = aws_opensearch_domain.main.domain_name
    engine_version   = aws_opensearch_domain.main.engine_version
  }
}

output "opensearch_summary" {
  description = "Complete summary of OpenSearch deployment"
  value = {
    domain_name           = aws_opensearch_domain.main.domain_name
    endpoint_url          = "https://${aws_opensearch_domain.main.endpoint}"
    dashboard_url         = "https://${aws_opensearch_domain.main.dashboard_endpoint}"
    engine_version        = aws_opensearch_domain.main.engine_version
    instance_type         = aws_opensearch_domain.main.cluster_config[0].instance_type
    instance_count        = aws_opensearch_domain.main.cluster_config[0].instance_count
    volume_size           = aws_opensearch_domain.main.ebs_options[0].volume_size
    vpc_id               = aws_opensearch_domain.main.vpc_options[0].vpc_id
    security_group_id     = aws_security_group.opensearch.id
    encryption_enabled    = aws_opensearch_domain.main.encrypt_at_rest[0].enabled
    advanced_security     = aws_opensearch_domain.main.advanced_security_options[0].enabled
    zone_awareness        = aws_opensearch_domain.main.cluster_config[0].zone_awareness_enabled
    snapshot_hour        = aws_opensearch_domain.main.snapshot_options[0].automated_snapshot_start_hour
  }
}